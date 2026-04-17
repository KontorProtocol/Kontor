use anyhow::Result;
use bitcoin::Txid;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use indexer_types::{Inst, OpMetadata};

use crate::bitcoin_client::Client;
use crate::block::{filter_map, op_from_inst};
use crate::database;
use crate::retry::{new_backoff_unlimited, retry};
use crate::runtime::ExecutionError;
use crate::runtime::Runtime;
use crate::runtime::kontor::built_in::context::HolderRef;
use crate::runtime::registry;
use crate::runtime::wit::{Holder, Signer};

/// Check if a parsed transaction contains only batchable ops.
/// Publish must only execute via Value::Block decisions (contract address
/// depends on block height/tx_index). All other ops are batchable.
/// Aggregate inputs are always batchable.
pub fn is_batchable(inputs: &[indexer_types::Input]) -> bool {
    inputs.iter().all(|input| {
        if input.insts.is_aggregate() {
            return true;
        }
        !input
            .insts
            .ops
            .iter()
            .any(|inst| matches!(inst, indexer_types::Inst::Publish { .. }))
    })
}

/// Abstraction over transaction execution and state rollback.
///
/// The consensus orchestration logic (`ConsensusState.process_decided_batch` and
/// `run_finality_checks`) calls these methods instead of directly manipulating state.
#[allow(async_fn_in_trait)]
pub trait Executor {
    /// Validate a pre-parsed transaction for batching.
    /// Checks batchability and may propagate the tx to the local bitcoind mempool.
    /// Returns true if the transaction is valid for inclusion in a batch.
    async fn validate_transaction(
        &self,
        raw: &bitcoin::Transaction,
        parsed: &indexer_types::Transaction,
    ) -> bool;

    /// Resolve a txid to a full bitcoin::Transaction. Used to fetch transaction
    /// data for batch execution — batches carry only txids.
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction>;

    /// Execute a single transaction's operations at the given height.
    /// Called by the reactor after DB row insertion. Sets context and runs ops.
    /// Returns Err only for non-deterministic infrastructure failures.
    async fn execute_transaction(
        &self,
        runtime: &mut Runtime,
        height: i64,
        tx_id: i64,
        tx: &indexer_types::Transaction,
    ) -> Result<()>;

    /// Signal the block source to re-deliver blocks starting from `height`.
    async fn replay_blocks_from(&mut self, height: u64) -> Result<()>;

    /// Parse a bitcoin::Transaction into an indexer_types::Transaction.
    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction>;
}

/// Placeholder executor that does nothing.
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    async fn validate_transaction(
        &self,
        _raw: &bitcoin::Transaction,
        _parsed: &indexer_types::Transaction,
    ) -> bool {
        false
    }
    async fn resolve_transaction(&self, _txid: &Txid) -> Option<bitcoin::Transaction> {
        None
    }
    async fn execute_transaction(
        &self,
        _runtime: &mut Runtime,
        _height: i64,
        _tx_id: i64,
        _tx: &indexer_types::Transaction,
    ) -> Result<()> {
        Ok(())
    }
    async fn replay_blocks_from(&mut self, _height: u64) -> Result<()> {
        Ok(())
    }
    fn parse_transaction(&self, _tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        None
    }
}

/// Production executor: handles transaction validation, resolution, and op execution.
/// Does NOT own the Runtime — the reactor owns it and passes &mut Runtime when needed.
pub struct RuntimeExecutor {
    bitcoin_client: Option<Client>,
    replay_tx: Option<tokio::sync::mpsc::Sender<u64>>,
    cancel_token: CancellationToken,
}

impl RuntimeExecutor {
    pub fn new(cancel_token: CancellationToken) -> Self {
        Self {
            bitcoin_client: None,
            replay_tx: None,
            cancel_token,
        }
    }

    pub fn with_bitcoin_client(mut self, client: Client) -> Self {
        self.bitcoin_client = Some(client);
        self
    }

    pub fn with_replay_tx(mut self, tx: tokio::sync::mpsc::Sender<u64>) -> Self {
        self.replay_tx = Some(tx);
        self
    }
}

impl Executor for RuntimeExecutor {
    async fn validate_transaction(
        &self,
        raw: &bitcoin::Transaction,
        parsed: &indexer_types::Transaction,
    ) -> bool {
        if !is_batchable(&parsed.inputs) {
            return false;
        }

        // Push to local bitcoind mempool (idempotent, succeeds if already present).
        // -25 (RPC_VERIFY_ERROR): general validation error (missing inputs) — invalid
        // -26 (RPC_VERIFY_REJECTED): rejected by mempool policy — invalid
        // -27 (RPC_VERIFY_ALREADY_IN_UTXO_SET): tx already confirmed — treat as success
        // All other errors (network, node loading) are retried via unlimited backoff.
        if let Some(client) = &self.bitcoin_client {
            let raw_hex = bitcoin::consensus::encode::serialize_hex(raw);
            let result = retry(
                || async {
                    match client.send_raw_transaction(&raw_hex).await {
                        Ok(_) => Ok(true),
                        Err(crate::bitcoin_client::error::Error::BitcoinRpc {
                            code: -27, ..
                        }) => Ok(true),
                        Err(crate::bitcoin_client::error::Error::BitcoinRpc {
                            code: -25 | -26,
                            ..
                        }) => Ok(false),
                        Err(e) => Err(e),
                    }
                },
                "send_raw_transaction",
                new_backoff_unlimited(),
                self.cancel_token.clone(),
            )
            .await;
            match result {
                Ok(true) => {}
                Ok(false) => {
                    warn!(txid = %raw.compute_txid(), "Transaction rejected by bitcoind");
                    return false;
                }
                Err(e) => {
                    warn!(txid = %raw.compute_txid(), %e, "send_raw_transaction failed");
                    return false;
                }
            }
        }

        true
    }
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        // Fall back to Bitcoin RPC (via tx cache)
        let client = self.bitcoin_client.as_ref()?;
        match client.get_raw_transaction(txid).await {
            Ok(tx) => Some(tx),
            Err(e) => {
                warn!(%txid, %e, "Failed to resolve transaction via RPC");
                None
            }
        }
    }
    async fn execute_transaction(
        &self,
        runtime: &mut Runtime,
        height: i64,
        tx_id: i64,
        tx: &indexer_types::Transaction,
    ) -> Result<()> {
        for input in &tx.inputs {
            let op_return_data = tx.op_return_data.get(&(input.input_index as u64)).cloned();
            process_input(
                runtime,
                input,
                height,
                Some(tx_id),
                tx.index,
                tx.txid,
                op_return_data,
            )
            .await?;
        }
        Ok(())
    }
    async fn replay_blocks_from(&mut self, height: u64) -> Result<()> {
        if let Some(tx) = &self.replay_tx {
            tx.send(height)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send replay request to poller: {e}"))?;
        }
        Ok(())
    }

    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        filter_map((0, tx.clone()))
    }
}

pub async fn process_input(
    runtime: &mut Runtime,
    input: &indexer_types::Input,
    height: i64,
    tx_id: Option<i64>,
    tx_index: i64,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::OpReturnData>,
) -> Result<()> {
    if input.insts.is_aggregate() {
        process_aggregate_input(
            runtime,
            input,
            height,
            tx_id,
            tx_index,
            txid,
            op_return_data,
        )
        .await?;
    } else {
        process_direct_input(
            runtime,
            input,
            height,
            tx_id,
            tx_index,
            txid,
            op_return_data,
        )
        .await?;
    }
    Ok(())
}

async fn process_direct_input(
    runtime: &mut Runtime,
    input: &indexer_types::Input,
    height: i64,
    tx_id: Option<i64>,
    tx_index: i64,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::OpReturnData>,
) -> Result<()> {
    let conn = runtime.get_storage_conn();
    let holder_ref = HolderRef::XOnlyPubkey(input.x_only_pubkey.to_string());
    let holder = Holder::from_holder_ref(holder_ref, &conn, height)
        .await
        .map_err(|e| anyhow::anyhow!("holder resolution failed: {e:?}"))?;
    let identity = holder
        .identity
        .ok_or_else(|| anyhow::anyhow!("expected identity for x_only_pubkey signer"))?;

    let metadata = OpMetadata {
        previous_output: input.previous_output,
        input_index: input.input_index,
        signer_id: identity.signer_id() as u64,
    };

    for (op_index, inst) in input.insts.ops.iter().enumerate() {
        let op = op_from_inst(inst.clone(), metadata.clone());

        runtime
            .set_context(
                height,
                Some(crate::runtime::TransactionContext {
                    tx_id,
                    tx_index,
                    input_index: input.input_index,
                    op_index: op_index as i64,
                    txid,
                }),
                Some(input.previous_output),
                op_return_data.clone().map(Into::into),
            )
            .await;

        execute_op(runtime, &op).await?;
    }
    Ok(())
}

async fn process_aggregate_input(
    runtime: &mut Runtime,
    input: &indexer_types::Input,
    height: i64,
    tx_id: Option<i64>,
    tx_index: i64,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::OpReturnData>,
) -> Result<()> {
    let signer_map = match crate::bls::verify_aggregate(runtime, &input.insts).await {
        Ok(map) => map,
        Err(e) => {
            warn!("Aggregate verification failed: {e}");
            return Ok(());
        }
    };

    let agg = input
        .insts
        .aggregate
        .as_ref()
        .expect("aggregate must be present after successful verification");

    for (op_index, (inst, &signer_id)) in input
        .insts
        .ops
        .iter()
        .zip(agg.signer_ids.iter())
        .enumerate()
    {
        if !signer_map.contains_key(&signer_id) {
            warn!("signer_id {signer_id} not in signer_map after verification");
            continue;
        };

        runtime
            .set_context(
                height,
                Some(crate::runtime::TransactionContext {
                    tx_id,
                    tx_index,
                    input_index: input.input_index,
                    op_index: op_index as i64,
                    txid,
                }),
                Some(input.previous_output),
                op_return_data.clone().map(Into::into),
            )
            .await;

        if let Inst::Call { nonce, .. } = inst {
            let nonce_val = match nonce {
                Some(n) => *n,
                None => {
                    warn!("aggregate Call for signer {signer_id} missing nonce");
                    continue;
                }
            };
            let conn = runtime.get_storage_conn();
            let height = runtime.storage.height;
            let identity = database::types::Identity::new(signer_id as i64);
            match identity
                .advance_nonce(&conn, nonce_val as i64, height)
                .await
            {
                Ok(_) => {}
                Err(database::queries::Error::InvalidData(msg)) => {
                    warn!("aggregate nonce check failed for signer {signer_id}: {msg}");
                    continue;
                }
                Err(e) => {
                    anyhow::bail!("aggregate nonce advance error for signer {signer_id}: {e}");
                }
            }
        }

        let metadata = OpMetadata {
            previous_output: input.previous_output,
            input_index: input.input_index,
            signer_id,
        };
        let op = op_from_inst(inst.clone(), metadata);
        execute_op(runtime, &op).await?;
    }
    Ok(())
}

async fn execute_op(runtime: &mut Runtime, op: &indexer_types::Op) -> Result<()> {
    let identity = database::types::Identity::new(op.metadata().signer_id as i64);
    let signer = Signer::Id(identity);

    match op {
        indexer_types::Op::Publish {
            gas_limit,
            name,
            bytes,
            ..
        } => {
            runtime.set_gas_limit(*gas_limit);
            match runtime.publish(&signer, name, bytes).await {
                Ok(_) => {}
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("Publish operation failed: {e:#}");
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    return Err(e.context("Publish operation infrastructure failure"));
                }
            }
        }
        indexer_types::Op::Call {
            gas_limit,
            contract,
            expr,
            ..
        } => {
            runtime.set_gas_limit(*gas_limit);
            match runtime
                .execute(Some(&signer), &(contract.into()), expr)
                .await
            {
                Ok(_) => {}
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("Call operation failed: {e:#}");
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    return Err(e.context("Call operation infrastructure failure"));
                }
            }
        }
        indexer_types::Op::Issuance { .. } => match runtime.issuance(&signer).await {
            Ok(_) => {}
            Err(ExecutionError::Deterministic(e)) => {
                warn!("Issuance operation failed: {e:#}");
            }
            Err(ExecutionError::NonDeterministic(e)) => {
                return Err(e.context("Issuance infrastructure failure"));
            }
        },
        indexer_types::Op::RegisterBlsKey {
            bls_pubkey,
            schnorr_sig,
            bls_sig,
            ..
        } => {
            match runtime
                .register_bls_key(
                    &signer,
                    bls_pubkey.as_slice(),
                    schnorr_sig.as_slice(),
                    bls_sig.as_slice(),
                )
                .await
            {
                Ok(_) => {
                    registry::api::registered(runtime, &Signer::Core(Box::new(signer.clone())))
                        .await
                        .map_err(|e| anyhow::anyhow!("registry.registered failed: {e}"))?;
                }
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("RegisterBlsKey failed: {e:#}");
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    return Err(e.context("RegisterBlsKey infrastructure failure"));
                }
            }
        }
    }
    Ok(())
}
