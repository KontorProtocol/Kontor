use anyhow::Result;
use bitcoin::Txid;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::bitcoin_client::Client;
use crate::block::filter_map;
use crate::retry::{new_backoff_unlimited, retry};
use crate::runtime::Runtime;

/// Check if a parsed transaction contains only batchable ops.
/// Publish must only execute via Value::Block decisions (contract address
/// depends on block height/tx_index). All other ops are batchable.
/// Aggregate inputs are always batchable.
pub fn is_batchable(inputs: &[indexer_types::TransactionInput]) -> bool {
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
    /// Validate a transaction and parse its Kontor ops.
    /// Returns the parsed transaction if valid, None otherwise.
    /// Implementations may also propagate the tx to the local bitcoind mempool.
    async fn validate_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction>;

    /// Resolve a txid to a full bitcoin::Transaction. Used to fetch transaction
    /// data for batch execution — batches carry only txids.
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction>;

    /// Execute a single transaction's operations at the given height.
    /// Called by the reactor after DB row insertion. Sets context and runs ops.
    async fn execute_transaction(
        &self,
        runtime: &mut Runtime,
        height: i64,
        tx_id: i64,
        tx: &indexer_types::Transaction,
    );

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
        _tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        None
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
    ) {
    }
    async fn replay_blocks_from(&mut self, _height: u64) -> Result<()> {
        Ok(())
    }
    fn parse_transaction(&self, _tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        None
    }
}

type ParsedTxCache = moka::sync::Cache<Txid, indexer_types::Transaction>;

/// Production executor: handles transaction validation, resolution, and op execution.
/// Does NOT own the Runtime — the reactor owns it and passes &mut Runtime when needed.
pub struct RuntimeExecutor {
    bitcoin_client: Option<Client>,
    replay_tx: Option<tokio::sync::mpsc::Sender<u64>>,
    cancel_token: CancellationToken,
    parsed_tx_cache: ParsedTxCache,
}

impl RuntimeExecutor {
    pub fn new(cancel_token: CancellationToken) -> Self {
        Self {
            bitcoin_client: None,
            replay_tx: None,
            cancel_token,
            parsed_tx_cache: moka::sync::Cache::builder().max_capacity(10_000).build(),
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
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        let parsed = self.parse_transaction(tx)?;

        if !is_batchable(&parsed.inputs) {
            return None;
        }

        // Push to local bitcoind mempool (idempotent, succeeds if already present).
        // -25 (RPC_VERIFY_ERROR): general validation error (missing inputs) — invalid
        // -26 (RPC_VERIFY_REJECTED): rejected by mempool policy — invalid
        // -27 (RPC_VERIFY_ALREADY_IN_UTXO_SET): tx already confirmed — treat as success
        // All other errors (network, node loading) are retried via unlimited backoff.
        if let Some(client) = &self.bitcoin_client {
            let raw_hex = bitcoin::consensus::encode::serialize_hex(tx);
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
                    warn!(txid = %tx.compute_txid(), "Transaction rejected by bitcoind");
                    return None;
                }
                Err(e) => {
                    warn!(txid = %tx.compute_txid(), %e, "send_raw_transaction failed");
                    return None;
                }
            }
        }

        Some(parsed)
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
    ) {
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
            .await;
        }
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
        let txid = tx.compute_txid();
        if let Some(parsed) = self.parsed_tx_cache.get(&txid) {
            return Some(parsed);
        }
        let parsed = filter_map((0, tx.clone()))?;
        self.parsed_tx_cache.insert(txid, parsed.clone());
        Some(parsed)
    }
}

pub async fn process_input(
    runtime: &mut Runtime,
    input: &indexer_types::TransactionInput,
    height: i64,
    tx_id: Option<i64>,
    tx_index: i64,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::OpReturnData>,
) {
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
        .await;
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
        .await;
    }
}

async fn process_direct_input(
    runtime: &mut Runtime,
    input: &indexer_types::TransactionInput,
    height: i64,
    tx_id: Option<i64>,
    tx_index: i64,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::OpReturnData>,
) {
    use crate::block::op_from_inst;
    use indexer_types::OpMetadata;

    let metadata = OpMetadata {
        previous_output: input.previous_output,
        input_index: input.input_index,
        signer: input.witness_signer.clone(),
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

        execute_op(runtime, &op).await;
    }
}

async fn process_aggregate_input(
    runtime: &mut Runtime,
    input: &indexer_types::TransactionInput,
    height: i64,
    tx_id: Option<i64>,
    tx_index: i64,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::OpReturnData>,
) {
    use crate::block::op_from_inst;
    use crate::runtime::{registry, wit::Signer};
    use indexer_types::{Inst, OpMetadata};

    let signer_map = match crate::bls::verify_aggregate(runtime, &input.insts).await {
        Ok(map) => map,
        Err(e) => {
            warn!("Aggregate verification failed: {e}");
            return;
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
        let x_only = match signer_map.get(&signer_id) {
            Some(x) => x.clone(),
            None => {
                warn!("signer_id {signer_id} not in signer_map after verification");
                continue;
            }
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
            let nonce_result = registry::api::advance_nonce(
                runtime,
                &Signer::Core(Box::new(Signer::Nobody)),
                signer_id,
                nonce_val,
            )
            .await;
            match nonce_result {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    warn!("aggregate nonce check failed for signer {signer_id}: {e:?}");
                    continue;
                }
                Err(e) => {
                    warn!("aggregate nonce advance error for signer {signer_id}: {e}");
                    continue;
                }
            }
        }

        let signer = Signer::XOnlyPubKey(x_only);
        let metadata = OpMetadata {
            previous_output: input.previous_output,
            input_index: input.input_index,
            signer: signer.clone(),
        };
        let op = op_from_inst(inst.clone(), metadata);
        execute_op(runtime, &op).await;
    }
}

async fn execute_op(runtime: &mut Runtime, op: &indexer_types::Op) {
    use crate::runtime::wit::Signer;

    if let Signer::XOnlyPubKey(x_only) = &op.metadata().signer
        && let Err(e) = runtime.ensure_signer(x_only).await
    {
        warn!("Failed to ensure signer for {x_only}: {e}");
        return;
    }

    match op {
        indexer_types::Op::Publish {
            metadata,
            gas_limit,
            name,
            bytes,
        } => {
            runtime.set_gas_limit(*gas_limit);
            let result = runtime.publish(&metadata.signer, name, bytes).await;
            if result.is_err() {
                warn!("Publish operation failed: {:?}", result);
            }
        }
        indexer_types::Op::Call {
            metadata,
            gas_limit,
            contract,
            expr,
            ..
        } => {
            runtime.set_gas_limit(*gas_limit);
            let result = runtime
                .execute(Some(&metadata.signer), &(contract.into()), expr)
                .await;
            if result.is_err() {
                warn!("Call operation failed: {:?}", result);
            }
        }
        indexer_types::Op::Issuance { metadata, .. } => {
            let result = runtime.issuance(&metadata.signer).await;
            if result.is_err() {
                warn!("Issuance operation failed: {:?}", result);
            }
        }
        indexer_types::Op::RegisterBlsKey {
            metadata,
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        } => {
            if let Err(e) = runtime
                .register_bls_key(
                    &metadata.signer,
                    bls_pubkey.as_slice(),
                    schnorr_sig.as_slice(),
                    bls_sig.as_slice(),
                )
                .await
            {
                warn!("RegisterBlsKey failed: {e}");
            }
        }
    }
}
