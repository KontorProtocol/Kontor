use anyhow::{Context, Result};
use bitcoin::Txid;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use indexer_types::{InstKind, OpKind};

use crate::bitcoin_client::types::Acceptance;
use crate::bitcoin_client::{Client, check_mempool_acceptance};
use crate::block::{TxWalker, filter_map};
use crate::database;
use crate::retry::{new_backoff_limited, retry};
use crate::runtime::ExecutionError;
use crate::runtime::Runtime;
use crate::runtime::registry;
use crate::runtime::wit::Signer;

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
            .any(|inst| matches!(inst.kind, InstKind::Publish { .. }))
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
    ///
    /// `threshold_sat_per_vb` is the precomputed acceptance floor for this
    /// validation pass — typically `fee_index.fastest_fee() * 0.9`.
    /// Hoisting it to the caller avoids recomputing per tx in a batch.
    ///
    /// Returns `Ok(true)` if the tx is valid for inclusion, `Ok(false)` if
    /// it failed a policy check (batchability, mempool rejection, fee
    /// threshold). Returns `Err` only for infrastructure failures that
    /// indicate the validator can't safely continue (e.g. bitcoind RPC
    /// unreachable after retries) — the reactor propagates this and shuts
    /// down via the cancellation token.
    async fn validate_transaction(
        &self,
        raw: &bitcoin::Transaction,
        parsed: &indexer_types::Transaction,
        threshold_sat_per_vb: u64,
    ) -> Result<bool>;

    /// Resolve a txid to a full bitcoin::Transaction. Used to fetch transaction
    /// data for batch execution — batches carry only txids.
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction>;

    /// Execute a single transaction's operations at the given height.
    /// Called by the reactor after DB row insertion. Sets context and runs ops.
    /// Returns Err only for non-deterministic infrastructure failures.
    ///
    /// The success case returns a nested positional failure vector: outer
    /// index = `tx.inputs[i]`, inner index = `inputs[i].insts.ops[j]`. A
    /// slot is `None` when that op executed without deterministic failure;
    /// `Some(e)` when it failed (pre-execution rejection or in-execution
    /// trap/OOG/Err). The reactor's canonical path discards this vec; the
    /// simulate handler zips it into the response.
    async fn execute_transaction(
        &self,
        runtime: &mut Runtime,
        height: u64,
        tx_id: u64,
        tx: &indexer_types::Transaction,
    ) -> Result<Vec<Vec<Option<anyhow::Error>>>>;

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
        _threshold_sat_per_vb: u64,
    ) -> Result<bool> {
        Ok(false)
    }
    async fn resolve_transaction(&self, _txid: &Txid) -> Option<bitcoin::Transaction> {
        None
    }
    async fn execute_transaction(
        &self,
        _runtime: &mut Runtime,
        _height: u64,
        _tx_id: u64,
        _tx: &indexer_types::Transaction,
    ) -> Result<Vec<Vec<Option<anyhow::Error>>>> {
        Ok(Vec::new())
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
    bitcoin_client: Client,
    replay_tx: Option<tokio::sync::mpsc::Sender<u64>>,
    cancel_token: CancellationToken,
}

impl RuntimeExecutor {
    pub fn new(cancel_token: CancellationToken, bitcoin_client: Client) -> Self {
        Self {
            bitcoin_client,
            replay_tx: None,
            cancel_token,
        }
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
        threshold_sat_per_vb: u64,
    ) -> Result<bool> {
        if !is_batchable(&parsed.inputs) {
            return Ok(false);
        }

        let raw_hex = bitcoin::consensus::encode::serialize_hex(raw);
        let txid = raw.compute_txid();

        // 1. Check Bitcoin's mempool policy + obtain the package fee rate.
        //    `check_mempool_acceptance` handles the idempotency and
        //    already-known-fallback inside the client layer. RPC failure
        //    after retries is fatal — bitcoind is unreachable.
        let acceptance = retry(
            || check_mempool_acceptance(&self.bitcoin_client, &raw_hex, &txid),
            "check_mempool_acceptance",
            new_backoff_limited(),
            self.cancel_token.clone(),
        )
        .await
        .with_context(|| {
            format!(
                "check_mempool_acceptance failed after retries for {txid}; \
                 bitcoind may be unreachable"
            )
        })?;
        let tx_fee_rate = match acceptance {
            Acceptance::Accepted {
                fee_rate_sat_per_vb,
            } => fee_rate_sat_per_vb,
            Acceptance::Rejected { reason } => {
                warn!(%txid, %reason, "Rejected by mempool policy");
                return Ok(false);
            }
        };

        // 2. Fee-rate threshold check.
        if tx_fee_rate < threshold_sat_per_vb {
            warn!(
                %txid,
                tx_fee_rate,
                threshold = threshold_sat_per_vb,
                "Rejected: fee rate below threshold"
            );
            return Ok(false);
        }

        // 3. send_raw_transaction: broadcast to the network. Redundant
        //    with testmempoolaccept but catches races and ensures the tx
        //    is relayed to our bitcoind if we were the proposer.
        //    RPC failure after retries is fatal (same reasoning as above).
        let result = retry(
            || async {
                match self.bitcoin_client.send_raw_transaction(&raw_hex).await {
                    Ok(_) => Ok(true),
                    Err(crate::bitcoin_client::error::Error::BitcoinRpc { code: -27, .. }) => {
                        Ok(true)
                    }
                    Err(crate::bitcoin_client::error::Error::BitcoinRpc {
                        code: -25 | -26,
                        ..
                    }) => Ok(false),
                    Err(e) => Err(e),
                }
            },
            "send_raw_transaction",
            new_backoff_limited(),
            self.cancel_token.clone(),
        )
        .await
        .with_context(|| {
            format!(
                "send_raw_transaction failed after retries for {txid}; \
                 bitcoind may be unreachable"
            )
        })?;
        match result {
            true => Ok(true),
            false => {
                warn!(%txid, "Transaction rejected by bitcoind");
                Ok(false)
            }
        }
    }
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        // Fall back to Bitcoin RPC (via tx cache)
        match self.bitcoin_client.get_raw_transaction(txid).await {
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
        height: u64,
        tx_id: u64,
        tx: &indexer_types::Transaction,
    ) -> Result<Vec<Vec<Option<anyhow::Error>>>> {
        let mut all = Vec::with_capacity(tx.inputs.len());
        // `TxWalker` owns the cross-input Sponsor state machine + the
        // payment-override computation; the same instance walks every
        // input, capturing Sponsor Ops and advancing at each input
        // boundary. Shared with `block::inspect` so simulate's zip stays
        // aligned.
        let mut walker = TxWalker::new();
        for input in &tx.inputs {
            let op_return_data = tx
                .op_return_data
                .iter()
                .find(|e| e.input_index == input.input_index)
                .map(|e| e.recipient.clone());
            let per_input = process_input(
                runtime,
                &mut walker,
                input,
                height,
                Some(tx_id),
                tx.index,
                tx.txid,
                op_return_data,
            )
            .await?;
            all.push(per_input);
        }
        Ok(all)
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

/// Process every op in one Bitcoin-input's `Insts`. Returns the
/// positional failure vector aligned with `input.insts.ops` — `None` at
/// position j means the j-th op executed without a deterministic failure,
/// `Some(err)` means rejection or in-execution failure. `OpKind::Sponsor`
/// ops short-circuit `execute_op` (no contract dispatch, no result row
/// outside this in-memory vec) and contribute `None`.
///
/// `walker` carries the cross-input Sponsor state across calls — the
/// caller (`execute_transaction`) owns it and reuses the same instance
/// for every input; this function captures any Sponsor in `input` and
/// advances at the input boundary.
pub async fn process_input(
    runtime: &mut Runtime,
    walker: &mut TxWalker,
    input: &indexer_types::Input,
    height: u64,
    tx_id: Option<u64>,
    tx_index: u32,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::SignerRef>,
) -> Result<Vec<Option<anyhow::Error>>> {
    let errors = if input.insts.is_aggregate() {
        process_aggregate_input(
            runtime,
            walker,
            input,
            height,
            tx_id,
            tx_index,
            txid,
            op_return_data,
        )
        .await?
    } else {
        process_direct_input(
            runtime,
            walker,
            input,
            height,
            tx_id,
            tx_index,
            txid,
            op_return_data,
        )
        .await?
    };
    walker.next_input();
    Ok(errors)
}

async fn process_direct_input(
    runtime: &mut Runtime,
    walker: &mut TxWalker,
    input: &indexer_types::Input,
    height: u64,
    tx_id: Option<u64>,
    tx_index: u32,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::SignerRef>,
) -> Result<Vec<Option<anyhow::Error>>> {
    let identity = runtime
        .get_or_create_identity(&input.x_only_pubkey.to_string())
        .await?;

    let signer_id = identity.signer_id();
    let mut errors: Vec<Option<anyhow::Error>> = Vec::with_capacity(input.insts.ops.len());
    for (op_index, inst) in input.insts.ops.iter().enumerate() {
        // Direct inputs have no publisher — only a cross-input Sponsor
        // (held in `walker.active`) can override the input signer's
        // self-pay default. `walker.materialize` handles that internally.
        let op = match walker.materialize(input, op_index, signer_id, None, inst) {
            Ok(op) => op,
            Err(e) => {
                warn!("Rejected direct op: {e:#}");
                errors.push(Some(e));
                continue;
            }
        };

        // Sponsor Op short-circuits — it's a directive, not a contract
        // call. Its terms have already been captured by `walker.materialize`
        // and will drive the next input's payment overrides.
        if matches!(op.kind, OpKind::Sponsor) {
            errors.push(None);
            continue;
        }

        runtime
            .set_context(
                height,
                Some(crate::runtime::TransactionContext {
                    tx_id,
                    tx_index,
                    input_index: input.input_index,
                    op_index: op_index as u32,
                    txid,
                }),
                Some(input.previous_output),
                op_return_data.clone().map(Into::into),
            )
            .await;

        errors.push(execute_op(runtime, &op).await?);
    }
    Ok(errors)
}

async fn process_aggregate_input(
    runtime: &mut Runtime,
    walker: &mut TxWalker,
    input: &indexer_types::Input,
    height: u64,
    tx_id: Option<u64>,
    tx_index: u32,
    txid: bitcoin::Txid,
    op_return_data: Option<indexer_types::SignerRef>,
) -> Result<Vec<Option<anyhow::Error>>> {
    let n_ops = input.insts.ops.len();
    let resolved = match crate::bls::verify_aggregate(runtime, &input.insts).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Aggregate verification failed: {e}");
            // Fan the input-wide rejection across every op slot so the
            // positional vector remains length-aligned with input.insts.ops.
            // Aggregates can't carry `Sponsor` (BLS shape validation rejects),
            // so the walker has nothing to capture this input.
            let msg = format!("aggregate verification failed: {e:#}");
            return Ok((0..n_ops).map(|_| Some(anyhow::anyhow!("{msg}"))).collect());
        }
    };

    let agg = input
        .insts
        .aggregate
        .as_ref()
        .expect("aggregate must be present after successful verification");

    // Resolve the publisher's signer_id once — payer for any op with
    // `AggregateSigner.sponsored = true`. The publisher is the Bitcoin
    // input's x_only_pubkey, ensured into the signers table.
    let publisher_signer_id = {
        let identity = runtime
            .get_or_create_identity(&input.x_only_pubkey.to_string())
            .await?;
        identity.signer_id()
    };

    let mut errors: Vec<Option<anyhow::Error>> = Vec::with_capacity(n_ops);
    for (op_index, ((inst, agg_signer), &signer_id)) in input
        .insts
        .ops
        .iter()
        .zip(agg.signers.iter())
        .zip(resolved.signer_ids.iter())
        .enumerate()
    {
        if !resolved.signer_map.contains_key(&signer_id) {
            warn!("signer_id {signer_id} not in signer_map after verification");
            errors.push(Some(anyhow::anyhow!(
                "signer_id {signer_id} not in signer_map after verification"
            )));
            continue;
        };

        runtime
            .set_context(
                height,
                Some(crate::runtime::TransactionContext {
                    tx_id,
                    tx_index,
                    input_index: input.input_index,
                    op_index: op_index as u32,
                    txid,
                }),
                Some(input.previous_output),
                op_return_data.clone().map(Into::into),
            )
            .await;

        // Every aggregate op advances the signer's nonce. The variant restriction
        // ("Call only") is enforced separately in validate_aggregate_shape; here
        // we just consume the nonce the co-signer committed to in their BLS sig.
        let conn = runtime.get_storage_conn();
        let identity = database::types::Identity::new(signer_id);
        match identity
            .advance_nonce(&conn, agg_signer.nonce, height)
            .await
        {
            Ok(_) => {}
            Err(database::queries::Error::InvalidData(msg)) => {
                warn!("aggregate nonce check failed for signer {signer_id}: {msg}");
                errors.push(Some(anyhow::anyhow!(
                    "nonce check failed for signer {signer_id}: {msg}"
                )));
                continue;
            }
            Err(e) => {
                anyhow::bail!("aggregate nonce advance error for signer {signer_id}: {e}");
            }
        }

        // `walker.materialize` handles the precedence: cross-input
        // Sponsor (`walker.active`) wins over the aggregate's per-op
        // publisher offer, which it computes from `signer.sponsored` +
        // the publisher's signer_id we pass in. Capture is a no-op in
        // practice — BLS shape validation rejects Sponsor in aggregates.
        let op =
            match walker.materialize(input, op_index, signer_id, Some(publisher_signer_id), inst) {
                Ok(op) => op,
                Err(e) => {
                    warn!("Rejected aggregate op for signer {signer_id}: {e:#}");
                    errors.push(Some(e));
                    continue;
                }
            };
        errors.push(execute_op(runtime, &op).await?);
    }
    Ok(errors)
}

/// Execute one op against the runtime.
///
/// Returns `Ok(None)` for success; `Ok(Some(e))` for a deterministic
/// failure (the op didn't take effect, but the failure is determinable
/// from chain state — every node will reach the same conclusion);
/// `Err(_)` for a non-deterministic infrastructure failure that
/// crashes the reactor (returning Err propagates upward and aborts).
async fn execute_op(
    runtime: &mut Runtime,
    op: &indexer_types::Op,
) -> Result<Option<anyhow::Error>> {
    let identity = database::types::Identity::new(op.metadata.signer_id);
    let signer = Signer::Id(identity);
    let payment = op.metadata.payment.clone();

    match &op.kind {
        OpKind::Publish { name, bytes } => {
            match runtime.publish(&signer, payment, name, bytes).await {
                Ok(_) => Ok(None),
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("Publish operation failed: {e:#}");
                    Ok(Some(e))
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    Err(e.context("Publish operation infrastructure failure"))
                }
            }
        }
        OpKind::Call { contract, expr, .. } => {
            match runtime
                .execute(Some(&signer), Some(payment), &(contract.into()), expr)
                .await
            {
                Ok(_) => Ok(None),
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("Call operation failed: {e:#}");
                    Ok(Some(e))
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    Err(e.context("Call operation infrastructure failure"))
                }
            }
        }
        OpKind::Issuance => match runtime.issuance(&signer).await {
            Ok(_) => Ok(None),
            Err(ExecutionError::Deterministic(e)) => {
                warn!("Issuance operation failed: {e:#}");
                Ok(Some(e))
            }
            Err(ExecutionError::NonDeterministic(e)) => {
                Err(e.context("Issuance infrastructure failure"))
            }
        },
        // Sponsor is a payer-redirection directive: no contract dispatch,
        // no gas held against the runtime. The per-input loop captures
        // `op.metadata.payment` from the materialized Op into
        // `pending_for_next` before reaching `execute_op` (see
        // `process_direct_input`), so this branch is the no-op success
        // that keeps the failure vector positionally aligned.
        OpKind::Sponsor => Ok(None),
        OpKind::RegisterBlsKey {
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        } => {
            // Charge the payer for the registration via the registry contract
            // first. If the hold fails (insufficient tokens), the host-side
            // register_bls_key DB write below is skipped.
            match runtime
                .execute(
                    Some(&signer),
                    Some(payment),
                    &registry::address(),
                    "registered()",
                )
                .await
            {
                Ok(_) => {}
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("registry.registered failed: {e:#}");
                    return Ok(Some(e));
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    return Err(e.context("registry.registered infrastructure failure"));
                }
            }
            match runtime
                .register_bls_key(
                    &signer,
                    bls_pubkey.as_slice(),
                    schnorr_sig.as_slice(),
                    bls_sig.as_slice(),
                )
                .await
            {
                Ok(_) => Ok(None),
                Err(ExecutionError::Deterministic(e)) => {
                    warn!("RegisterBlsKey failed: {e:#}");
                    Ok(Some(e))
                }
                Err(ExecutionError::NonDeterministic(e)) => {
                    Err(e.context("RegisterBlsKey infrastructure failure"))
                }
            }
        }
    }
}
