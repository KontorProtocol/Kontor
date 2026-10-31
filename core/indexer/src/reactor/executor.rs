use anyhow::{Context, Result};
use bitcoin::{Transaction as BitcoinTransaction, Txid};
use indexer_types::{Block, Transaction};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tracing::warn;

use crate::bitcoin_client::error::Error as RpcError;
use crate::bitcoin_client::types::Acceptance;
use crate::bitcoin_client::{Client, check_mempool_acceptance};
use crate::bitcoin_follower::block::BlockInput;
use crate::block::filter_map;
use crate::database::queries::insert_transaction_execution_usage;
use crate::protocol::coordinator::selection::{ExecutionSelection, ExecutorVersion};
pub use crate::protocol::v1::execution::process_input;
use crate::protocol::v1::{execution, lifecycle, transactions};

use crate::retry::{new_backoff_limited, retry};
use crate::runtime::Runtime;
use futures_util::future::BoxFuture;

/// The I/O phase's per-transaction verdict. The reason is for logs only —
/// every rejection has the same effect (drop from the candidate set / reject
/// the proposal).
#[derive(Debug)]
pub enum TxPolicy {
    Accepted,
    Rejected(String),
}

pub struct RecognizedTransaction {
    pub raw: BitcoinTransaction,
    pub parsed: Option<Transaction>,
}

fn recognize_mempool(
    transactions: Vec<BitcoinTransaction>,
    recognize: impl Fn(&BitcoinTransaction) -> Option<Transaction> + Send + Sync,
) -> Vec<RecognizedTransaction> {
    transactions
        .into_par_iter()
        .map(|raw| RecognizedTransaction {
            parsed: recognize(&raw),
            raw,
        })
        .collect()
}

/// Abstraction over transaction execution and state rollback.
///
/// The consensus orchestration logic (`ConsensusState.process_decided_batch` and
/// `run_finality_checks`) calls these methods instead of directly manipulating state.
#[allow(async_fn_in_trait)]
pub(crate) trait Executor: Sync {
    fn decode_simulation(
        &self,
        selection: &ExecutionSelection,
        raw: &[u8],
    ) -> std::result::Result<BitcoinTransaction, String> {
        match selection.version() {
            ExecutorVersion::LegacyP1 => transactions::decode_simulation(raw),
        }
    }

    fn is_batchable(&self, selection: &ExecutionSelection, tx: &Transaction) -> bool {
        match selection.version() {
            ExecutorVersion::LegacyP1 => transactions::is_batchable(&tx.inputs),
        }
    }

    async fn run_block_lifecycle(
        &self,
        selection: &ExecutionSelection,
        runtime: &mut Runtime,
        block: &Block,
    ) -> Result<()> {
        selection.ensure_runtime(runtime.network, runtime.executor_version())?;
        selection.ensure_execution(runtime.network, block.height)?;
        selection.ensure_block(block.height, block.hash)?;
        let mut runtime = runtime.bind_selection(selection)?;
        match selection.version() {
            ExecutorVersion::LegacyP1 => lifecycle::run_block_lifecycle(&mut runtime, block).await,
        }
    }

    /// Start the I/O phase of validating `txs` against bitcoind: mempool
    /// policy acceptance plus the fee-threshold check, verdicts in input
    /// order.
    ///
    /// Returns an OWNED, `'static` future. The reactor polls it as an arm of
    /// its root `select!`, so the in-flight RPC is drop-cancelled at shutdown
    /// for free and the event loop keeps serving every other arm while it
    /// runs — this is what took bitcoind off the consensus hot path.
    /// Everything the future needs rides in; it must not touch reactor state
    /// (state predicates run at snapshot and again at apply, on the loop).
    ///
    /// `Err` is infrastructure only — bitcoind unreachable after retries —
    /// and the reactor treats it as fatal (I5).
    ///
    /// Returns each transaction PAIRED with its verdict, `txs` moving through
    /// the future and back. Structural, not stylistic: a separate verdict
    /// vector invites a `zip` at the apply site, and `zip` silently truncates —
    /// a short vector would let trailing transactions through unchecked.
    fn validate_txs(
        &self,
        txs: Vec<bitcoin::Transaction>,
        threshold_sat_per_vb: u64,
    ) -> BoxFuture<'static, Result<Vec<(bitcoin::Transaction, TxPolicy)>>>;

    /// Resolve many txids in one round trip
    /// where the backend supports it (bitcoind's JSON-RPC batch + tx cache),
    /// returning `None` per still-unresolved txid, in input order. The reactor's
    /// replay/sync path resolves whole decided batches at once, so a per-txid
    /// RPC there is one round trip per historical transaction.
    async fn resolve_transactions(&self, txids: &[Txid]) -> Vec<Option<bitcoin::Transaction>>;

    async fn execute_transaction_inner(
        &self,
        selection: &ExecutionSelection,
        runtime: &mut Runtime,
        height: u64,
        tx_id: u64,
        tx: &indexer_types::Transaction,
    ) -> Result<Vec<Vec<Option<anyhow::Error>>>>;

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
        selection: &ExecutionSelection,
        runtime: &mut Runtime,
        height: u64,
        tx_id: u64,
        tx: &indexer_types::Transaction,
    ) -> Result<Vec<Vec<Option<anyhow::Error>>>> {
        selection.ensure_runtime(runtime.network, runtime.executor_version())?;
        selection.ensure_execution(runtime.network, height)?;
        let mut runtime = runtime.bind_selection(selection)?;
        let previous = runtime.start_usage();
        let result = self
            .execute_transaction_inner(selection, &mut runtime, height, tx_id, tx)
            .await;
        let usage = runtime.finish_usage(previous);
        let result = result?;
        insert_transaction_execution_usage(&runtime.get_storage_conn(), tx_id, usage?).await?;
        Ok(result)
    }

    /// Signal the block source to re-deliver blocks strictly AFTER `after_height`.
    /// Exclusive, matching the poller's rollback convention: a caller that has just
    /// truncated to `h` asks for `h` so block `h` itself is re-delivered.
    async fn replay_blocks_after(&mut self, after_height: u64) -> Result<()>;

    /// Parse a bitcoin::Transaction into an indexer_types::Transaction.
    fn parse_transaction(
        &self,
        selection: &ExecutionSelection,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction>;

    async fn parse_block(
        &self,
        selection: &ExecutionSelection,
        block: BlockInput,
    ) -> Result<Block> {
        Ok(block.recognize(|raw| self.parse_transaction(selection, raw)))
    }

    // Owned preparation never carries storage authority across a suspension.
    // Production moves recognition to a blocking worker; the default is for
    // lightweight executors whose recognizer has no expensive decoding.
    fn parse_mempool(
        &self,
        selection: &ExecutionSelection,
        transactions: Vec<BitcoinTransaction>,
    ) -> BoxFuture<'static, Result<Vec<RecognizedTransaction>>> {
        let prepared =
            recognize_mempool(transactions, |raw| self.parse_transaction(selection, raw));
        Box::pin(async move { Ok(prepared) })
    }
}

/// Placeholder executor that does nothing.
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    fn validate_txs(
        &self,
        txs: Vec<bitcoin::Transaction>,
        _threshold_sat_per_vb: u64,
    ) -> BoxFuture<'static, Result<Vec<(bitcoin::Transaction, TxPolicy)>>> {
        Box::pin(async move {
            Ok(txs
                .into_iter()
                .map(|tx| (tx, TxPolicy::Rejected("noop executor".to_string())))
                .collect())
        })
    }
    async fn resolve_transactions(&self, txids: &[Txid]) -> Vec<Option<bitcoin::Transaction>> {
        txids.iter().map(|_| None).collect()
    }
    async fn execute_transaction_inner(
        &self,
        _selection: &ExecutionSelection,
        _runtime: &mut Runtime,
        _height: u64,
        _tx_id: u64,
        _tx: &indexer_types::Transaction,
    ) -> Result<Vec<Vec<Option<anyhow::Error>>>> {
        Ok(Vec::new())
    }
    async fn replay_blocks_after(&mut self, _after_height: u64) -> Result<()> {
        Ok(())
    }
    fn parse_transaction(
        &self,
        _selection: &ExecutionSelection,
        _tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        None
    }
}

/// Production executor: handles transaction validation, resolution, and op execution.
/// Does NOT own the Runtime — the reactor owns it and passes &mut Runtime when needed.
pub struct RuntimeExecutor {
    bitcoin_client: Client,
    replay_tx: Option<tokio::sync::mpsc::Sender<u64>>,
}

impl RuntimeExecutor {
    fn recognize_transaction(tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        filter_map((0, tx.clone()))
    }

    pub fn new(bitcoin_client: Client) -> Self {
        Self {
            bitcoin_client,
            replay_tx: None,
        }
    }

    pub fn with_replay_tx(mut self, tx: tokio::sync::mpsc::Sender<u64>) -> Self {
        self.replay_tx = Some(tx);
        self
    }
}

impl Executor for RuntimeExecutor {
    fn validate_txs(
        &self,
        txs: Vec<bitcoin::Transaction>,
        threshold_sat_per_vb: u64,
    ) -> BoxFuture<'static, Result<Vec<(bitcoin::Transaction, TxPolicy)>>> {
        // Owned clone: the future must borrow nothing, so the reactor can hold
        // it across loop iterations and drop it at shutdown.
        let client = self.bitcoin_client.clone();
        Box::pin(async move {
            let mut verdicts = Vec::with_capacity(txs.len());
            for tx in txs {
                let raw_hex = bitcoin::consensus::encode::serialize_hex(&tx);
                let txid = tx.compute_txid();
                // `check_mempool_acceptance` handles idempotency and the
                // already-known fallback inside the client layer. RPC failure
                // after retries is infrastructure — bitcoind unreachable — and
                // propagates as fatal (I5). Plain `retry`: this future is
                // dropped at shutdown, backoff and in-flight request included.
                let acceptance = retry(
                    || check_mempool_acceptance(&client, &raw_hex, &txid),
                    "check_mempool_acceptance",
                    new_backoff_limited(),
                )
                .await
                .with_context(|| {
                    format!(
                        "check_mempool_acceptance failed after retries for {txid}; \
                         bitcoind may be unreachable"
                    )
                })?;
                let policy = match acceptance {
                    Acceptance::Accepted {
                        fee_rate_sat_per_vb,
                    } if fee_rate_sat_per_vb < threshold_sat_per_vb => TxPolicy::Rejected(format!(
                        "fee rate {fee_rate_sat_per_vb} below threshold {threshold_sat_per_vb}"
                    )),
                    Acceptance::Accepted { .. } => TxPolicy::Accepted,
                    Acceptance::Rejected { reason } => {
                        TxPolicy::Rejected(format!("mempool policy: {reason}"))
                    }
                };
                // Relay each accepted tx IMMEDIATELY, before validating the
                // next. Load-bearing for parent/child batches, not redundancy:
                // a child spending an unconfirmed parent's output only passes
                // `testmempoolaccept` on a bitcoind that already HOLDS the
                // parent, and on a validator whose node has not seen it via
                // P2P yet, this in-order relay is what puts it there. It works
                // only because the caller hands `txs` in dependency order — an
                // incoming proposal is validated for that order (`batch_is_ordered`)
                // and a locally-built candidate set is `dependency_sort`ed before
                // this phase (`make_value_snapshot`), so a parent always precedes
                // its child here. (`-27` = already known; `-25`/`-26` = rejected.)
                let policy = match policy {
                    TxPolicy::Accepted => {
                        let submitted = retry(
                            || async {
                                match client.send_raw_transaction(&raw_hex).await {
                                    Ok(_) | Err(RpcError::BitcoinRpc { code: -27, .. }) => Ok(true),
                                    Err(RpcError::BitcoinRpc {
                                        code: -25 | -26, ..
                                    }) => Ok(false),
                                    Err(e) => Err(e),
                                }
                            },
                            "send_raw_transaction",
                            new_backoff_limited(),
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "send_raw_transaction failed after retries for {txid}; \
                                 bitcoind may be unreachable"
                            )
                        })?;
                        if submitted {
                            TxPolicy::Accepted
                        } else {
                            TxPolicy::Rejected("rejected by bitcoind on relay".to_string())
                        }
                    }
                    rejected => rejected,
                };
                verdicts.push((tx, policy));
            }
            Ok(verdicts)
        })
    }

    async fn resolve_transactions(&self, txids: &[Txid]) -> Vec<Option<bitcoin::Transaction>> {
        // One JSON-RPC batch (cache-checked) instead of a round trip per txid.
        match self.bitcoin_client.get_raw_transactions(txids).await {
            Ok(results) => results
                .into_iter()
                .zip(txids)
                .map(|(r, txid)| match r {
                    Ok(tx) => Some(tx),
                    Err(e) => {
                        warn!(%txid, %e, "Failed to resolve transaction via RPC");
                        None
                    }
                })
                .collect(),
            Err(e) => {
                warn!(%e, "Batched transaction resolution failed");
                txids.iter().map(|_| None).collect()
            }
        }
    }
    async fn execute_transaction_inner(
        &self,
        selection: &ExecutionSelection,
        runtime: &mut Runtime,
        height: u64,
        tx_id: u64,
        tx: &indexer_types::Transaction,
    ) -> Result<Vec<Vec<Option<anyhow::Error>>>> {
        match selection.version() {
            ExecutorVersion::LegacyP1 => {
                execution::execute_transaction(runtime, height, tx_id, tx).await
            }
        }
    }
    async fn replay_blocks_after(&mut self, after_height: u64) -> Result<()> {
        if let Some(tx) = &self.replay_tx {
            tx.send(after_height)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send replay request to poller: {e}"))?;
        }
        Ok(())
    }

    fn parse_transaction(
        &self,
        selection: &ExecutionSelection,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        match selection.version() {
            ExecutorVersion::LegacyP1 => Self::recognize_transaction(tx),
        }
    }

    async fn parse_block(
        &self,
        selection: &ExecutionSelection,
        block: BlockInput,
    ) -> Result<Block> {
        // Parsing can decompress witnesses. Keep that CPU work off the async
        // worker, with only owned raw input crossing the task boundary.
        let version = selection.version();
        Ok(tokio::task::spawn_blocking(move || match version {
            ExecutorVersion::LegacyP1 => block.recognize(Self::recognize_transaction),
        })
        .await?)
    }

    fn parse_mempool(
        &self,
        selection: &ExecutionSelection,
        transactions: Vec<BitcoinTransaction>,
    ) -> BoxFuture<'static, Result<Vec<RecognizedTransaction>>> {
        let version = selection.version();
        Box::pin(async move {
            Ok(tokio::task::spawn_blocking(move || match version {
                ExecutorVersion::LegacyP1 => {
                    recognize_mempool(transactions, Self::recognize_transaction)
                }
            })
            .await?)
        })
    }
}
