use anyhow::{Context, Result};
#[cfg(test)]
use bitcoin::BlockHash;
use bitcoin::consensus::serialize;
#[cfg(test)]
use bitcoin::hashes::Hash;
use bitcoin::{Network, Transaction as BitcoinTransaction};
#[cfg(test)]
use indexer_types::Block;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::bitcoin_client::error::Error as RpcError;
use crate::bitcoin_client::types::Acceptance;
use crate::bitcoin_client::{Client, check_mempool_acceptance};
use crate::bitcoin_follower::block::BlockInput;
#[cfg(test)]
use crate::block::filter_map;
use crate::database::queries::insert_transaction_execution_usage;
use crate::protocol::coordinator::linked::{
    self, PreparedBlock, PreparedTransaction, TransactionRecognizer,
};
use crate::protocol::coordinator::selection::ExecutionSelection;
#[cfg(test)]
use crate::protocol::coordinator::selection::ExecutorVersion;
#[cfg(test)]
use crate::protocol::v1::execution;
#[cfg(test)]
pub use crate::protocol::v1::execution::process_input;
#[cfg(test)]
use crate::protocol::v1::lifecycle;

use crate::retry::{new_backoff_limited, retry};
#[cfg(test)]
use crate::runtime::Runtime;
use crate::runtime::fuel::ExecutionUsage;
use crate::runtime::pool::LinkedSession;
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
    pub(crate) parsed: Option<PreparedTransaction>,
}

fn recognize_mempool(
    transactions: Vec<BitcoinTransaction>,
    recognize: impl Fn(&BitcoinTransaction) -> Result<Option<PreparedTransaction>> + Send + Sync,
) -> Result<Vec<RecognizedTransaction>> {
    transactions
        .into_par_iter()
        .map(|raw| {
            Ok(RecognizedTransaction {
                parsed: recognize(&raw)?,
                raw,
            })
        })
        .collect()
}

/// Abstraction over transaction execution and state rollback.
///
/// The consensus orchestration logic (`ConsensusState.process_decided_batch` and
/// `run_finality_checks`) calls these methods instead of directly manipulating state.
#[allow(async_fn_in_trait)]
pub(crate) trait Executor: Sync {
    fn prepare_transaction(
        &self,
        recognizer: &TransactionRecognizer,
        selection: &ExecutionSelection,
        raw: &BitcoinTransaction,
    ) -> Result<Option<PreparedTransaction>> {
        recognizer
            .recognize(selection, serialize(raw))?
            .map_err(|error| {
                anyhow::anyhow!("serialized Bitcoin transaction failed to decode: {error}")
            })
    }

    fn prepare_simulation(
        &self,
        recognizer: &TransactionRecognizer,
        selection: &ExecutionSelection,
        raw: Vec<u8>,
    ) -> Result<Result<Option<PreparedTransaction>, String>> {
        recognizer.recognize(selection, raw)
    }

    async fn execute_prepared(
        &self,
        selection: &ExecutionSelection,
        session: &LinkedSession,
        network: Network,
        height: u64,
        tx_id: u64,
        transaction: &PreparedTransaction,
    ) -> Result<Vec<Vec<Option<String>>>> {
        selection.ensure_execution(network, height)?;
        linked::execute_transaction(
            session,
            selection,
            network,
            transaction,
            transaction.index,
            tx_id,
        )
        .await
    }

    async fn prepare_block(
        &self,
        recognizer: &TransactionRecognizer,
        selection: &ExecutionSelection,
        block: BlockInput,
    ) -> Result<PreparedBlock> {
        block.prepare(|raw| self.prepare_transaction(recognizer, selection, raw))
    }

    #[cfg(test)]
    async fn run_block_lifecycle(
        &self,
        selection: &ExecutionSelection,
        runtime: &mut Runtime,
        block: &Block,
    ) -> Result<()> {
        selection.ensure_runtime(runtime.network, runtime.executor_version())?;
        selection.ensure_execution(runtime.network, block.height)?;
        selection.ensure_block(block.height, block.hash)?;
        let mut runtime = runtime.bind_selection(&selection.envelope())?;
        match selection.version() {
            ExecutorVersion::LegacyP1 => {
                lifecycle::run_block_lifecycle(
                    &mut runtime,
                    block.height,
                    block.hash.to_byte_array(),
                )
                .await
            }
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

    #[cfg(test)]
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
    #[cfg(test)]
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
        let mut runtime = runtime.bind_selection(&selection.envelope())?;
        let previous = runtime.start_usage();
        let result = self
            .execute_transaction_inner(selection, &mut runtime, height, tx_id, tx)
            .await;
        let usage = runtime.finish_usage(previous);
        let result = result?;
        insert_transaction_execution_usage(&runtime.get_storage_conn(), tx_id, usage?).await?;
        Ok(result)
    }

    /// Parse a bitcoin::Transaction into an indexer_types::Transaction.
    #[cfg(test)]
    fn parse_transaction(
        &self,
        selection: &ExecutionSelection,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction>;

    // Owned preparation never carries storage authority across a suspension.
    // Production moves recognition to a blocking worker; the default is for
    // lightweight executors whose recognizer has no expensive decoding.
    fn parse_mempool(
        &self,
        recognizer: &TransactionRecognizer,
        selection: &ExecutionSelection,
        transactions: Vec<BitcoinTransaction>,
    ) -> BoxFuture<'static, Result<Vec<RecognizedTransaction>>> {
        let prepared = recognize_mempool(transactions, |raw| {
            self.prepare_transaction(recognizer, selection, raw)
        });
        Box::pin(async move { prepared })
    }
}

/// Placeholder executor that does nothing.
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    fn prepare_transaction(
        &self,
        _recognizer: &TransactionRecognizer,
        _selection: &ExecutionSelection,
        _raw: &BitcoinTransaction,
    ) -> Result<Option<PreparedTransaction>> {
        Ok(None)
    }

    fn prepare_simulation(
        &self,
        recognizer: &TransactionRecognizer,
        selection: &ExecutionSelection,
        raw: Vec<u8>,
    ) -> Result<Result<Option<PreparedTransaction>, String>> {
        Ok(recognizer.recognize(selection, raw)?.map(|_| None))
    }

    async fn execute_prepared(
        &self,
        selection: &ExecutionSelection,
        session: &LinkedSession,
        network: Network,
        height: u64,
        tx_id: u64,
        transaction: &PreparedTransaction,
    ) -> Result<Vec<Vec<Option<String>>>> {
        selection.ensure_execution(network, height)?;
        transaction.payload(selection, network)?;
        insert_transaction_execution_usage(&session.conn, tx_id, ExecutionUsage::default()).await?;
        Ok(Vec::new())
    }

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
    #[cfg(test)]
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
    #[cfg(test)]
    fn parse_transaction(
        &self,
        _selection: &ExecutionSelection,
        _tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        None
    }
}

/// Production executor: handles transaction validation and op execution.
/// Contract execution uses the selected retained session; Bitcoin I/O stays in the node.
pub struct RuntimeExecutor {
    bitcoin_client: Client,
}

impl RuntimeExecutor {
    #[cfg(test)]
    fn recognize_transaction(tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        filter_map((0, tx.clone()))
    }

    pub fn new(bitcoin_client: Client) -> Self {
        Self { bitcoin_client }
    }

    #[cfg(test)]
    pub(super) async fn retained_test_block(
        &self,
        height: u64,
        hash: BlockHash,
    ) -> Result<BlockInput> {
        Ok(BlockInput::from_bitcoin(
            height,
            hash,
            self.bitcoin_client.get_block(&hash).await?,
        ))
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

    #[cfg(test)]
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

    #[cfg(test)]
    fn parse_transaction(
        &self,
        selection: &ExecutionSelection,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        match selection.version() {
            ExecutorVersion::LegacyP1 => Self::recognize_transaction(tx),
        }
    }

    async fn prepare_block(
        &self,
        recognizer: &TransactionRecognizer,
        selection: &ExecutionSelection,
        block: BlockInput,
    ) -> Result<PreparedBlock> {
        let recognizer = recognizer.clone();
        let selection = selection.clone();
        tokio::task::spawn_blocking(move || {
            block.prepare(|raw| {
                recognizer
                    .recognize(&selection, serialize(raw))?
                    .map_err(|error| {
                        anyhow::anyhow!("serialized Bitcoin transaction failed to decode: {error}")
                    })
            })
        })
        .await?
    }

    fn parse_mempool(
        &self,
        recognizer: &TransactionRecognizer,
        selection: &ExecutionSelection,
        transactions: Vec<BitcoinTransaction>,
    ) -> BoxFuture<'static, Result<Vec<RecognizedTransaction>>> {
        let recognizer = recognizer.clone();
        let selection = selection.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                recognize_mempool(transactions, |raw| {
                    recognizer
                        .recognize(&selection, serialize(raw))?
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "serialized Bitcoin transaction failed to decode: {error}"
                            )
                        })
                })
            })
            .await?
        })
    }
}
