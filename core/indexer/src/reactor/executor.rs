use anyhow::Result;
use bitcoin::Txid;
use indexer_types::OpWithResult;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::bitcoin_client::Client;
use crate::consensus::Height;
use crate::database::{self};
use crate::runtime::Runtime;

use super::block_handler::{batch_handler, block_handler, simulate_handler};

/// Check if a parsed transaction contains only batchable ops.
/// Non-batchable ops (Publish, Issuance, RegisterBlsKey) must only execute
/// via Value::Block decisions, not consensus batches.
pub fn is_batchable(ops: &[indexer_types::Op]) -> bool {
    !ops.iter().any(|op| {
        matches!(
            op,
            indexer_types::Op::Publish { .. }
                | indexer_types::Op::Issuance { .. }
                | indexer_types::Op::RegisterBlsKey { .. }
        )
    })
}

/// Abstraction over transaction execution and state rollback.
///
/// The consensus orchestration logic (`ConsensusState.process_decided_batch` and
/// `run_finality_checks`) calls these methods instead of directly manipulating state.
/// This allows different backends: `StateLog` (mock, used by consensus-sim)
/// and `RuntimeExecutor` (production, WASM execution + DB).
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
    /// Sources: local mempool/block cache, Bitcoin RPC, LRU cache.
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction>;

    /// Execute a consensus-decided batch of mempool transactions at the given anchor height.
    async fn execute_batch(
        &mut self,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        consensus_height: Height,
        certificate: &[u8],
        txs: &[indexer_types::Transaction],
        raw_txs: &[bitcoin::Transaction],
    );

    /// Execute a confirmed Bitcoin block. Implementations handle deduplication of
    /// transactions already executed via a prior batch.
    async fn execute_block(&mut self, block: &indexer_types::Block);

    /// Signal the block source to re-deliver blocks starting from `height`.
    /// In prod: resets the poller via a control channel.
    /// In tests: records the call for assertions; the test sends blocks manually.
    async fn replay_blocks_from(&mut self, height: u64);

    /// Parse a bitcoin::Transaction into an indexer_types::Transaction.
    /// Used during replay/sync when parsed_tx_cache misses.
    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction>;

    /// Simulate executing a transaction without committing state changes.
    async fn simulate(&mut self, _btx: bitcoin::Transaction) -> Result<Vec<OpWithResult>> {
        anyhow::bail!("Simulation not supported on this executor")
    }
}

/// Placeholder executor that does nothing. Used by the production reactor until
/// `RuntimeExecutor` is implemented in Phase 7.
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
    async fn execute_batch(
        &mut self,
        _anchor_height: u64,
        _anchor_hash: bitcoin::BlockHash,
        _consensus_height: Height,
        _certificate: &[u8],
        _txs: &[indexer_types::Transaction],
        _raw_txs: &[bitcoin::Transaction],
    ) {
    }
    async fn execute_block(&mut self, _block: &indexer_types::Block) {}
    async fn replay_blocks_from(&mut self, _height: u64) {}
    fn parse_transaction(&self, _tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        None
    }
}

/// Production executor: real WASM execution via Runtime + DB persistence.
pub struct RuntimeExecutor {
    pub runtime: Runtime,
    pub writer: database::Writer,
    pub bitcoin_client: Option<Client>,
    pub replay_tx: Option<tokio::sync::mpsc::Sender<u64>>,
    pub cancel_token: CancellationToken,
}

impl RuntimeExecutor {
    pub fn new(
        runtime: Runtime,
        writer: database::Writer,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            runtime,
            writer,
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

    fn connection(&self) -> libsql::Connection {
        self.writer.connection()
    }
}

impl Executor for RuntimeExecutor {
    async fn validate_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        use crate::block::filter_map;
        use crate::retry::{new_backoff_unlimited, retry};

        // Parse Kontor ops — reject if no valid ops
        let parsed = filter_map((0, tx.clone()))?;

        if !is_batchable(&parsed.ops) {
            return None;
        }

        // Push to local bitcoind mempool (idempotent, succeeds if already present)
        if let Some(client) = &self.bitcoin_client {
            let raw_hex = bitcoin::consensus::encode::serialize_hex(tx);
            let result = retry(
                || client.send_raw_transaction(&raw_hex),
                "send_raw_transaction",
                new_backoff_unlimited(),
                self.cancel_token.clone(),
            )
            .await;
            if let Err(e) = result {
                warn!(txid = %tx.compute_txid(), %e, "Transaction rejected by bitcoind");
                return None;
            }
        }

        Some(parsed)
    }
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        // Check unconfirmed batch txs table first (for replay/sync recovery)
        if let Ok(Some(raw_bytes)) = crate::database::queries::select_unconfirmed_batch_tx(
            &self.connection(),
            &txid.to_string(),
        )
        .await
            && let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw_bytes)
        {
            return Some(tx);
        }

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
    async fn execute_batch(
        &mut self,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        consensus_height: Height,
        certificate: &[u8],
        txs: &[indexer_types::Transaction],
        raw_txs: &[bitcoin::Transaction],
    ) {
        if let Err(e) = batch_handler(
            &mut self.runtime,
            anchor_height,
            anchor_hash,
            consensus_height,
            certificate,
            txs,
            raw_txs,
        )
        .await
        {
            tracing::error!("batch_handler error: {e}");
        }
    }
    async fn execute_block(&mut self, block: &indexer_types::Block) {
        info!("# Block Kontor Transactions: {}", block.transactions.len());
        if let Err(e) = block_handler(&mut self.runtime, block).await {
            tracing::error!("block_handler error: {e}");
        }
    }
    async fn replay_blocks_from(&mut self, height: u64) {
        if let Some(tx) = &self.replay_tx
            && let Err(e) = tx.send(height).await
        {
            tracing::error!(%e, height, "Failed to send replay request to poller");
        }
    }

    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        use crate::block::filter_map;
        filter_map((0, tx.clone()))
    }

    async fn simulate(&mut self, btx: bitcoin::Transaction) -> Result<Vec<OpWithResult>> {
        simulate_handler(&mut self.runtime, btx).await
    }
}
