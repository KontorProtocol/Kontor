use bitcoin::Txid;

use crate::consensus::{CommitCertificate, Ctx, Height, Value};

/// Abstraction over transaction execution and state rollback.
///
/// The consensus orchestration logic (`ConsensusState.process_decided_batch` and
/// `run_finality_checks`) calls these methods instead of directly manipulating state.
/// This allows different backends: `StateLog` (mock, used by consensus-sim)
/// and `RuntimeExecutor` (production, WASM execution + DB).
#[allow(async_fn_in_trait)]
pub trait Executor {
    async fn validate_transaction(&self, tx: &bitcoin::Transaction) -> bool;

    /// Resolve a txid to a full bitcoin::Transaction. Used to fetch transaction
    /// data for batch execution — batches carry only txids.
    /// Sources: local mempool/block cache, Bitcoin RPC, LRU cache.
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction>;

    /// Execute a consensus-decided batch of mempool transactions at the given anchor height.
    async fn execute_batch(
        &mut self,
        anchor_height: u64,
        consensus_height: Height,
        txs: &[bitcoin::Transaction],
    );

    /// Execute a confirmed Bitcoin block. Implementations handle deduplication of
    /// transactions already executed via a prior batch.
    async fn execute_block(&mut self, block: &indexer_types::Block);

    async fn rollback_state(&mut self, to_anchor: u64) -> usize;
    async fn checkpoint(&self) -> Option<[u8; 32]>;

    /// Was this txid confirmed in a Bitcoin block? Used by finality checks.
    /// In prod, this is a DB query. In sim, checks a HashSet.
    async fn is_confirmed_on_chain(&self, txid: &bitcoin::Txid) -> bool;

    /// Return the highest consensus height whose anchor_height < `anchor`.
    /// Used after a Bitcoin rollback to determine where to resume consensus.
    async fn last_batch_consensus_height_before(&self, anchor: u64) -> Option<Height>;

    /// The highest block height that has been executed. Used to detect timeout
    /// race conditions where blocks were executed before their corresponding batch.
    async fn last_executed_block_height(&self) -> Option<u64>;

    // --- Decided value storage (used by Malachite sync protocol) ---

    /// Store a decided value and its commit certificate. Called after `Finalized`.
    async fn store_decided(
        &mut self,
        height: Height,
        value: Value,
        certificate: CommitCertificate<Ctx>,
    );

    /// Retrieve a decided value at the given height.
    async fn get_decided(&self, height: Height) -> Option<(Value, CommitCertificate<Ctx>)>;

    /// Return the minimum decided height, or None if no values stored.
    async fn min_decided_height(&self) -> Option<Height>;
}

/// Placeholder executor that does nothing. Used by the production reactor until
/// `RuntimeExecutor` is implemented in Phase 7.
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    async fn validate_transaction(&self, _tx: &bitcoin::Transaction) -> bool {
        true
    }
    async fn resolve_transaction(&self, _txid: &Txid) -> Option<bitcoin::Transaction> {
        None
    }
    async fn execute_batch(
        &mut self,
        _anchor_height: u64,
        _consensus_height: Height,
        _txs: &[bitcoin::Transaction],
    ) {
    }
    async fn execute_block(&mut self, _block: &indexer_types::Block) {}
    async fn rollback_state(&mut self, _to_anchor: u64) -> usize {
        0
    }
    async fn checkpoint(&self) -> Option<[u8; 32]> {
        None
    }
    async fn last_batch_consensus_height_before(&self, _anchor: u64) -> Option<Height> {
        None
    }
    async fn is_confirmed_on_chain(&self, _txid: &bitcoin::Txid) -> bool {
        false
    }
    async fn last_executed_block_height(&self) -> Option<u64> {
        None
    }
    async fn store_decided(
        &mut self,
        _height: Height,
        _value: Value,
        _certificate: CommitCertificate<Ctx>,
    ) {
    }
    async fn get_decided(&self, _height: Height) -> Option<(Value, CommitCertificate<Ctx>)> {
        None
    }
    async fn min_decided_height(&self) -> Option<Height> {
        None
    }
}
