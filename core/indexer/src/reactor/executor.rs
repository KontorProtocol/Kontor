use crate::consensus::Height;

/// Abstraction over transaction execution and state rollback.
///
/// The consensus orchestration logic (`ConsensusState.process_decided_batch` and
/// `run_finality_checks`) calls these methods instead of directly manipulating state.
/// This allows different backends: `StateLog` (mock, used by consensus-sim)
/// and `RuntimeExecutor` (production, WASM execution + DB).
#[allow(async_fn_in_trait)]
pub trait Executor {
    async fn validate_transaction(&self, tx: &bitcoin::Transaction) -> bool;

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
}

/// Placeholder executor that does nothing. Used by the production reactor until
/// `RuntimeExecutor` is implemented in Phase 7.
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    async fn validate_transaction(&self, _tx: &bitcoin::Transaction) -> bool {
        true
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
}
