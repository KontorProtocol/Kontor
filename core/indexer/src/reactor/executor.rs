use bitcoin::Txid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    Batched,
    Confirmed,
}

/// Abstraction over transaction execution and state rollback.
///
/// The consensus orchestration logic (`ConsensusState.process_decided_batch` and
/// `run_finality_checks`) calls these methods instead of directly manipulating state.
/// This allows different backends: `StateLogExecutor` (mock, used by consensus-sim)
/// and `RuntimeExecutor` (production, WASM execution + DB).
pub trait Executor {
    fn validate_transaction(&self, txid: &Txid) -> bool;
    fn execute_transaction(&mut self, anchor_height: u64, txid: Txid, status: TxStatus);
    fn rollback_state(&mut self, to_anchor: u64) -> usize;
    fn checkpoint(&self) -> Option<[u8; 32]>;
}

/// Placeholder executor that does nothing. Used by the production reactor until
/// `RuntimeExecutor` is implemented in Phase 6.
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    fn validate_transaction(&self, _txid: &Txid) -> bool {
        true
    }
    fn execute_transaction(&mut self, _anchor_height: u64, _txid: Txid, _status: TxStatus) {}
    fn rollback_state(&mut self, _to_anchor: u64) -> usize {
        0
    }
    fn checkpoint(&self) -> Option<[u8; 32]> {
        None
    }
}
