use indexer::consensus::Height;

pub const FINALITY_WINDOW: u64 = 6;

#[derive(Debug, Clone)]
pub struct PendingBatch {
    pub consensus_height: Height,
    pub anchor_height: u64,
    pub txids: Vec<[u8; 32]>,
    pub deadline: u64, // anchor_height + FINALITY_WINDOW
}

#[derive(Debug, Clone, PartialEq)]
pub enum FinalityEvent {
    BatchFinalized {
        consensus_height: Height,
        anchor_height: u64,
    },
    Rollback {
        from_anchor: u64,
        invalidated_batches: Vec<Height>,
        missing_txids: Vec<[u8; 32]>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum StateEvent {
    BlockProcessed {
        height: u64,
        unbatched_count: usize,
        checkpoint: [u8; 32],
    },
    BatchApplied {
        consensus_height: Height,
        anchor_height: u64,
        txid_count: usize,
        checkpoint: [u8; 32],
    },
    RollbackExecuted {
        to_anchor: u64,
        entries_removed: usize,
        checkpoint: [u8; 32],
    },
}
