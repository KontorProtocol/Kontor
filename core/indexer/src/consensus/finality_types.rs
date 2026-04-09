use bitcoin::{BlockHash, Txid};

use super::{Height, Value};

pub const FINALITY_WINDOW: u64 = 6;

#[derive(Debug, Clone)]
pub struct UnfinalizedBatch {
    pub consensus_height: Height,
    pub anchor_height: u64,
    pub anchor_hash: BlockHash,
    pub txids: Vec<Txid>,
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
        missing_txids: Vec<Txid>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum StateEvent {
    BlockProcessed {
        height: u64,
        unbatched_count: usize,
        checkpoint: Option<[u8; 32]>,
    },
    BatchApplied {
        consensus_height: Height,
        anchor_height: u64,
        txid_count: usize,
        checkpoint: Option<[u8; 32]>,
    },
    RollbackExecuted {
        to_anchor: u64,
        entries_removed: usize,
        checkpoint: Option<[u8; 32]>,
    },
}

/// A decided batch observed from a node.
#[derive(Debug, Clone)]
pub struct DecidedBatch {
    pub validator_index: Option<usize>,
    pub consensus_height: Height,
    pub value: Value,
}
