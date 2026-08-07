use bitcoin::{BlockHash, Txid};

use super::{Height, Value};

pub const FINALITY_WINDOW: u64 = 6;

/// Bitcoin height by which a batch anchored at `anchor_height` must have its
/// transactions confirmed, or the batch is void and its anchor rolls back.
pub const fn deadline_for(anchor_height: u64) -> u64 {
    anchor_height + FINALITY_WINDOW
}

/// Lowest anchor height whose batches can still be awaiting a deadline at `tip`.
/// Startup rehydration reloads exactly this band, so it introduces no new window —
/// it reconstructs the set the running node already tracks.
///
/// Inclusive of the at-deadline anchor (`anchor >= floor`, not `>`): a batch whose
/// deadline is exactly `tip` still needs its verdict, and dropping it on restart
/// would silently skip the rollback a peer performs. The first `check_finality`
/// after startup settles it.
pub const fn tracking_floor(tip: u64) -> u64 {
    tip.saturating_sub(FINALITY_WINDOW)
}

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
        /// Per DECISION, not flattened. Which batch a txid went missing from is what
        /// lets the exclusion be recorded against that height alone — flattening it
        /// is how a global ban gets built by accident.
        missing: Vec<BatchExclusion>,
    },
}

/// The txids one decided batch failed to confirm by its own deadline.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchExclusion {
    pub consensus_height: Height,
    pub anchor_height: u64,
    pub txids: Vec<Txid>,
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
