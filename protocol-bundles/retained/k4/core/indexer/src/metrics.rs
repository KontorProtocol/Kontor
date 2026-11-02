//! Prometheus metric names. Centralized so call sites can't drift, and so
//! adding/renaming a metric happens in one place.
//!
//! Per-event duration data is on the `duration_ms` field of the existing
//! `info!("Block processed", ...)` and `info!("Batch processing complete", ...)`
//! log lines, not as metric series. Cloud Logging is the right surface for
//! "how long did this specific event take" debugging; metrics here are
//! liveness + throughput only.

pub const BLOCK_HEIGHT: &str = "index_current_block_height";
pub const CONSENSUS_HEIGHT: &str = "index_current_consensus_height";
pub const ITEMS_INDEXED: &str = "items_indexed_total";

/// Bitcoin blocks buffered but not yet executed. Bounded by
/// `MAX_PENDING_BLOCKS`; sitting at that ceiling means the reactor has stopped
/// consuming the poller.
pub const PENDING_BLOCKS: &str = "index_pending_blocks";

/// Decided values waiting on data before they can execute. Healthy nodes idle
/// near zero and drain within a block. A queue that only grows is a node whose
/// consensus height is advancing while its execution is not — it is on the
/// chain but no longer of it, and no amount of waiting recovers it.
///
/// Together with `BLOCK_HEIGHT` and `CONSENSUS_HEIGHT` this is the alert that
/// would have caught the 2026-08 signet halt in minutes: consensus climbing
/// while the block height stays flat.
pub const DEFERRED_DECISIONS: &str = "index_deferred_decisions";
