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
