//! Prometheus metric names. Centralized so call sites can't drift, and so
//! adding/renaming a metric happens in one place.

pub const BLOCK_HEIGHT: &str = "index_current_block_height";
pub const ITEMS_INDEXED: &str = "items_indexed_total";
pub const BLOCK_DURATION: &str = "indexing_duration_seconds";
