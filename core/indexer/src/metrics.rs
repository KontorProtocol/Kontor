//! Prometheus metric names. Centralized so call sites can't drift, and so
//! adding/renaming a metric happens in one place.
//!
//! Metrics are diagnostic trends. Exact cross-node comparisons use /api/protocol.

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

mod engine;
mod exposition;
mod telemetry;

pub(crate) use engine::EngineMetrics;
pub use engine::collection_panicking;
#[cfg(test)]
pub(crate) use exposition::normalize as validate_engine_sample;

pub fn recorder_builder() -> PrometheusBuilder {
    let duration = &[
        0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
    ];
    let mut builder = PrometheusBuilder::new();
    for name in [
        "kontor_closure_step_duration_seconds",
        "kontor_recovery_duration_seconds",
    ] {
        builder = builder
            .set_buckets_for_metric(Matcher::Full(name.into()), duration)
            .expect("fixed duration buckets");
    }
    builder
        .set_buckets_for_metric(
            Matcher::Full("kontor_rollback_depth_blocks".into()),
            &[0.0, 1.0, 2.0, 3.0, 6.0, 12.0, 24.0, 48.0, 144.0, 1008.0],
        )
        .expect("fixed rollback buckets")
}
pub(crate) use telemetry::Step;
pub use telemetry::Telemetry;

pub const BLOCK_HEIGHT: &str = "index_current_block_height";
pub const CONSENSUS_HEIGHT: &str = "index_current_consensus_height";
/// Execution work, including replay, not a count of unique transactions.
pub const ITEMS_INDEXED: &str = "items_indexed_total";

/// Bitcoin blocks buffered but not yet executed. Bounded by
/// `MAX_PENDING_BLOCKS`; sitting at that ceiling means the reactor has stopped
/// consuming the poller.
pub const PENDING_BLOCKS: &str = "index_pending_blocks";

/// Boolean presence of a deferred decision, not a queue length.
pub const DEFERRED_DECISIONS: &str = "index_deferred_decisions";
