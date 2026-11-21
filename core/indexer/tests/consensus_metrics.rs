use kontor_consensus_first::api;

// Exercise the bundle's exact writer without enabling cfg(test) on its borrowed
// node modules, whose unit tests belong to the indexer crate.
#[path = "../../../protocol-bundles/consensus/metrics.rs"]
mod metrics;
