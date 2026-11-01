pub(crate) mod application_closure;
pub(crate) mod baseline;
pub(crate) mod bootstrap;
pub(crate) mod certified_decision;
pub(crate) mod certified_input;
pub(crate) mod closure_execution;
pub(crate) mod closure_record;
pub(crate) mod closure_work;
pub(crate) mod committee;
pub(crate) mod decision;
pub(crate) mod genesis;
pub(crate) mod linked;
pub(crate) mod manifest;
pub(crate) mod migration;
pub(crate) mod registration_history;
pub(crate) mod selection;
pub(crate) mod v1;

// Pruning is node-local, but must retain every active or historical rule set
// that can still require rollback. Add new versions to this maximum before
// enabling them; using only the currently selected version can prune old state.
pub(crate) const fn minimum_prune_retention_blocks() -> u64 {
    v1::FINALITY_ROLLBACK_DEPTH
}
#[cfg(all(test, not(kontor_node)))]
pub(crate) mod view;
