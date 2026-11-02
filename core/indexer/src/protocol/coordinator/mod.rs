pub(crate) mod activation;
pub(crate) mod activation_execution;
pub(crate) mod application_closure;
pub(crate) mod artifacts;
pub(crate) mod baseline;
pub(crate) mod bootstrap;
pub(crate) mod certified_decision;
pub(crate) mod certified_input;
pub(crate) mod closure_execution;
pub(crate) mod closure_record;
pub(crate) mod closure_work;
#[cfg(any(test, feature = "protocol-qualification"))]
pub(crate) mod committee;
pub(crate) mod control;
pub(crate) mod decision;
#[cfg(any(test, kontor_managed))]
pub(crate) mod durable_signer;
pub(crate) mod genesis;
pub(crate) mod linked;
#[cfg(kontor_managed)]
pub(crate) mod managed;
pub(crate) mod manifest;
pub(crate) mod migration;
mod migration_export;
pub(crate) mod registration_history;
pub(crate) mod registry;
pub(crate) mod replay_input;
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

#[cfg(any(kontor_managed, test))]
pub(crate) mod successor;
