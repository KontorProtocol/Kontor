#[cfg(not(kontor_node))]
pub(crate) mod fixture_migration;
pub(crate) mod migration_definition;
#[cfg(not(kontor_node))]
pub(crate) mod native;

pub(crate) const FIXTURE_NAME: &str = "upgrade-fixture";
