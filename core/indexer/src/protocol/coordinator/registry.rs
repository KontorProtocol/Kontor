use anyhow::{Result, bail};

use super::baseline::Baseline;
#[cfg(kontor_managed)]
use super::managed::startup::Bundle;
use super::manifest::ProtocolManifest;
#[cfg(kontor_managed)]
use super::successor;
use crate::protocol::execution::ExecutorVersion;
use crate::protocol::identity::{MigrationDefinition, ProtocolId};
use crate::protocol::v1::migration_definition;
#[cfg(kontor_managed)]
use crate::protocol::v2::migration_definition as p2_migration;

pub(crate) struct InstalledProtocol {
    pub(crate) executor: ExecutorVersion,
    pub(crate) migration: MigrationDefinition,
    #[cfg(kontor_managed)]
    pub(crate) consensus: Bundle,
}

#[derive(Debug, thiserror::Error)]
#[error("protocol is not installed: {0:?}")]
pub(crate) struct UnavailableProtocol(ProtocolId);

// Installation is an exact manifest mapping, not permission to run an arbitrary
// manifest that happens to name one familiar executor or migration routine.
pub(crate) fn resolve(manifest: &ProtocolManifest) -> Result<InstalledProtocol> {
    let first = Baseline::for_node(manifest.chain)?;
    if manifest == &first.manifest {
        return Ok(InstalledProtocol {
            executor: ExecutorVersion::LegacyP1,
            migration: migration_definition::noop(first.manifest.executor),
            #[cfg(kontor_managed)]
            consensus: Bundle::First,
        });
    }
    #[cfg(kontor_managed)]
    if manifest == &successor::manifest(manifest.chain)? {
        return Ok(InstalledProtocol {
            executor: ExecutorVersion::P2,
            migration: p2_migration::token_count(manifest.executor),
            consensus: Bundle::First,
        });
    }
    bail!(UnavailableProtocol(manifest.id()?))
}
