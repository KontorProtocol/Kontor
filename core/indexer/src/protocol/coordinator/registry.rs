use anyhow::{Result, bail};

use super::baseline::Baseline;
use super::manifest::ProtocolManifest;
#[cfg(all(kontor_managed, feature = "protocol-qualification"))]
use super::successor;
use crate::protocol::execution::ExecutorVersion;
use crate::protocol::identity::{MigrationDefinition, ProtocolId};
use crate::protocol::v1::migration_definition;
#[cfg(all(kontor_managed, feature = "protocol-qualification"))]
use crate::protocol::v2::migration_definition as p2_migration;

pub(crate) struct InstalledProtocol {
    pub(crate) executor: ExecutorVersion,
    pub(crate) migration: MigrationDefinition,
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
        });
    }
    #[cfg(all(kontor_managed, feature = "protocol-qualification"))]
    if manifest == &successor::manifest(manifest.chain)? {
        return Ok(InstalledProtocol {
            executor: ExecutorVersion::P2,
            migration: p2_migration::install_fixture(manifest.executor),
        });
    }
    #[cfg(all(kontor_managed, feature = "protocol-qualification"))]
    if manifest == &successor::qualification_third(manifest.chain)? {
        return Ok(InstalledProtocol {
            executor: ExecutorVersion::P2,
            migration: p2_migration::preserve(manifest.executor),
        });
    }
    bail!(UnavailableProtocol(manifest.id()?))
}
