use anyhow::{Result, ensure};

use super::baseline::Baseline;
use super::manifest::ProtocolManifest;
use crate::protocol::execution::ExecutorVersion;
use crate::protocol::identity::{MigrationDefinition, ProtocolId};
use crate::protocol::v1::migration_definition;

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
    ensure!(
        manifest == &first.manifest,
        UnavailableProtocol(manifest.id()?)
    );
    Ok(InstalledProtocol {
        executor: ExecutorVersion::LegacyP1,
        migration: migration_definition::noop(first.manifest.executor),
    })
}
