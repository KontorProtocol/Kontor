use anyhow::{Result, ensure};

use super::baseline::{Baseline, source};
use super::consensus_rules;
use super::manifest::ProtocolManifest;
use crate::protocol::canonical_codec::Encoder;
#[cfg(any(kontor_managed, test))]
use crate::protocol::identity::ChainId;
use crate::protocol::identity::{DefinitionReference, domain_digest};
use crate::protocol::v2::{FIXTURE_NAME, migration_definition};

pub(crate) const EXECUTOR_REFERENCE: &[u8] =
    include_bytes!("../../../../../protocol-bundles/executor-observer/definition.bin");
const FIXTURE_ARTIFACT: &str = "core/indexer/src/protocol/v2/native/upgrade_fixture.wasm.br";

#[cfg(kontor_managed)]
pub(crate) fn manifest(chain: ChainId) -> Result<ProtocolManifest> {
    let first = Baseline::for_node(chain)?;
    let reference = DefinitionReference::decode(EXECUTOR_REFERENCE)?;
    compose(&first, &reference)
}

fn compose(first: &Baseline, reference: &DefinitionReference) -> Result<ProtocolManifest> {
    let mut next =
        Baseline::compose_consensus(first.manifest.chain, reference, consensus_rules::REFERENCE)?
            .manifest;
    ensure!(
        first.manifest.executor != next.executor,
        "P2 must use an independent executor"
    );
    ensure!(
        first.manifest.consensus == next.consensus,
        "P2 must preserve the shared consensus rules"
    );
    let mut native = Encoder::default();
    native.fixed(&next.native_contracts_root)?;
    native.bytes(FIXTURE_NAME.as_bytes())?;
    native.fixed(&source(reference, FIXTURE_ARTIFACT)?)?;
    next.native_contracts_root = domain_digest(b"kontor/native-additions/v1", &native.finish());
    next.protocol_number = 2;
    next.predecessor = first.manifest.id()?;
    next.state_schema = 2;
    next.input_state_schema = 1;
    next.output_state_schema = 2;
    next.migration = migration_definition::install_fixture(next.executor).id()?;
    Ok(next)
}

// A second genuine transition for qualification, sharing P2's execution semantics.
// Normal nodes do not install this manifest merely because they have its executor.
#[cfg(all(kontor_managed, feature = "protocol-qualification"))]
pub(crate) fn qualification_third(chain: ChainId) -> Result<ProtocolManifest> {
    let mut next = manifest(chain)?;
    next.predecessor = next.id()?;
    next.protocol_number = 3;
    next.input_state_schema = 2;
    next.migration = migration_definition::preserve(next.executor).id()?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::coordinator::registry;
    #[cfg(all(kontor_managed, feature = "protocol-qualification"))]
    use crate::protocol::execution::ExecutorVersion;

    #[test]
    fn p2_keeps_consensus_rules_with_distinct_execution_and_migration() -> Result<()> {
        let chain = ChainId([7; 32]);
        let retained = DefinitionReference::decode(include_bytes!(
            "../../../../../protocol-bundles/executor-first/definition.bin"
        ))?;
        let first = Baseline::compose_consensus(chain, &retained, consensus_rules::REFERENCE)?;
        let reference = DefinitionReference::decode(EXECUTOR_REFERENCE)?;
        let next = compose(&first, &reference)?;
        assert_ne!(next.executor, first.manifest.executor);
        assert_eq!(next.consensus, first.manifest.consensus);
        assert_eq!(next.consensus, consensus_rules::definition());
        assert_ne!(
            next.native_contracts_root,
            first.manifest.native_contracts_root
        );
        assert_eq!(next.certificate_codec, first.manifest.certificate_codec);
        assert_eq!(next.transaction_formats, first.manifest.transaction_formats);
        assert_eq!(next.predecessor, first.manifest.id()?);
        #[cfg(all(kontor_managed, feature = "protocol-qualification"))]
        {
            assert_eq!(registry::resolve(&next)?.executor, ExecutorVersion::P2);
            let mut changed = next.clone();
            changed.native_contracts_root = first.manifest.native_contracts_root;
            assert!(registry::resolve(&changed).is_err());
            changed = next.clone();
            changed.migration = first.manifest.migration;
            assert!(registry::resolve(&changed).is_err());
            changed = next.clone();
            changed.consensus[0] ^= 1;
            assert!(registry::resolve(&changed).is_err());
            assert_ne!(manifest(ChainId([8; 32]))?.id()?, next.id()?);
        }
        #[cfg(not(all(kontor_managed, feature = "protocol-qualification")))]
        assert!(
            registry::resolve(&next).is_err(),
            "normal nodes must not install the qualification successor"
        );
        Ok(())
    }
}
