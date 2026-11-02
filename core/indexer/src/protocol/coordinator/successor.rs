use anyhow::{Result, ensure};

use super::baseline::{Baseline, source};
use super::manifest::ProtocolManifest;
use crate::protocol::canonical_codec::Encoder;
use crate::protocol::identity::{ChainId, DefinitionReference, domain_digest};
use crate::protocol::v1::native::TOKEN_CONTRACT_ID;
use crate::protocol::v2::migration_definition;

pub(crate) const EXECUTOR_REFERENCE: &[u8] =
    include_bytes!("../../../../../protocol-bundles/executor-observer/definition.bin");
const CONSENSUS_REFERENCE: &[u8] = include_bytes!("managed/definitions/second.json");
const TOKEN_ARTIFACT: &str = "core/indexer/src/protocol/v2/native/token.wasm.br";

pub(crate) fn consensus_definition() -> [u8; 32] {
    domain_digest(b"kontor/consensus-definition/v1", CONSENSUS_REFERENCE)
}

pub(crate) fn manifest(chain: ChainId) -> Result<ProtocolManifest> {
    let first = Baseline::for_node(chain)?;
    let reference = DefinitionReference::decode(EXECUTOR_REFERENCE)?;
    compose(&first, &reference)
}

fn compose(first: &Baseline, reference: &DefinitionReference) -> Result<ProtocolManifest> {
    let mut next =
        Baseline::compose_consensus(first.manifest.chain, reference, CONSENSUS_REFERENCE)?.manifest;
    ensure!(
        first.manifest.executor != next.executor,
        "P2 must use an independent executor"
    );
    ensure!(
        first.manifest.consensus != next.consensus,
        "P2 must use its own consensus definition"
    );
    let mut native = Encoder::default();
    native.fixed(&next.native_contracts_root)?;
    native.u64(TOKEN_CONTRACT_ID)?;
    native.fixed(&source(reference, TOKEN_ARTIFACT)?)?;
    next.native_contracts_root = domain_digest(b"kontor/native-replacements/v1", &native.finish());
    next.protocol_number = 2;
    next.predecessor = first.manifest.id()?;
    next.state_schema = 2;
    next.input_state_schema = 1;
    next.output_state_schema = 2;
    next.migration = migration_definition::token_count(next.executor).id()?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::coordinator::registry;
    #[cfg(kontor_managed)]
    use crate::protocol::execution::ExecutorVersion;

    #[test]
    fn p2_manifest_binds_distinct_graphs_native_mapping_and_exact_migration() -> Result<()> {
        let chain = ChainId([7; 32]);
        let retained = DefinitionReference::decode(include_bytes!(
            "../../../../../protocol-bundles/retained/p1/protocol-bundles/executor-first/definition.bin"
        ))?;
        let first = Baseline::compose_consensus(
            chain,
            &retained,
            include_bytes!("managed/definitions/first.json"),
        )?;
        let reference = DefinitionReference::decode(EXECUTOR_REFERENCE)?;
        let next = compose(&first, &reference)?;
        assert_ne!(next.executor, first.manifest.executor);
        assert_ne!(next.consensus, first.manifest.consensus);
        assert_ne!(
            next.native_contracts_root,
            first.manifest.native_contracts_root
        );
        assert_eq!(next.certificate_codec, first.manifest.certificate_codec);
        assert_eq!(next.transaction_formats, first.manifest.transaction_formats);
        assert_eq!(next.predecessor, first.manifest.id()?);
        #[cfg(kontor_managed)]
        {
            assert_eq!(registry::resolve(&next)?.executor, ExecutorVersion::P2);
            let mut changed = next.clone();
            changed.native_contracts_root = first.manifest.native_contracts_root;
            assert!(registry::resolve(&changed).is_err());
            changed = next.clone();
            changed.migration = first.manifest.migration;
            assert!(registry::resolve(&changed).is_err());
            assert_ne!(manifest(ChainId([8; 32]))?.id()?, next.id()?);
        }
        #[cfg(not(kontor_managed))]
        assert!(
            registry::resolve(&next).is_err(),
            "unmanaged node must not install P2"
        );
        Ok(())
    }
}
