use anyhow::{Context, Result, ensure};

use super::certified_input::{
    EraContext, MAX_BATCH_BYTES, MAX_BITCOIN_BYTES, MAX_DESCRIPTOR_BYTES,
};
use super::manifest::ProtocolManifest;
use super::v1::{FINALITY_ROLLBACK_DEPTH, FINALITY_WINDOW};
use crate::protocol::canonical_codec::Encoder;
use crate::protocol::identity::{ChainId, DefinitionReference, ProtocolId, domain_digest};
use crate::protocol::v1::definition::{REFERENCE, execution_definition};
use crate::protocol::v1::migration_definition;
use crate::protocol::v1::native::{NATIVE_GENESIS_ID, native_provenance};

const CONSENSUS_REFERENCE: &[u8] = include_bytes!("baseline/consensus.json");
const PARAMETERS: &[&str] = &[
    "core/indexer/src/protocol/v1/engine.rs",
    "core/indexer/src/protocol/v1/gas.rs",
    "core/indexer/src/protocol/v1/resources.rs",
    "core/indexer/src/protocol/v1/storage_bounds.rs",
    "core/indexer/src/protocol/v1/storage-contract.json",
];
const NATIVE_MANIFEST: &str = "core/indexer/src/protocol/v1/native/manifest.json";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Baseline {
    pub(crate) manifest: ProtocolManifest,
    pub(crate) context: EraContext,
}

impl Baseline {
    pub(crate) fn current(chain: ChainId) -> Result<Self> {
        native_provenance()?;
        let reference = DefinitionReference::decode(REFERENCE)?;
        ensure!(
            reference.id()? == execution_definition()?,
            "baseline executor reference differs"
        );
        Self::compose(chain, &reference)
    }

    fn compose(chain: ChainId, reference: &DefinitionReference) -> Result<Self> {
        let executor = reference.id()?;
        let mut native = [0; 32];
        hex::decode_to_slice(NATIVE_GENESIS_ID, &mut native)?;
        ensure!(
            source(reference, NATIVE_MANIFEST)? == native,
            "baseline native artifacts differ from selected executor"
        );
        let mut parameters = Encoder::default();
        parameters.fixed(b"KBP1")?;
        parameters.fixed(&chain.0)?;
        // The selected executor's source digests commit the actual numerical
        // limits, including historical values, without consulting node settings.
        parameters.count(PARAMETERS.len())?;
        for path in PARAMETERS {
            parameters.bytes(path.as_bytes())?;
            parameters.fixed(&source(reference, path)?)?;
        }
        for value in [
            FINALITY_WINDOW,
            FINALITY_ROLLBACK_DEPTH,
            MAX_BATCH_BYTES as u64,
            MAX_BITCOIN_BYTES as u64,
            MAX_DESCRIPTOR_BYTES as u64,
        ] {
            parameters.u64(value)?;
        }
        let migration = migration_definition::noop(executor);
        ensure!(
            migration.input_schema == migration.output_schema,
            "baseline no-op changes storage schema"
        );
        let manifest = ProtocolManifest {
            chain,
            protocol_number: 1,
            predecessor: ProtocolId([0; 32]),
            executor,
            consensus: domain_digest(b"kontor/consensus-definition/v1", CONSENSUS_REFERENCE),
            // ID 1 names the existing retained payload and synchronous host ABI.
            transaction_formats: vec![1],
            host_abis: vec![1],
            bridge_schema: 1,
            state_schema: 1,
            certificate_codec: 1,
            control_codec: 1,
            parameters_root: domain_digest(b"kontor/baseline-parameters/v1", &parameters.finish()),
            native_contracts_root: native,
            migration: migration.id()?,
            input_state_schema: 1,
            output_state_schema: 1,
        };
        let protocol = manifest.id()?;
        let mut era = Encoder::default();
        era.fixed(&chain.0)?;
        era.fixed(&protocol.0)?;
        let context = EraContext {
            chain,
            era: domain_digest(b"kontor/genesis-era/v1", &era.finish()),
            protocol,
            codec: 1,
        };
        Ok(Self { manifest, context })
    }

    pub(crate) fn require_context(&self, context: EraContext) -> Result<()> {
        ensure!(
            context == self.context,
            "unsupported baseline era/protocol context"
        );
        Ok(())
    }
}

fn source(reference: &DefinitionReference, path: &str) -> Result<[u8; 32]> {
    reference
        .sources
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.digest)
        .with_context(|| {
            format!("selected executor does not commit required baseline input: {path}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_binds_real_executor_native_artifacts_and_noop() -> Result<()> {
        let chain = ChainId([7; 32]);
        let baseline = Baseline::current(chain)?;
        assert_eq!(baseline.manifest.executor, execution_definition()?);
        assert_eq!(
            baseline.manifest.native_contracts_root,
            hex::decode(NATIVE_GENESIS_ID)?.as_slice()
        );
        assert_eq!(
            baseline.manifest.migration,
            migration_definition::noop(execution_definition()?).id()?
        );
        assert_eq!(baseline.context.protocol, baseline.manifest.id()?);
        assert_eq!(
            ProtocolManifest::decode(&baseline.manifest.encode()?)?,
            baseline.manifest
        );
        assert_eq!(Baseline::current(chain)?, baseline);
        baseline.require_context(baseline.context)?;
        let other = Baseline::current(ChainId([8; 32]))?;
        assert_ne!(baseline.context, other.context);
        assert!(baseline.require_context(other.context).is_err());
        Ok(())
    }

    #[test]
    fn baseline_parameters_follow_selected_source_and_missing_roots_fail() -> Result<()> {
        let chain = ChainId([7; 32]);
        let original = DefinitionReference::decode(REFERENCE)?;
        let baseline = Baseline::compose(chain, &original)?;
        let mut changed = original.clone();
        changed
            .sources
            .iter_mut()
            .find(|item| item.path == PARAMETERS[1])
            .unwrap()
            .digest[0] ^= 1;
        let changed = Baseline::compose(chain, &changed)?;
        assert_ne!(baseline.manifest.executor, changed.manifest.executor);
        assert_ne!(
            baseline.manifest.parameters_root,
            changed.manifest.parameters_root
        );
        assert_ne!(baseline.context.protocol, changed.context.protocol);
        let mut missing = original.clone();
        missing.sources.retain(|item| item.path != PARAMETERS[0]);
        assert!(Baseline::compose(chain, &missing).is_err());
        let mut changed_native = original;
        changed_native
            .sources
            .iter_mut()
            .find(|item| item.path == NATIVE_MANIFEST)
            .unwrap()
            .digest[0] ^= 1;
        assert!(Baseline::compose(chain, &changed_native).is_err());
        Ok(())
    }
}
