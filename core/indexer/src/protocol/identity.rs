use sha2::{Digest, Sha256};

use super::canonical_codec::{CodecError, Decoder, Encoder, strictly_ordered};
use super::migration_work::MigrationWork;

macro_rules! digest_ids {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) struct $name(pub(crate) [u8; 32]);
    )+};
}

digest_ids!(
    ChainId,
    ExecutionDefinitionId,
    MigrationDefinitionId,
    ProtocolId,
    PlanId
);

pub(crate) fn domain_digest(domain: &'static [u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(bytes);
    hash.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceDigest {
    pub(crate) path: String,
    pub(crate) digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DefinitionReference {
    pub(crate) sources: Vec<SourceDigest>,
    pub(crate) locks: Vec<SourceDigest>,
    pub(crate) features: Vec<String>,
    pub(crate) build_policy: [u8; 32],
}

impl DefinitionReference {
    fn validate(&self) -> Result<(), CodecError> {
        for entries in [&self.sources, &self.locks] {
            if entries.is_empty() {
                return Err(CodecError::InvalidValue);
            }
            if entries.windows(2).any(|pair| pair[0].path >= pair[1].path) {
                return Err(CodecError::UnorderedSet);
            }
            for entry in entries {
                if entry.path.contains(['\\', '\0'])
                    || entry
                        .path
                        .split('/')
                        .any(|part| matches!(part, "" | "." | ".."))
                {
                    return Err(CodecError::InvalidValue);
                }
            }
        }
        strictly_ordered(&self.features)?;
        if self.features.iter().any(String::is_empty) {
            return Err(CodecError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut output = Encoder::default();
        output.tag(1)?;
        for entries in [&self.sources, &self.locks] {
            output.count(entries.len())?;
            for entry in entries {
                output.bytes(entry.path.as_bytes())?;
                output.fixed(&entry.digest)?;
            }
        }
        output.count(self.features.len())?;
        for feature in &self.features {
            output.bytes(feature.as_bytes())?;
        }
        output.fixed(&self.build_policy)?;
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::new(bytes);
        input.expect_tag(1)?;
        let sources = decode_sources(&mut input)?;
        let locks = decode_sources(&mut input)?;
        let count = input.count(4)?;
        let mut features = Vec::new();
        features
            .try_reserve(count)
            .map_err(|_| CodecError::Allocation)?;
        for _ in 0..count {
            features.push(input.owned_string()?);
        }
        let value = Self {
            sources,
            locks,
            features,
            build_policy: input.fixed()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn id(&self) -> Result<ExecutionDefinitionId, CodecError> {
        Ok(ExecutionDefinitionId(domain_digest(
            b"kontor/execution-definition/v1",
            &self.encode()?,
        )))
    }
}

fn decode_sources(input: &mut Decoder<'_>) -> Result<Vec<SourceDigest>, CodecError> {
    let count = input.count(36)?;
    let mut entries = Vec::new();
    entries
        .try_reserve(count)
        .map_err(|_| CodecError::Allocation)?;
    for _ in 0..count {
        entries.push(SourceDigest {
            path: input.owned_string()?,
            digest: input.fixed()?,
        });
    }
    Ok(entries)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutionIdentity {
    Baseline(ExecutionDefinitionId),
    Protocol {
        protocol: ProtocolId,
        execution: ExecutionDefinitionId,
    },
}

impl ExecutionIdentity {
    pub(crate) fn encode(self, output: &mut Encoder) -> Result<(), CodecError> {
        match self {
            Self::Baseline(execution) => {
                output.tag(0)?;
                output.fixed(&execution.0)
            }
            Self::Protocol {
                protocol,
                execution,
            } => {
                output.tag(1)?;
                output.fixed(&protocol.0)?;
                output.fixed(&execution.0)
            }
        }
    }

    pub(crate) fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        match input.tag()? {
            0 => Ok(Self::Baseline(ExecutionDefinitionId(input.fixed()?))),
            1 => Ok(Self::Protocol {
                protocol: ProtocolId(input.fixed()?),
                execution: ExecutionDefinitionId(input.fixed()?),
            }),
            _ => Err(CodecError::InvalidTag),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MigrationDefinition {
    pub(crate) execution: ExecutionDefinitionId,
    pub(crate) routine: String,
    pub(crate) input_schema: [u8; 32],
    pub(crate) output_schema: [u8; 32],
    pub(crate) accounting_version: u32,
    pub(crate) budget: MigrationWork,
}

impl MigrationDefinition {
    fn validate(&self) -> Result<(), CodecError> {
        if self.accounting_version != 1 {
            return Err(CodecError::InvalidTag);
        }
        if self.routine.is_empty() {
            return Err(CodecError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut output = Encoder::default();
        output.tag(1)?;
        output.fixed(&self.execution.0)?;
        output.bytes(self.routine.as_bytes())?;
        output.fixed(&self.input_schema)?;
        output.fixed(&self.output_schema)?;
        output.fixed(&self.accounting_version.to_be_bytes())?;
        self.budget.encode(&mut output)?;
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::new(bytes);
        input.expect_tag(1)?;
        let value = Self {
            execution: ExecutionDefinitionId(input.fixed()?),
            routine: input.owned_string()?,
            input_schema: input.fixed()?,
            output_schema: input.fixed()?,
            accounting_version: u32::from_be_bytes(input.fixed()?),
            budget: MigrationWork::decode(&mut input)?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn id(&self) -> Result<MigrationDefinitionId, CodecError> {
        Ok(MigrationDefinitionId(domain_digest(
            b"kontor/migration-definition/v1",
            &self.encode()?,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DefinitionReference, ExecutionDefinitionId, ExecutionIdentity, MigrationDefinition,
        ProtocolId, SourceDigest,
    };
    use crate::protocol::canonical_codec::{CodecError, Decoder, Encoder};
    use crate::protocol::migration_work::MigrationWork;

    fn reference() -> DefinitionReference {
        DefinitionReference {
            sources: vec![SourceDigest {
                path: "core/main.rs".into(),
                digest: [0x11; 32],
            }],
            locks: vec![SourceDigest {
                path: "core/Cargo.lock".into(),
                digest: [0x22; 32],
            }],
            features: vec!["a".into(), "b".into()],
            build_policy: [0x33; 32],
        }
    }

    #[test]
    fn definition_roundtrip_and_input_binding() {
        let value = reference();
        assert_eq!(
            DefinitionReference::decode(&value.encode().unwrap()).unwrap(),
            value
        );
        let baseline = value.id().unwrap();
        assert_eq!(
            baseline.0,
            [
                4, 43, 15, 7, 21, 98, 17, 64, 164, 68, 55, 216, 226, 220, 98, 220, 116, 174, 114,
                204, 139, 165, 230, 138, 253, 210, 99, 233, 140, 112, 245, 146
            ]
        );
        let mut changed = value.clone();
        changed.sources[0].digest[0] ^= 1;
        assert_ne!(changed.id().unwrap(), baseline);
        changed = value.clone();
        changed.features.push("c".into());
        assert_ne!(changed.id().unwrap(), baseline);
        changed = value.clone();
        changed.locks[0].digest[0] ^= 1;
        assert_ne!(changed.id().unwrap(), baseline);
        changed = value;
        changed.build_policy[0] ^= 1;
        assert_ne!(changed.id().unwrap(), baseline);
    }

    #[test]
    fn duplicate_paths_features_and_noncanonical_paths_are_rejected() {
        let mut value = reference();
        let mut duplicate = value.sources[0].clone();
        duplicate.digest = [0xff; 32];
        value.sources.push(duplicate);
        assert_eq!(value.encode(), Err(CodecError::UnorderedSet));
        for path in ["/absolute", "a/../b", "a//b", "a/./b", "a\\b", ""] {
            let mut value = reference();
            value.sources[0].path = path.into();
            assert_eq!(value.encode(), Err(CodecError::InvalidValue));
        }
        for features in [vec!["b".into(), "a".into()], vec!["a".into(), "a".into()]] {
            let mut value = reference();
            value.features = features;
            assert_eq!(value.encode(), Err(CodecError::UnorderedSet));
        }
    }

    #[test]
    fn baseline_and_manifest_bound_identity_cannot_alias() {
        let baseline = ExecutionIdentity::Baseline(ExecutionDefinitionId([1; 32]));
        let protocol = ExecutionIdentity::Protocol {
            protocol: ProtocolId([1; 32]),
            execution: ExecutionDefinitionId([1; 32]),
        };
        let mut encodings = Vec::new();
        for value in [baseline, protocol] {
            let mut output = Encoder::default();
            value.encode(&mut output).unwrap();
            let bytes = output.finish();
            let mut input = Decoder::new(&bytes);
            assert_eq!(ExecutionIdentity::decode(&mut input), Ok(value));
            input.finish().unwrap();
            encodings.push(bytes);
        }
        assert_ne!(encodings[0], encodings[1]);
        assert_eq!(
            ExecutionIdentity::decode(&mut Decoder::new(&[2])),
            Err(CodecError::InvalidTag)
        );
    }

    #[test]
    fn migration_definition_binds_budget_and_rejects_unknown_versions() {
        let value = MigrationDefinition {
            execution: reference().id().unwrap(),
            routine: "noop".into(),
            input_schema: [1; 32],
            output_schema: [2; 32],
            accounting_version: 1,
            budget: MigrationWork::default(),
        };
        assert_eq!(
            MigrationDefinition::decode(&value.encode().unwrap()).unwrap(),
            value
        );
        let id = value.id().unwrap();
        assert_eq!(
            id.0,
            [
                27, 163, 243, 57, 37, 155, 219, 1, 181, 208, 145, 63, 40, 242, 231, 183, 96, 169,
                223, 207, 68, 169, 170, 34, 27, 48, 211, 200, 188, 248, 34, 141
            ]
        );
        let mut changed = value.clone();
        changed.budget.read_bytes = 1;
        assert_ne!(changed.id().unwrap(), id);
        changed.accounting_version = 2;
        assert_eq!(changed.encode(), Err(CodecError::InvalidTag));
        let bytes = value.encode().unwrap();
        for end in 0..bytes.len() {
            assert!(MigrationDefinition::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            MigrationDefinition::decode(&trailing),
            Err(CodecError::TrailingBytes)
        );
    }
}
