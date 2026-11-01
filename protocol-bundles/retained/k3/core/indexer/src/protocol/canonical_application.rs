use bitcoin::{Transaction, hashes::Hash};

use super::canonical_codec::{CodecError, Decoder, Encoder, strictly_ordered};
use super::canonical_input::CanonicalInput;
use super::identity::{ChainId, ExecutionIdentity, MigrationDefinitionId, PlanId, domain_digest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecisionExclusions {
    pub(crate) consensus_height: u64,
    pub(crate) direct: Vec<[u8; 32]>,
    pub(crate) effective: Vec<[u8; 32]>,
}

impl DecisionExclusions {
    pub(crate) fn for_batch(
        consensus_height: u64,
        decided: &[Transaction],
        executed: &[Transaction],
        applicable: &[[u8; 32]],
    ) -> Result<Self, CodecError> {
        strictly_ordered(applicable)?;
        let mut remaining = executed.iter().peekable();
        let mut direct = Vec::new();
        let mut effective = Vec::new();
        for transaction in decided {
            let txid = transaction.compute_txid().to_byte_array();
            let excluded = applicable.binary_search(&txid).is_ok();
            if remaining.peek().is_some_and(|next| *next == transaction) {
                if excluded {
                    return Err(CodecError::InvalidValue);
                }
                remaining.next();
            } else {
                effective.push(txid);
                if excluded {
                    direct.push(txid);
                }
            }
        }
        if remaining.next().is_some() {
            return Err(CodecError::InvalidValue);
        }
        for entries in [&mut direct, &mut effective] {
            entries.sort_unstable();
            entries.dedup();
        }
        Ok(Self {
            consensus_height,
            direct,
            effective,
        })
    }

    fn validate(&self) -> Result<(), CodecError> {
        strictly_ordered(&self.direct)?;
        strictly_ordered(&self.effective)?;
        if self
            .direct
            .iter()
            .any(|id| self.effective.binary_search(id).is_err())
        {
            return Err(CodecError::InvalidValue);
        }
        Ok(())
    }

    fn encode(&self, output: &mut Encoder) -> Result<(), CodecError> {
        self.validate()?;
        output.u64(self.consensus_height)?;
        for entries in [&self.direct, &self.effective] {
            output.count(entries.len())?;
            for entry in entries {
                output.fixed(entry)?;
            }
        }
        Ok(())
    }

    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let value = Self {
            consensus_height: input.u64()?,
            direct: decode_digests(input)?,
            effective: decode_digests(input)?,
        };
        value.validate()?;
        Ok(value)
    }

    #[cfg(test)]
    pub(crate) fn digest(&self) -> Result<[u8; 32], CodecError> {
        let mut output = Encoder::default();
        output.tag(1)?;
        self.encode(&mut output)?;
        Ok(domain_digest(
            b"kontor/canonical-exclusions/v1",
            &output.finish(),
        ))
    }
}

fn decode_digests(input: &mut Decoder<'_>) -> Result<Vec<[u8; 32]>, CodecError> {
    let count = input.count(32)?;
    let mut entries = Vec::new();
    entries
        .try_reserve(count)
        .map_err(|_| CodecError::Allocation)?;
    for _ in 0..count {
        entries.push(input.fixed()?);
    }
    Ok(entries)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApplicationSource {
    Genesis {
        stage: u32,
    },
    BlockTransactions {
        height: u64,
        hash: [u8; 32],
        parent_hash: [u8; 32],
    },
    BlockLifecycle {
        height: u64,
        hash: [u8; 32],
    },
    Batch {
        anchor_height: u64,
        anchor_hash: [u8; 32],
        exclusions: DecisionExclusions,
    },
    Migration {
        anchor_height: u64,
        anchor_hash: [u8; 32],
        plan: PlanId,
        definition: MigrationDefinitionId,
        checkpoint: Option<[u8; 32]>,
    },
}

impl ApplicationSource {
    fn encode(&self, output: &mut Encoder) -> Result<(), CodecError> {
        match self {
            Self::Genesis { stage } => {
                output.tag(0)?;
                output.fixed(&stage.to_be_bytes())
            }
            Self::BlockTransactions {
                height,
                hash,
                parent_hash,
            } => {
                output.tag(1)?;
                output.u64(*height)?;
                output.fixed(hash)?;
                output.fixed(parent_hash)
            }
            Self::BlockLifecycle { height, hash } => {
                output.tag(2)?;
                output.u64(*height)?;
                output.fixed(hash)
            }
            Self::Batch {
                anchor_height,
                anchor_hash,
                exclusions,
            } => {
                output.tag(3)?;
                output.u64(*anchor_height)?;
                output.fixed(anchor_hash)?;
                exclusions.encode(output)
            }
            Self::Migration {
                anchor_height,
                anchor_hash,
                plan,
                definition,
                checkpoint,
            } => {
                output.tag(4)?;
                output.u64(*anchor_height)?;
                output.fixed(anchor_hash)?;
                output.fixed(&plan.0)?;
                output.fixed(&definition.0)?;
                match checkpoint {
                    None => output.tag(0),
                    Some(value) => {
                        output.tag(1)?;
                        output.fixed(value)
                    }
                }
            }
        }
    }

    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(match input.tag()? {
            0 => Self::Genesis {
                stage: u32::from_be_bytes(input.fixed()?),
            },
            1 => Self::BlockTransactions {
                height: input.u64()?,
                hash: input.fixed()?,
                parent_hash: input.fixed()?,
            },
            2 => Self::BlockLifecycle {
                height: input.u64()?,
                hash: input.fixed()?,
            },
            3 => Self::Batch {
                anchor_height: input.u64()?,
                anchor_hash: input.fixed()?,
                exclusions: DecisionExclusions::decode(input)?,
            },
            4 => Self::Migration {
                anchor_height: input.u64()?,
                anchor_hash: input.fixed()?,
                plan: PlanId(input.fixed()?),
                definition: MigrationDefinitionId(input.fixed()?),
                checkpoint: match input.tag()? {
                    0 => None,
                    1 => Some(input.fixed()?),
                    _ => return Err(CodecError::InvalidTag),
                },
            },
            _ => return Err(CodecError::InvalidTag),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalApplication {
    pub(crate) chain: ChainId,
    pub(crate) ordinal: u64,
    pub(crate) parent_lineage: [u8; 32],
    pub(crate) execution: ExecutionIdentity,
    pub(crate) storage_height: u64,
    pub(crate) source: ApplicationSource,
    pub(crate) input: Option<CanonicalInput>,
}

impl CanonicalApplication {
    fn validate(&self) -> Result<(), CodecError> {
        if self.ordinal == 0 {
            return Err(CodecError::InvalidValue);
        }
        let needs_input = matches!(
            self.source,
            ApplicationSource::BlockTransactions { .. } | ApplicationSource::Batch { .. }
        );
        if self.input.is_some() != needs_input {
            return Err(CodecError::InvalidValue);
        }
        let height = match self.source {
            ApplicationSource::Genesis { .. } => self.storage_height,
            ApplicationSource::BlockTransactions { height, .. }
            | ApplicationSource::BlockLifecycle { height, .. } => height,
            ApplicationSource::Batch { anchor_height, .. }
            | ApplicationSource::Migration { anchor_height, .. } => anchor_height,
        };
        if self.storage_height != height {
            return Err(CodecError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut output = Encoder::default();
        output.tag(1)?;
        output.fixed(&self.chain.0)?;
        output.u64(self.ordinal)?;
        output.fixed(&self.parent_lineage)?;
        self.execution.encode(&mut output)?;
        output.u64(self.storage_height)?;
        self.source.encode(&mut output)?;
        match self.input {
            None => output.tag(0)?,
            Some(value) => {
                output.tag(1)?;
                value.encode(&mut output)?;
            }
        }
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::new(bytes);
        input.expect_tag(1)?;
        let value = Self {
            chain: ChainId(input.fixed()?),
            ordinal: input.u64()?,
            parent_lineage: input.fixed()?,
            execution: ExecutionIdentity::decode(&mut input)?,
            storage_height: input.u64()?,
            source: ApplicationSource::decode(&mut input)?,
            input: match input.tag()? {
                0 => None,
                1 => Some(CanonicalInput::decode(&mut input)?),
                _ => return Err(CodecError::InvalidTag),
            },
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn lineage(&self) -> Result<[u8; 32], CodecError> {
        Ok(domain_digest(
            b"kontor/canonical-application/v1",
            &self.encode()?,
        ))
    }

    pub(crate) fn migration_key(&self) -> Result<[u8; 32], CodecError> {
        let ApplicationSource::Migration {
            anchor_height,
            anchor_hash,
            plan,
            definition,
            checkpoint,
        } = &self.source
        else {
            return Err(CodecError::InvalidValue);
        };
        self.validate()?;
        let mut output = Encoder::default();
        output.tag(1)?;
        output.fixed(&self.chain.0)?;
        output.fixed(&plan.0)?;
        output.u64(*anchor_height)?;
        output.fixed(anchor_hash)?;
        output.fixed(&self.parent_lineage)?;
        match checkpoint {
            None => output.tag(0)?,
            Some(value) => {
                output.tag(1)?;
                output.fixed(value)?;
            }
        }
        output.fixed(&definition.0)?;
        Ok(domain_digest(
            b"kontor/migration-application/v1",
            &output.finish(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{ApplicationSource, CanonicalApplication, DecisionExclusions};
    use crate::protocol::canonical_codec::CodecError;
    use crate::protocol::canonical_input::CanonicalInput;
    use crate::protocol::identity::{
        ChainId, ExecutionDefinitionId, ExecutionIdentity, MigrationDefinitionId, PlanId,
    };
    use bitcoin::{
        Transaction, TxIn, Witness, absolute::LockTime, hashes::Hash, transaction::Version,
    };

    fn exclusions() -> DecisionExclusions {
        DecisionExclusions {
            consensus_height: 11,
            direct: vec![[1; 32]],
            effective: vec![[1; 32], [2; 32]],
        }
    }

    fn application() -> CanonicalApplication {
        CanonicalApplication {
            chain: ChainId([1; 32]),
            ordinal: 3,
            parent_lineage: [2; 32],
            execution: ExecutionIdentity::Baseline(ExecutionDefinitionId([3; 32])),
            storage_height: 7,
            source: ApplicationSource::Batch {
                anchor_height: 7,
                anchor_hash: [4; 32],
                exclusions: exclusions(),
            },
            input: Some(CanonicalInput::Bitcoin([9; 32])),
        }
    }

    fn migration() -> CanonicalApplication {
        CanonicalApplication {
            source: ApplicationSource::Migration {
                anchor_height: 7,
                anchor_hash: [4; 32],
                plan: PlanId([5; 32]),
                definition: MigrationDefinitionId([7; 32]),
                checkpoint: Some([6; 32]),
            },
            input: None,
            ..application()
        }
    }

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn batch_exclusions_bind_effective_descendants_without_unrelated_records() {
        let first = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        };
        let mut second = first.clone();
        second.lock_time = LockTime::from_height(1).unwrap();
        let first_id = first.compute_txid().to_byte_array();
        let second_id = second.compute_txid().to_byte_array();
        let decided = [first.clone(), second.clone()];
        let result = DecisionExclusions::for_batch(10, &decided, &[], &[first_id]).unwrap();
        assert_eq!(result.direct, vec![first_id]);
        assert!(result.effective.contains(&second_id));
        let mut with_unrelated = vec![first_id, [99; 32]];
        with_unrelated.sort_unstable();
        assert_eq!(
            DecisionExclusions::for_batch(10, &decided, &[], &with_unrelated).unwrap(),
            result
        );
        assert!(
            DecisionExclusions::for_batch(10, &decided, &[second.clone(), first.clone()], &[])
                .is_err()
        );
        assert!(DecisionExclusions::for_batch(10, &decided, &decided, &[first_id]).is_err());
        let mut changed_witness = second;
        changed_witness.input[0].witness = Witness::from_slice(&[b"changed"]);
        assert!(
            DecisionExclusions::for_batch(10, &decided, &[first, changed_witness], &[]).is_err()
        );
        let empty = DecisionExclusions::for_batch(10, &[], &[], &[]).unwrap();
        assert!(empty.effective.is_empty());
        assert_ne!(empty.digest().unwrap(), result.digest().unwrap());
    }

    #[test]
    fn application_exclusions_and_migration_golden_vectors() {
        assert_eq!(application().encode().unwrap().len(), 301);
        assert_eq!(
            hex(application().lineage().unwrap()),
            "deb8ce8ee8ed7ebb6d98855b41155bf851501770714039443066cd81e1012abb"
        );
        assert_eq!(
            hex(exclusions().digest().unwrap()),
            "24dc257116fd9748a8cfbaab74a93d2654536f713401c970d7f65b27183afdb0"
        );
        assert_eq!(
            hex(migration().migration_key().unwrap()),
            "745e0c3537066720e9ed9343c5f8205c552b26bbf83872358b2b07b23e9feae8"
        );
    }

    #[test]
    fn every_application_phase_roundtrips_and_rejects_truncation() {
        let mut values = vec![application(), migration()];
        for source in [
            ApplicationSource::Genesis { stage: 0 },
            ApplicationSource::BlockTransactions {
                height: 7,
                hash: [4; 32],
                parent_hash: [8; 32],
            },
            ApplicationSource::BlockLifecycle {
                height: 7,
                hash: [4; 32],
            },
        ] {
            let input = matches!(source, ApplicationSource::BlockTransactions { .. })
                .then_some(CanonicalInput::Bitcoin([9; 32]));
            values.push(CanonicalApplication {
                source,
                input,
                ..application()
            });
        }
        for value in values {
            let bytes = value.encode().unwrap();
            assert_eq!(CanonicalApplication::decode(&bytes), Ok(value));
            for end in 0..bytes.len() {
                assert!(CanonicalApplication::decode(&bytes[..end]).is_err());
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert_eq!(
                CanonicalApplication::decode(&trailing),
                Err(CodecError::TrailingBytes)
            );
            trailing[0] = 2;
            assert_eq!(
                CanonicalApplication::decode(&trailing),
                Err(CodecError::InvalidTag)
            );
        }
    }

    #[test]
    fn identity_binds_order_input_branch_and_scoped_exclusions() {
        let original = application();
        let baseline = original.lineage().unwrap();
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.parent_lineage = [42; 32];
        variants.push(changed);
        let mut changed = original.clone();
        changed.ordinal += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.input = Some(CanonicalInput::Bitcoin([42; 32]));
        variants.push(changed);
        for (height, hash, effective) in [
            (12, [4; 32], vec![[1; 32], [2; 32]]),
            (11, [42; 32], vec![[1; 32], [2; 32]]),
            (11, [4; 32], vec![[1; 32]]),
        ] {
            let mut changed = original.clone();
            changed.source = ApplicationSource::Batch {
                anchor_height: 7,
                anchor_hash: hash,
                exclusions: DecisionExclusions {
                    consensus_height: height,
                    effective,
                    ..exclusions()
                },
            };
            variants.push(changed);
        }
        for changed in variants {
            assert_ne!(changed.lineage().unwrap(), baseline);
        }
    }

    #[test]
    fn malformed_sets_and_inconsistent_positions_are_rejected() {
        for effective in [
            vec![[2; 32]],
            vec![[2; 32], [1; 32]],
            vec![[1; 32], [1; 32]],
        ] {
            assert!(
                DecisionExclusions {
                    effective,
                    ..exclusions()
                }
                .digest()
                .is_err()
            );
        }
        let original = application();
        for changed in [
            CanonicalApplication {
                ordinal: 0,
                ..original.clone()
            },
            CanonicalApplication {
                storage_height: 8,
                ..original.clone()
            },
            CanonicalApplication {
                input: None,
                ..original
            },
            CanonicalApplication {
                input: Some(CanonicalInput::Bitcoin([9; 32])),
                ..migration()
            },
        ] {
            assert_eq!(changed.encode(), Err(CodecError::InvalidValue));
        }
        assert_eq!(application().migration_key(), Err(CodecError::InvalidValue));
    }

    #[test]
    fn migration_retry_key_requires_the_same_prestate_and_context() {
        let original = migration();
        let key = original.migration_key().unwrap();
        let mut changed = original.clone();
        changed.parent_lineage = [99; 32];
        assert_ne!(changed.migration_key().unwrap(), key);
        changed = original.clone();
        changed.chain = ChainId([99; 32]);
        assert_ne!(changed.migration_key().unwrap(), key);
        for (plan, definition, checkpoint, hash) in [
            ([99; 32], [7; 32], Some([6; 32]), [4; 32]),
            ([5; 32], [99; 32], Some([6; 32]), [4; 32]),
            ([5; 32], [7; 32], None, [4; 32]),
            ([5; 32], [7; 32], Some([6; 32]), [99; 32]),
        ] {
            changed = original.clone();
            changed.source = ApplicationSource::Migration {
                anchor_height: 7,
                anchor_hash: hash,
                plan: PlanId(plan),
                definition: MigrationDefinitionId(definition),
                checkpoint,
            };
            assert_ne!(changed.migration_key().unwrap(), key);
        }
    }
}
