use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};

use super::certified_decision::{AuthorityMember, CommitteeRecord};
use super::certified_input::EraContext;
use crate::consensus::{Address, signing::PublicKey};
use crate::protocol::canonical_codec::{Decoder, Encoder};
use crate::protocol::committee::Committee;
use crate::protocol::identity::domain_digest;
use crate::protocol::registration::{Registration, RegistrationObservation};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObservationPosition {
    pub(crate) context: EraContext,
    pub(crate) height: u64,
    pub(crate) decision: [u8; 32],
    pub(crate) stage: u64,
    pub(crate) lineage: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservedRegistration {
    pub(crate) holder: String,
    pub(crate) value: Option<Registration>,
    pub(crate) generation: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegistrationSnapshot {
    pub(crate) position: ObservationPosition,
    pub(crate) parent: Option<[u8; 32]>,
    pub(crate) committee: Committee,
    pub(crate) entries: Vec<ObservedRegistration>,
}

fn active(value: &Registration) -> bool {
    matches!(value.1, 1 | 3)
}

fn encode_position(output: &mut Encoder, position: ObservationPosition) -> Result<()> {
    position.context.encode(output)?;
    output.u64(position.height)?;
    output.fixed(&position.decision)?;
    output.u64(position.stage)?;
    output.fixed(&position.lineage)?;
    Ok(())
}

fn encode_registration(output: &mut Encoder, value: &Option<Registration>) -> Result<()> {
    match value {
        None => output.tag(0)?,
        Some((key, status, activation, deactivation)) => {
            output.tag(1)?;
            output.bytes(key)?;
            output.tag(*status)?;
            output.u64(*activation)?;
            output.u64(*deactivation)?;
        }
    }
    Ok(())
}

fn encode_digest(output: &mut Encoder, digest: Option<[u8; 32]>) -> Result<()> {
    match digest {
        None => output.tag(0)?,
        Some(digest) => {
            output.tag(1)?;
            output.fixed(&digest)?;
        }
    }
    Ok(())
}

fn decode_digest(input: &mut Decoder<'_>) -> Result<Option<[u8; 32]>> {
    match input.tag()? {
        0 => Ok(None),
        1 => Ok(Some(input.fixed()?)),
        _ => anyhow::bail!("invalid optional registration digest"),
    }
}

impl RegistrationSnapshot {
    pub(crate) fn observe(
        previous: Option<&Self>,
        position: ObservationPosition,
        observation: RegistrationObservation,
    ) -> Result<Self> {
        ensure!(
            position.context.codec == 1,
            "unsupported observation context"
        );
        if let Some(previous) = previous {
            previous.validate()?;
            ensure!(
                previous.position.context.chain == position.context.chain,
                "registration observation changed chain"
            );
            let follows_stage = previous.position.height == position.height
                && previous.position.decision == position.decision
                && previous.position.context == position.context
                && previous.position.stage.checked_add(1) == Some(position.stage);
            let follows_decision = previous.position.height.checked_add(1) == Some(position.height)
                && position.stage == 1;
            ensure!(
                follows_stage || follows_decision,
                "registration observation position gap"
            );
        } else {
            ensure!(
                position.height == 0 && position.stage == 0,
                "first observation must be genesis"
            );
        }
        let prior: BTreeMap<_, _> = previous
            .into_iter()
            .flat_map(|value| &value.entries)
            .map(|entry| (entry.holder.as_str(), entry))
            .collect();
        let (committee, observed) = observation;
        let mut entries = Vec::new();
        let mut last = None;
        let mut remaining: BTreeSet<_> = prior.keys().copied().collect();
        for (holder, value) in observed {
            ensure!(
                !holder.is_empty() && last.as_ref().is_none_or(|last| last < &holder),
                "registration holders must be strictly ordered"
            );
            last = Some(holder.clone());
            remaining.remove(holder.as_str());
            let generation = if let Some(current) = value.as_ref().filter(|value| active(value)) {
                let retained = prior.get(holder.as_str()).filter(|old| {
                    old.value.as_ref().is_some_and(|value| {
                        active(value) && value.0 == current.0 && value.2 == current.2
                    })
                });
                if let Some(old) = retained {
                    old.generation
                } else {
                    let mut encoded = Encoder::default();
                    encode_position(&mut encoded, position)?;
                    encoded.bytes(holder.as_bytes())?;
                    encode_registration(&mut encoded, &value)?;
                    Some(domain_digest(
                        b"kontor/registration-generation/v1",
                        &encoded.finish(),
                    ))
                }
            } else {
                None
            };
            entries.push(ObservedRegistration {
                holder,
                value,
                generation,
            });
        }
        ensure!(
            remaining.is_empty(),
            "observation omitted previously watched holders"
        );
        let snapshot = Self {
            position,
            parent: previous.map(Self::id).transpose()?,
            committee,
            entries,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.position.context.codec == 1,
            "unsupported observation context"
        );
        ensure!(
            self.entries
                .windows(2)
                .all(|pair| pair[0].holder < pair[1].holder),
            "registration holders must be strictly ordered"
        );
        let mut active_keys = BTreeMap::new();
        for entry in &self.entries {
            ensure!(!entry.holder.is_empty(), "empty registration holder");
            let is_active = entry.value.as_ref().is_some_and(active);
            ensure!(
                entry.generation.is_some() == is_active,
                "invalid registration generation presence"
            );
            if let Some((key, status, _, _)) = &entry.value {
                ensure!(*status <= 3, "invalid registration status");
                // An inactive, stake-only account legitimately has no validator key.
                ensure!(
                    key.len() == 32 || (*status == 0 && key.is_empty()),
                    "invalid registration key length"
                );
                if is_active {
                    ensure!(
                        active_keys.insert(key.as_slice(), entry).is_none(),
                        "duplicate active registration key"
                    );
                }
            }
        }
        let mut total = 0u64;
        for (address, key, power) in &self.committee {
            ensure!(
                active_keys.remove(key.as_slice()).is_some(),
                "committee lacks unique active registration"
            );
            let public = PublicKey::from_bytes(*key)?;
            ensure!(
                Address::from_public_key(&public).into_inner() == *address && *power > 0,
                "invalid registration committee bridge"
            );
            total = total
                .checked_add(*power)
                .filter(|total| *total <= u64::MAX / 3)
                .context("registration committee power overflow")?;
        }
        ensure!(
            active_keys.is_empty(),
            "active registration omitted from committee"
        );
        Ok(())
    }

    pub(crate) fn authority(&self) -> Result<CommitteeRecord> {
        self.validate()?;
        let by_key: BTreeMap<_, _> = self
            .entries
            .iter()
            .filter_map(|entry| {
                entry
                    .value
                    .as_ref()
                    .filter(|value| active(value))
                    .map(|value| (value.0.as_slice(), entry))
            })
            .collect();
        let mut members = Vec::new();
        for (address, key, power) in &self.committee {
            let entry = by_key
                .get(key.as_slice())
                .context("missing active registration")?;
            members.push(AuthorityMember {
                holder: entry.holder.clone(),
                generation: entry
                    .generation
                    .context("missing registration generation")?,
                address: *address,
                key: *key,
                power: *power,
            });
        }
        let record = CommitteeRecord {
            context: self.position.context,
            height: self
                .position
                .height
                .checked_add(1)
                .context("committee height overflow")?,
            decision: self.position.decision,
            stage: self.position.stage,
            lineage: self.position.lineage,
            members,
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut output = Encoder::default();
        output.fixed(b"KRO1")?;
        encode_position(&mut output, self.position)?;
        encode_digest(&mut output, self.parent)?;
        output.count(self.committee.len())?;
        for (address, key, power) in &self.committee {
            output.fixed(address)?;
            output.fixed(key)?;
            output.u64(*power)?;
        }
        output.count(self.entries.len())?;
        for entry in &self.entries {
            output.bytes(entry.holder.as_bytes())?;
            encode_registration(&mut output, &entry.value)?;
            encode_digest(&mut output, entry.generation)?;
        }
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KRO1",
            "unknown registration encoding"
        );
        let position = ObservationPosition {
            context: EraContext::decode(&mut input)?,
            height: input.u64()?,
            decision: input.fixed()?,
            stage: input.u64()?,
            lineage: input.fixed()?,
        };
        let parent = decode_digest(&mut input)?;
        let count = input.count(60)?;
        let mut committee = Vec::new();
        for _ in 0..count {
            committee.push((input.fixed()?, input.fixed()?, input.u64()?));
        }
        let count = input.count(6)?;
        let mut entries = Vec::new();
        for _ in 0..count {
            let holder = input.owned_string()?;
            let value = match input.tag()? {
                0 => None,
                1 => Some((
                    input.bytes()?.to_vec(),
                    input.tag()?,
                    input.u64()?,
                    input.u64()?,
                )),
                _ => anyhow::bail!("invalid registration option"),
            };
            entries.push(ObservedRegistration {
                holder,
                value,
                generation: decode_digest(&mut input)?,
            });
        }
        input.finish()?;
        let snapshot = Self {
            position,
            parent,
            committee,
            entries,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) fn id(&self) -> Result<[u8; 32]> {
        Ok(domain_digest(
            b"kontor/registration-observation/v1",
            &self.encode()?,
        ))
    }

    pub(crate) fn verify_successor(&self, previous: Option<&Self>) -> Result<()> {
        let observed = self
            .entries
            .iter()
            .map(|entry| (entry.holder.clone(), entry.value.clone()))
            .collect();
        ensure!(
            Self::observe(previous, self.position, (self.committee.clone(), observed))? == *self,
            "registration generation or predecessor differs"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
