use anyhow::{Result, ensure};
use bitcoin::Transaction;

use super::closure_work::WorkOrigin;
use crate::protocol::canonical_application::DecisionExclusions;
use crate::protocol::canonical_codec::{Decoder, Encoder, strictly_ordered};
use crate::protocol::identity::domain_digest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplayInput {
    pub(crate) origin: WorkOrigin,
    pub(crate) decision: [u8; 32],
    pub(crate) interval_since: u64,
    pub(crate) exclusions: DecisionExclusions,
    pub(crate) dropped_positions: Vec<u64>,
}

impl ReplayInput {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let exclusions = &self.exclusions;
        ensure!(
            self.interval_since > 0
                && self.interval_since <= exclusions.consensus_height
                && exclusions.consensus_height <= self.origin.height,
            "replay input decision or interval exceeds verdict"
        );
        strictly_ordered(&self.dropped_positions)?;
        strictly_ordered(&exclusions.direct)?;
        strictly_ordered(&exclusions.effective)?;
        ensure!(
            exclusions
                .direct
                .iter()
                .all(|id| exclusions.effective.binary_search(id).is_ok()),
            "replay direct exclusions are not effective"
        );
        let mut out = Encoder::default();
        out.fixed(b"KRI1")?;
        out.bytes(&self.origin.encode()?)?;
        out.fixed(&self.decision)?;
        out.u64(self.interval_since)?;
        out.u64(exclusions.consensus_height)?;
        for entries in [&exclusions.direct, &exclusions.effective] {
            out.count(entries.len())?;
            for entry in entries {
                out.fixed(entry)?;
            }
        }
        out.count(self.dropped_positions.len())?;
        for &position in &self.dropped_positions {
            out.u64(position)?;
        }
        Ok(out.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KRI1",
            "unknown replay input encoding"
        );
        let origin = WorkOrigin::decode(input.bytes()?)?;
        let decision = input.fixed()?;
        let interval_since = input.u64()?;
        let consensus_height = input.u64()?;
        let mut sets = [Vec::new(), Vec::new()];
        for entries in &mut sets {
            let count = input.count(32)?;
            entries.try_reserve(count)?;
            for _ in 0..count {
                entries.push(input.fixed()?);
            }
        }
        let count = input.count(8)?;
        let mut dropped_positions = Vec::new();
        dropped_positions.try_reserve(count)?;
        for _ in 0..count {
            dropped_positions.push(input.u64()?);
        }
        input.finish()?;
        let [direct, effective] = sets;
        let value = Self {
            origin,
            decision,
            interval_since,
            dropped_positions,
            exclusions: DecisionExclusions {
                consensus_height,
                direct,
                effective,
            },
        };
        value.encode()?;
        Ok(value)
    }

    pub(crate) fn id(&self) -> Result<[u8; 32]> {
        Ok(domain_digest(
            b"kontor/closure-replay-input/v1",
            &self.encode()?,
        ))
    }

    pub(crate) fn transactions(&self, original: &[Transaction]) -> Result<Vec<Transaction>> {
        self.encode()?;
        ensure!(
            self.dropped_positions
                .last()
                .is_none_or(|&index| index < original.len() as u64),
            "replay drop position exceeds batch"
        );
        let kept: Vec<_> = original
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                self.dropped_positions
                    .binary_search(&(*index as u64))
                    .is_err()
            })
            .map(|(_, tx)| tx.clone())
            .collect();
        // Reconstructing the receipt also rejects IDs outside the original batch.
        ensure!(
            DecisionExclusions::for_batch(
                self.exclusions.consensus_height,
                original,
                &kept,
                &self.exclusions.direct
            )? == self.exclusions,
            "replay exclusions differ from original batch"
        );
        Ok(kept)
    }
}
