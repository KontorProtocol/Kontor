use anyhow::{Result, ensure};

use super::application_closure::CanonicalPosition;
use super::certified_input::EraContext;
use crate::protocol::canonical_codec::{Decoder, Encoder};
use crate::protocol::identity::domain_digest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClosureRecord {
    pub(crate) context: EraContext,
    pub(crate) height: u64,
    pub(crate) decision: [u8; 32],
    pub(crate) previous: [u8; 32],
    pub(crate) plan: [u8; 32],
    pub(crate) stages: u64,
    pub(crate) stage_head: [u8; 32],
    pub(crate) output: CanonicalPosition,
    pub(crate) bitcoin_height: u64,
    pub(crate) bitcoin_hash: [u8; 32],
    pub(crate) observation: [u8; 32],
    pub(crate) next_committee: [u8; 32],
}

impl ClosureRecord {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.context.codec == 1
                && self.height > 0
                && self.stages > 0
                && self.bitcoin_height > 0,
            "invalid completed closure position"
        );
        let mut output = Encoder::default();
        output.fixed(b"KCC1")?;
        self.context.encode(&mut output)?;
        output.u64(self.height)?;
        output.fixed(&self.decision)?;
        output.fixed(&self.previous)?;
        output.fixed(&self.plan)?;
        output.u64(self.stages)?;
        output.fixed(&self.stage_head)?;
        self.output.encode(&mut output)?;
        output.u64(self.bitcoin_height)?;
        output.fixed(&self.bitcoin_hash)?;
        output.fixed(&self.observation)?;
        output.fixed(&self.next_committee)?;
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KCC1",
            "unknown closure record encoding"
        );
        let record = Self {
            context: EraContext::decode(&mut input)?,
            height: input.u64()?,
            decision: input.fixed()?,
            previous: input.fixed()?,
            plan: input.fixed()?,
            stages: input.u64()?,
            stage_head: input.fixed()?,
            output: CanonicalPosition::decode(&mut input)?,
            bitcoin_height: input.u64()?,
            bitcoin_hash: input.fixed()?,
            observation: input.fixed()?,
            next_committee: input.fixed()?,
        };
        input.finish()?;
        record.encode()?;
        Ok(record)
    }

    pub(crate) fn id(&self) -> Result<[u8; 32]> {
        Ok(domain_digest(
            b"kontor/decision-closure/v1",
            &self.encode()?,
        ))
    }
}
