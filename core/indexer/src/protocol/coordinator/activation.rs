use anyhow::{Context, Result, ensure};

use super::certified_input::EraContext;
use super::control::{ControlState, validate_target};
use super::manifest::ProtocolManifest;
use crate::protocol::canonical_codec::{Decoder, Encoder};
use crate::protocol::identity::{ChainId, PlanId, ProtocolId, domain_digest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransitionDescriptor {
    pub(crate) chain: ChainId,
    pub(crate) plan: PlanId,
    pub(crate) bitcoin_height: u64,
    pub(crate) bitcoin_hash: [u8; 32],
    pub(crate) source: ProtocolId,
    pub(crate) target: ProtocolId,
    pub(crate) consensus: [u8; 32],
    pub(crate) start_height: u64,
}

impl TransitionDescriptor {
    pub(crate) fn expected(
        state: &ControlState,
        bitcoin_height: u64,
        bitcoin_hash: [u8; 32],
        decision_height: u64,
    ) -> Result<Option<Self>> {
        ensure!(
            bitcoin_height > 0 && decision_height > 0,
            "invalid transition position"
        );
        let source = state.current_manifest.id()?;
        ensure!(
            state.current_manifest.chain == state.context.chain && source == state.context.protocol,
            "transition control context differs"
        );
        let Some(plan) = state.pending.as_ref().filter(|plan| !plan.consumed) else {
            return Ok(None);
        };
        ensure!(
            bitcoin_height <= plan.activation,
            "pending activation was skipped"
        );
        if bitcoin_height < plan.activation {
            return Ok(None);
        }
        validate_target(&plan.manifest, &state.current_manifest)?;
        let descriptor = Self {
            chain: state.context.chain,
            plan: plan.id,
            bitcoin_height,
            bitcoin_hash,
            source,
            target: plan.manifest.id()?,
            consensus: plan.manifest.consensus,
            start_height: decision_height
                .checked_add(1)
                .context("consensus height exhausted")?,
        };
        descriptor.validate()?;
        Ok(Some(descriptor))
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.bitcoin_height > 0 && self.start_height > 1 && self.source != self.target,
            "invalid activation descriptor"
        );
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Encoder::default();
        out.fixed(b"KAT1")?;
        out.fixed(&self.chain.0)?;
        out.fixed(&self.plan.0)?;
        out.u64(self.bitcoin_height)?;
        out.fixed(&self.bitcoin_hash)?;
        out.fixed(&self.source.0)?;
        out.fixed(&self.target.0)?;
        out.fixed(&self.consensus)?;
        out.u64(self.start_height)?;
        Ok(out.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KAT1",
            "unknown activation descriptor"
        );
        let descriptor = Self {
            chain: ChainId(input.fixed()?),
            plan: PlanId(input.fixed()?),
            bitcoin_height: input.u64()?,
            bitcoin_hash: input.fixed()?,
            source: ProtocolId(input.fixed()?),
            target: ProtocolId(input.fixed()?),
            consensus: input.fixed()?,
            start_height: input.u64()?,
        };
        input.finish()?;
        descriptor.validate()?;
        Ok(descriptor)
    }
}

// This record describes completed closure, not a promise made while voting on H.
// Committee and closure IDs are derived afterwards to avoid a hash dependency cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EraTransition {
    pub(crate) previous: EraContext,
    pub(crate) height: u64,
    pub(crate) decision: [u8; 32],
    pub(crate) lineage: [u8; 32],
    pub(crate) next: EraContext,
}

impl EraTransition {
    pub(crate) fn derive(
        previous: EraContext,
        height: u64,
        decision: [u8; 32],
        lineage: [u8; 32],
        selected: &ProtocolManifest,
    ) -> Result<Option<Self>> {
        ensure!(
            previous.chain == selected.chain
                && previous.codec == 1
                && selected.certificate_codec == 1
                && height > 0,
            "invalid completed protocol selection"
        );
        height
            .checked_add(1)
            .context("consensus height exhausted")?;
        let protocol = selected.id()?;
        if previous.protocol == protocol {
            return Ok(None);
        }
        let mut transition = Self {
            previous,
            height,
            decision,
            lineage,
            next: EraContext {
                chain: selected.chain,
                era: [0; 32],
                protocol,
                codec: selected.certificate_codec,
            },
        };
        transition.next.era = transition.era()?;
        transition.validate()?;
        Ok(Some(transition))
    }

    pub(crate) fn start_height(&self) -> Result<u64> {
        self.height
            .checked_add(1)
            .context("consensus height exhausted")
    }

    fn era(&self) -> Result<[u8; 32]> {
        let mut out = Encoder::default();
        self.previous.encode(&mut out)?;
        out.u64(self.height)?;
        out.fixed(&self.decision)?;
        out.fixed(&self.lineage)?;
        out.fixed(&self.next.protocol.0)?;
        out.fixed(&self.next.codec.to_be_bytes())?;
        Ok(domain_digest(
            b"kontor/closed-protocol-era/v1",
            &out.finish(),
        ))
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.height > 0
                && self.previous.chain == self.next.chain
                && self.previous.codec == 1
                && self.next.codec == 1
                && self.previous.protocol != self.next.protocol
                && self.previous.era != self.next.era
                && self.next.era == self.era()?,
            "invalid completed era transition"
        );
        self.start_height()?;
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Encoder::default();
        out.fixed(b"KET1")?;
        self.previous.encode(&mut out)?;
        out.u64(self.height)?;
        out.fixed(&self.decision)?;
        out.fixed(&self.lineage)?;
        self.next.encode(&mut out)?;
        Ok(out.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(input.fixed::<4>()? == *b"KET1", "unknown era transition");
        let transition = Self {
            previous: EraContext::decode(&mut input)?,
            height: input.u64()?,
            decision: input.fixed()?,
            lineage: input.fixed()?,
            next: EraContext::decode(&mut input)?,
        };
        input.finish()?;
        transition.validate()?;
        Ok(transition)
    }
}

#[cfg(test)]
mod tests;
