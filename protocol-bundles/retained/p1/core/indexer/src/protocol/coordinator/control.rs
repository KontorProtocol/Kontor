//! KUA1 signs `EraContext | head | nonce | expected plan | reference height |
//! reference decision | expiry | operation`. Schedule carries length-prefixed
//! KPM1 and H; Postpone carries target ID, old H and new H; Cancel carries
//! target ID and H. KUC1 encloses length-prefixed KUA1 and sorted fixed-width
//! `(key, generation, signature)` entries. Integers are big-endian. The Schedule
//! action ID becomes PlanId; the full KUC1 digest becomes the next control head.
//! KUS1 snapshots `context | current KPM1 | head | nonce | pending tag`, then
//! `(plan ID, target KPM1, H, consumed tag)` when pending. It contains no clock.

use std::collections::BTreeMap;

use malachitebft_signing_ed25519::{PrivateKey, PublicKey, Signature};

use super::certified_decision::CommitteeRecord;
use super::certified_input::{EraContext, MAX_BATCH_BYTES};
use super::manifest::{MAX_MANIFEST_BYTES, ProtocolManifest};
use crate::protocol::canonical_codec::{CodecError, Decoder, Encoder};
use crate::protocol::identity::{PlanId, ProtocolId, domain_digest};

const NOTICE_HEIGHTS: u64 = 1_008;
const MAX_REFERENCE_AGE: u64 = 144;
const ACTION_DOMAIN: &[u8] = b"kontor/upgrade-action/v1";
const APPROVAL_DOMAIN: &[u8] = b"kontor/upgrade-approval/v1";
const CONTROL_DOMAIN: &[u8] = b"kontor/upgrade-control/v1";
const APPROVAL_BYTES: usize = 32 + 32 + 64;

// Control actions are bounded, individually processed values shared by the
// independently compiled graphs; keep the manifest inline in this value type.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ControlOperation {
    Schedule {
        manifest: ProtocolManifest,
        activation: u64,
    },
    Postpone {
        target: ProtocolId,
        previous_activation: u64,
        activation: u64,
    },
    Cancel {
        target: ProtocolId,
        activation: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ControlAction {
    pub(crate) context: EraContext,
    pub(crate) head: [u8; 32],
    pub(crate) nonce: u64,
    pub(crate) expected_pending: Option<PlanId>,
    pub(crate) reference_height: u64,
    pub(crate) reference_decision: [u8; 32],
    pub(crate) expires_at: u64,
    pub(crate) operation: ControlOperation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Approval {
    pub(crate) key: [u8; 32],
    pub(crate) generation: [u8; 32],
    pub(crate) signature: [u8; 64],
}

impl Approval {
    pub(crate) fn verify_for(&self, action_id: [u8; 32]) -> Result<(), ControlError> {
        let public = PublicKey::from_bytes(self.key).map_err(|_| ControlError::Approval)?;
        let signature = Signature::from_bytes(self.signature);
        let preimage = approval_digest(action_id, self.key, self.generation)?;
        if public.verify(&preimage, &signature).is_err() {
            return Err(ControlError::Signature);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpgradeControl {
    pub(crate) action: ControlAction,
    pub(crate) approvals: Vec<Approval>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedReference {
    pub(crate) height: u64,
    pub(crate) decision: [u8; 32],
    pub(crate) bitcoin_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingPlan {
    pub(crate) id: PlanId,
    pub(crate) manifest: ProtocolManifest,
    pub(crate) activation: u64,
    pub(crate) consumed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ControlState {
    pub(crate) context: EraContext,
    pub(crate) current_manifest: ProtocolManifest,
    pub(crate) head: [u8; 32],
    pub(crate) nonce: u64,
    pub(crate) pending: Option<PendingPlan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcceptedControl {
    pub(crate) action: [u8; 32],
    pub(crate) control: [u8; 32],
    pub(crate) signed_power: u128,
    pub(crate) total_power: u128,
    pub(crate) next: ControlState,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlError {
    #[error("invalid canonical control encoding: {0}")]
    Codec(#[from] CodecError),
    #[error("invalid control context or current manifest")]
    Context,
    #[error("stale control head, nonce or expected plan")]
    Stale,
    #[error("invalid authenticated reference or Bitcoin-height expiry")]
    Reference,
    #[error("invalid target manifest, plan or activation height")]
    Plan,
    #[error("invalid inclusion committee")]
    Committee,
    #[error("unknown, duplicate or stale registration approval")]
    Approval,
    #[error("invalid approval signature")]
    Signature,
    #[error("insufficient current committee voting power")]
    Threshold,
    #[error("control arithmetic overflow")]
    Overflow,
}

impl ControlState {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let current = self.current_manifest.encode()?;
        if self.context.codec != 1
            || self.current_manifest.chain != self.context.chain
            || self.current_manifest.id()? != self.context.protocol
        {
            return Err(CodecError::InvalidValue);
        }
        let mut out = Encoder::default();
        out.fixed(b"KUS1")?;
        self.context.encode(&mut out)?;
        out.bytes(&current)?;
        out.fixed(&self.head)?;
        out.u64(self.nonce)?;
        match &self.pending {
            None => out.tag(0)?,
            Some(plan) => {
                if plan.manifest.chain != self.context.chain {
                    return Err(CodecError::InvalidValue);
                }
                out.tag(1)?;
                out.fixed(&plan.id.0)?;
                out.bytes(&plan.manifest.encode()?)?;
                out.u64(plan.activation)?;
                out.tag(u8::from(plan.consumed))?;
            }
        }
        let bytes = out.finish();
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(CodecError::LengthOverflow);
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(CodecError::LengthOverflow);
        }
        let mut input = Decoder::new(bytes);
        if input.fixed::<4>()? != *b"KUS1" {
            return Err(CodecError::InvalidTag);
        }
        let context = EraContext::decode(&mut input)?;
        let current_bytes = input.bytes()?;
        if current_bytes.len() > MAX_MANIFEST_BYTES {
            return Err(CodecError::LengthOverflow);
        }
        let current_manifest = ProtocolManifest::decode(current_bytes)?;
        let head = input.fixed()?;
        let nonce = input.u64()?;
        let pending = match input.tag()? {
            0 => None,
            1 => {
                let id = PlanId(input.fixed()?);
                let manifest_bytes = input.bytes()?;
                if manifest_bytes.len() > MAX_MANIFEST_BYTES {
                    return Err(CodecError::LengthOverflow);
                }
                let manifest = ProtocolManifest::decode(manifest_bytes)?;
                let activation = input.u64()?;
                let consumed = match input.tag()? {
                    0 => false,
                    1 => true,
                    _ => return Err(CodecError::InvalidTag),
                };
                Some(PendingPlan {
                    id,
                    manifest,
                    activation,
                    consumed,
                })
            }
            _ => return Err(CodecError::InvalidTag),
        };
        input.finish()?;
        let value = Self {
            context,
            current_manifest,
            head,
            nonce,
            pending,
        };
        if value.encode()? != bytes {
            return Err(CodecError::InvalidValue);
        }
        Ok(value)
    }
}

impl ControlAction {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::default();
        out.fixed(b"KUA1")?;
        self.context.encode(&mut out)?;
        out.fixed(&self.head)?;
        out.u64(self.nonce)?;
        match self.expected_pending {
            None => out.tag(0)?,
            Some(id) => {
                out.tag(1)?;
                out.fixed(&id.0)?;
            }
        }
        out.u64(self.reference_height)?;
        out.fixed(&self.reference_decision)?;
        out.u64(self.expires_at)?;
        match &self.operation {
            ControlOperation::Schedule {
                manifest,
                activation,
            } => {
                out.tag(1)?;
                out.bytes(&manifest.encode()?)?;
                out.u64(*activation)?;
            }
            ControlOperation::Postpone {
                target,
                previous_activation,
                activation,
            } => {
                out.tag(2)?;
                out.fixed(&target.0)?;
                out.u64(*previous_activation)?;
                out.u64(*activation)?;
            }
            ControlOperation::Cancel { target, activation } => {
                out.tag(3)?;
                out.fixed(&target.0)?;
                out.u64(*activation)?;
            }
        }
        let bytes = out.finish();
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(CodecError::LengthOverflow);
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(CodecError::LengthOverflow);
        }
        let mut input = Decoder::new(bytes);
        if input.fixed::<4>()? != *b"KUA1" {
            return Err(CodecError::InvalidTag);
        }
        let context = EraContext::decode(&mut input)?;
        let head = input.fixed()?;
        let nonce = input.u64()?;
        let expected_pending = match input.tag()? {
            0 => None,
            1 => Some(PlanId(input.fixed()?)),
            _ => return Err(CodecError::InvalidTag),
        };
        let reference_height = input.u64()?;
        let reference_decision = input.fixed()?;
        let expires_at = input.u64()?;
        let operation = match input.tag()? {
            1 => {
                let manifest_bytes = input.bytes()?;
                if manifest_bytes.len() > MAX_MANIFEST_BYTES {
                    return Err(CodecError::LengthOverflow);
                }
                ControlOperation::Schedule {
                    manifest: ProtocolManifest::decode(manifest_bytes)?,
                    activation: input.u64()?,
                }
            }
            2 => ControlOperation::Postpone {
                target: ProtocolId(input.fixed()?),
                previous_activation: input.u64()?,
                activation: input.u64()?,
            },
            3 => ControlOperation::Cancel {
                target: ProtocolId(input.fixed()?),
                activation: input.u64()?,
            },
            _ => return Err(CodecError::InvalidTag),
        };
        input.finish()?;
        let value = Self {
            context,
            head,
            nonce,
            expected_pending,
            reference_height,
            reference_decision,
            expires_at,
            operation,
        };
        if value.encode()? != bytes {
            return Err(CodecError::InvalidValue);
        }
        Ok(value)
    }

    pub(crate) fn id(&self) -> Result<[u8; 32], CodecError> {
        Ok(domain_digest(ACTION_DOMAIN, &self.encode()?))
    }
}

impl UpgradeControl {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let action = self.action.encode()?;
        let size = 4usize
            .checked_add(4 + action.len())
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(self.approvals.len().checked_mul(APPROVAL_BYTES)?))
            .ok_or(CodecError::LengthOverflow)?;
        if size > MAX_BATCH_BYTES {
            return Err(CodecError::LengthOverflow);
        }
        if self
            .approvals
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(CodecError::UnorderedSet);
        }
        let mut out = Encoder::default();
        out.fixed(b"KUC1")?;
        out.bytes(&action)?;
        out.count(self.approvals.len())?;
        for entry in &self.approvals {
            out.fixed(&entry.key)?;
            out.fixed(&entry.generation)?;
            out.fixed(&entry.signature)?;
        }
        Ok(out.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(CodecError::LengthOverflow);
        }
        let mut input = Decoder::new(bytes);
        if input.fixed::<4>()? != *b"KUC1" {
            return Err(CodecError::InvalidTag);
        }
        let action = ControlAction::decode(input.bytes()?)?;
        let count = input.count(APPROVAL_BYTES)?;
        let mut approvals = Vec::new();
        approvals
            .try_reserve(count)
            .map_err(|_| CodecError::Allocation)?;
        for _ in 0..count {
            approvals.push(Approval {
                key: input.fixed()?,
                generation: input.fixed()?,
                signature: input.fixed()?,
            });
        }
        input.finish()?;
        let value = Self { action, approvals };
        if value.encode()? != bytes {
            return Err(CodecError::InvalidValue);
        }
        Ok(value)
    }

    pub(crate) fn id(&self) -> Result<[u8; 32], CodecError> {
        Ok(domain_digest(CONTROL_DOMAIN, &self.encode()?))
    }

    pub(crate) fn verify(
        &self,
        state: &ControlState,
        inclusion: &CommitteeRecord,
        reference: AuthenticatedReference,
        inclusion_bitcoin_height: u64,
        minimum_reference_height: u64,
    ) -> Result<AcceptedControl, ControlError> {
        let control = self.id()?;
        let action = self.action.id()?;
        if state.current_manifest.chain != state.context.chain
            || state.current_manifest.id()? != state.context.protocol
            || state.context.codec != 1
            || state.current_manifest.control_codec != 1
            || self.action.context != state.context
            || inclusion.context != state.context
        {
            return Err(ControlError::Context);
        }
        if inclusion.validate().is_err() {
            return Err(ControlError::Committee);
        }
        if self.action.head != state.head
            || self.action.nonce != state.nonce.checked_add(1).ok_or(ControlError::Overflow)?
            || self.action.expected_pending != state.pending.as_ref().map(|plan| plan.id)
        {
            return Err(ControlError::Stale);
        }
        let latest_expiry = reference
            .bitcoin_height
            .checked_add(MAX_REFERENCE_AGE)
            .ok_or(ControlError::Overflow)?;
        if reference.height == 0
            || reference.height < minimum_reference_height
            || inclusion.height <= reference.height
            || self.action.reference_height != reference.height
            || self.action.reference_decision != reference.decision
            || reference.bitcoin_height > inclusion_bitcoin_height
            || self.action.expires_at < reference.bitcoin_height
            || self.action.expires_at > latest_expiry
            || inclusion_bitcoin_height > self.action.expires_at
        {
            return Err(ControlError::Reference);
        }
        let mut next = state.clone();
        next.head = control;
        next.nonce = self.action.nonce;
        match &self.action.operation {
            ControlOperation::Schedule {
                manifest,
                activation,
            } => {
                if state.pending.is_some() || self.action.expected_pending.is_some() {
                    return Err(ControlError::Plan);
                }
                validate_target(manifest, &state.current_manifest)?;
                validate_notice(*activation, inclusion_bitcoin_height)?;
                next.pending = Some(PendingPlan {
                    id: PlanId(action),
                    manifest: manifest.clone(),
                    activation: *activation,
                    consumed: false,
                });
            }
            ControlOperation::Postpone {
                target,
                previous_activation,
                activation,
            } => {
                let pending = state.pending.as_ref().ok_or(ControlError::Plan)?;
                if pending.consumed
                    || pending.manifest.id()? != *target
                    || pending.activation != *previous_activation
                    || *activation <= *previous_activation
                {
                    return Err(ControlError::Plan);
                }
                validate_notice(*activation, inclusion_bitcoin_height)?;
                next.pending.as_mut().ok_or(ControlError::Plan)?.activation = *activation;
            }
            ControlOperation::Cancel { target, activation } => {
                let pending = state.pending.as_ref().ok_or(ControlError::Plan)?;
                if pending.consumed
                    || pending.manifest.id()? != *target
                    || pending.activation != *activation
                {
                    return Err(ControlError::Plan);
                }
                next.pending = None;
            }
        }
        let mut by_key = BTreeMap::new();
        let mut total = 0u128;
        for member in &inclusion.members {
            total = total
                .checked_add(u128::from(member.power))
                .ok_or(ControlError::Overflow)?;
            by_key.insert(member.key, member);
        }
        let mut signed = 0u128;
        let mut previous = None;
        for approval in &self.approvals {
            if previous.is_some_and(|key| key >= approval.key) {
                return Err(ControlError::Approval);
            }
            previous = Some(approval.key);
            let member = by_key.get(&approval.key).ok_or(ControlError::Approval)?;
            if member.generation != approval.generation {
                return Err(ControlError::Approval);
            }
            approval.verify_for(action)?;
            signed = signed
                .checked_add(u128::from(member.power))
                .ok_or(ControlError::Overflow)?;
        }
        let passes = match self.action.operation {
            ControlOperation::Cancel { .. } => {
                signed.checked_mul(3).ok_or(ControlError::Overflow)?
                    > total.checked_mul(2).ok_or(ControlError::Overflow)?
            }
            _ => {
                signed.checked_mul(6).ok_or(ControlError::Overflow)?
                    >= total.checked_mul(5).ok_or(ControlError::Overflow)?
            }
        };
        if !passes {
            return Err(ControlError::Threshold);
        }
        Ok(AcceptedControl {
            action,
            control,
            signed_power: signed,
            total_power: total,
            next,
        })
    }
}

pub(crate) struct ApprovalSigner {
    key: PrivateKey,
}

impl ApprovalSigner {
    pub(crate) fn new(key: PrivateKey) -> Self {
        Self { key }
    }

    pub(crate) fn sign(
        &self,
        action: &ControlAction,
        generation: [u8; 32],
    ) -> Result<Approval, CodecError> {
        let key = *self.key.public_key().as_bytes();
        let preimage = approval_digest(action.id()?, key, generation)?;
        Ok(Approval {
            key,
            generation,
            signature: self.key.sign(&preimage).to_bytes(),
        })
    }
}

fn approval_digest(
    action: [u8; 32],
    key: [u8; 32],
    generation: [u8; 32],
) -> Result<[u8; 32], CodecError> {
    let mut out = Encoder::default();
    out.fixed(b"KAP1")?;
    out.fixed(&action)?;
    out.fixed(&key)?;
    out.fixed(&generation)?;
    Ok(domain_digest(APPROVAL_DOMAIN, &out.finish()))
}

pub(crate) fn validate_target(
    target: &ProtocolManifest,
    current: &ProtocolManifest,
) -> Result<(), ControlError> {
    if target.chain != current.chain
        || target.predecessor != current.id()?
        || target.protocol_number
            != current
                .protocol_number
                .checked_add(1)
                .ok_or(ControlError::Overflow)?
        || target.input_state_schema != current.state_schema
        || target.output_state_schema != target.state_schema
        || target.control_codec == 0
        || target.certificate_codec == 0
    {
        return Err(ControlError::Plan);
    }
    target.encode()?;
    Ok(())
}

fn validate_notice(activation: u64, inclusion_bitcoin_height: u64) -> Result<(), ControlError> {
    let minimum = inclusion_bitcoin_height
        .checked_add(NOTICE_HEIGHTS)
        .ok_or(ControlError::Overflow)?;
    if activation < minimum {
        return Err(ControlError::Plan);
    }
    Ok(())
}

#[cfg(test)]
#[path = "control/tests.rs"]
mod tests;
