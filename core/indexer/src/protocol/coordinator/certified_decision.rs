use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use malachitebft_core_types::{NilOrVal, Round};
use prost::Message;

use super::certified_input::{Descriptor, EraContext, ExactInput};
use crate::consensus::codec::decode_signature;
use crate::consensus::signing::PublicKey;
use crate::consensus::{Address, Height, ValueId, Vote, proto};
use crate::protocol::canonical_codec::{CodecError, Decoder, Encoder};
use crate::protocol::identity::domain_digest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthorityMember {
    pub(crate) holder: String,
    pub(crate) generation: [u8; 32],
    pub(crate) address: [u8; 20],
    pub(crate) key: [u8; 32],
    pub(crate) power: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommitteeRecord {
    pub(crate) context: EraContext,
    pub(crate) height: u64,
    pub(crate) decision: [u8; 32],
    pub(crate) stage: u64,
    pub(crate) lineage: [u8; 32],
    pub(crate) members: Vec<AuthorityMember>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthorityError {
    #[error("no active validators")]
    NoActiveValidators,
    #[error("invalid committee bridge member")]
    InvalidMember,
    #[error("duplicate committee key, address or holder")]
    DuplicateMember,
    #[error("committee voting power exceeds arithmetic bound")]
    VotingPowerOverflow,
}

impl CommitteeRecord {
    pub(crate) fn validate(&self) -> Result<u64> {
        if self.members.is_empty() {
            return Err(AuthorityError::NoActiveValidators.into());
        }
        ensure!(
            self.height > 0 && self.context.codec == 1,
            "invalid authority context"
        );
        let (mut keys, mut addresses, mut holders) =
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        let mut total = 0u64;
        for member in &self.members {
            let key =
                PublicKey::from_bytes(member.key).map_err(|_| AuthorityError::InvalidMember)?;
            if member.power == 0
                || member.holder.is_empty()
                || Address::from_public_key(&key).into_inner() != member.address
            {
                return Err(AuthorityError::InvalidMember.into());
            }
            if !keys.insert(member.key)
                || !addresses.insert(member.address)
                || !holders.insert(&member.holder)
            {
                return Err(AuthorityError::DuplicateMember.into());
            }
            total = total
                .checked_add(member.power)
                .filter(|total| *total <= u64::MAX / 3)
                .ok_or(AuthorityError::VotingPowerOverflow)?;
        }
        Ok(total)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut output = Encoder::default();
        output.fixed(b"KCA1")?;
        self.context.encode(&mut output)?;
        output.u64(self.height)?;
        output.fixed(&self.decision)?;
        output.u64(self.stage)?;
        output.fixed(&self.lineage)?;
        // KCA1 is the checked Ed25519/Keccak-address/u64-power bridge. Preserve
        // executor order, since sorting here could change proposer selection.
        output.count(self.members.len())?;
        for member in &self.members {
            output.bytes(member.holder.as_bytes())?;
            output.fixed(&member.generation)?;
            output.fixed(&member.address)?;
            output.fixed(&member.key)?;
            output.u64(member.power)?;
        }
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KCA1",
            "unknown committee encoding"
        );
        let context = EraContext::decode(&mut input)?;
        let height = input.u64()?;
        let decision = input.fixed()?;
        let stage = input.u64()?;
        let lineage = input.fixed()?;
        let count = input.count(96)?;
        let mut members = Vec::new();
        members
            .try_reserve(count)
            .map_err(|_| CodecError::Allocation)?;
        for _ in 0..count {
            members.push(AuthorityMember {
                holder: input.owned_string()?,
                generation: input.fixed()?,
                address: input.fixed()?,
                key: input.fixed()?,
                power: input.u64()?,
            });
        }
        input.finish()?;
        let record = Self {
            context,
            height,
            decision,
            stage,
            lineage,
            members,
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn id(&self) -> Result<[u8; 32]> {
        Ok(domain_digest(
            b"kontor/historical-committee/v1",
            &self.encode()?,
        ))
    }

    pub(crate) fn maximum_proof_bytes(&self) -> Result<usize> {
        self.members
            .len()
            .checked_mul(96)
            .and_then(|n| n.checked_add(1024))
            .context("certificate size bound overflow")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Decision {
    pub(crate) height: u64,
    pub(crate) predecessor: [u8; 32],
    pub(crate) committee: [u8; 32],
    pub(crate) descriptor: Descriptor,
}

impl Decision {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.height == 0 {
            return Err(CodecError::InvalidValue);
        }
        let mut output = Encoder::default();
        output.fixed(b"KCD1")?;
        output.u64(self.height)?;
        output.fixed(&self.predecessor)?;
        output.fixed(&self.committee)?;
        output.bytes(&self.descriptor.encode()?)?;
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::new(bytes);
        if input.fixed::<4>()? != *b"KCD1" {
            return Err(CodecError::InvalidTag);
        }
        let value = Self {
            height: input.u64()?,
            predecessor: input.fixed()?,
            committee: input.fixed()?,
            descriptor: Descriptor::decode(input.bytes()?)?,
        };
        input.finish()?;
        if value.height == 0 {
            return Err(CodecError::InvalidValue);
        }
        Ok(value)
    }

    pub(crate) fn id(&self) -> Result<[u8; 32], CodecError> {
        Ok(domain_digest(
            b"kontor/certified-decision/v1",
            &self.encode()?,
        ))
    }
}

pub(crate) struct AuthenticatedDecision {
    decision: Decision,
    input: ExactInput,
    proof: Vec<u8>,
}

impl AuthenticatedDecision {
    pub(crate) fn verify(
        decision: Decision,
        input: ExactInput,
        proof: Vec<u8>,
        authority: &CommitteeRecord,
    ) -> Result<Self> {
        ensure!(
            decision.descriptor == *input.descriptor(),
            "decision input differs"
        );
        verify_certificate(&decision, &proof, authority)?;
        Ok(Self {
            decision,
            input,
            proof,
        })
    }

    pub(crate) fn decision(&self) -> &Decision {
        &self.decision
    }
    pub(crate) fn input(&self) -> &ExactInput {
        &self.input
    }
    pub(crate) fn proof(&self) -> &[u8] {
        &self.proof
    }
}

pub(crate) fn verify_certificate(
    decision: &Decision,
    proof: &[u8],
    authority: &CommitteeRecord,
) -> Result<()> {
    let total = authority.validate()?;
    ensure!(
        decision.height == authority.height
            && decision.committee == authority.id()?
            && decision.descriptor.context == authority.context,
        "certificate authority context differs"
    );
    ensure!(
        proof.len() <= authority.maximum_proof_bytes()?,
        "certificate exceeds committee size bound"
    );
    let mut input = CertificateReader(proof);
    input.tag(8)?;
    ensure!(
        input.varint()? == decision.height,
        "certificate height differs"
    );
    let round = if input.0.first() == Some(&16) {
        input.tag(16)?;
        let round = u32::try_from(input.varint()?)?;
        ensure!(round != 0, "noncanonical zero round");
        round
    } else {
        0
    };
    let value = input.message(26, 34)?;
    ensure!(
        value.len() == 34 && value[..2] == [10, 32],
        "invalid certificate value encoding"
    );
    let value_id = ValueId::new(decision.descriptor.id()?);
    ensure!(value[2..] == value_id.0, "certificate value differs");
    let members = authority
        .members
        .iter()
        .map(|m| (m.address, m))
        .collect::<BTreeMap<_, _>>();
    let mut signed = BTreeSet::new();
    let mut power = 0u64;
    while !input.0.is_empty() {
        ensure!(
            signed.len() < members.len(),
            "certificate has too many signers"
        );
        // Decode one bounded record at a time. A hostile repeated-field count
        // cannot make Prost allocate a certificate-sized vector before validation.
        let bytes = input.message(34, 96)?;
        let signature = proto::CommitSignature::decode(bytes)?;
        ensure!(
            signature.encode_to_vec() == bytes && signature.extension.is_none(),
            "noncanonical signature or unsupported extension"
        );
        let address: [u8; 20] = signature
            .validator_address
            .context("missing signer")?
            .value
            .as_ref()
            .try_into()
            .context("invalid signer address")?;
        let member = members
            .get(&address)
            .context("unknown certificate signer")?;
        ensure!(signed.insert(address), "duplicate certificate signer");
        let signature = decode_signature(signature.signature.context("missing signature")?)?;
        let vote = Vote::new_precommit(
            Height::new(decision.height),
            Round::new(round),
            NilOrVal::Val(value_id),
            Address::new(address),
        );
        PublicKey::from_bytes(member.key)?
            .verify(&vote.to_sign_bytes(), &signature)
            .context("invalid certificate signature")?;
        power = power
            .checked_add(member.power)
            .context("certificate voting power overflow")?;
    }
    ensure!(power * 3 > total * 2, "certificate lacks supermajority");
    Ok(())
}

struct CertificateReader<'a>(&'a [u8]);

impl<'a> CertificateReader<'a> {
    fn tag(&mut self, expected: u8) -> Result<()> {
        ensure!(
            self.0.first() == Some(&expected),
            "unexpected certificate field"
        );
        self.0 = &self.0[1..];
        Ok(())
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = *self.0.first().context("truncated certificate integer")?;
            self.0 = &self.0[1..];
            ensure!(index < 9 || byte <= 1, "certificate integer overflow");
            value |= u64::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                ensure!(index == 0 || byte != 0, "nonminimal certificate integer");
                return Ok(value);
            }
        }
        anyhow::bail!("certificate integer overflow")
    }

    fn message(&mut self, tag: u8, maximum: usize) -> Result<&'a [u8]> {
        self.tag(tag)?;
        let length = usize::try_from(self.varint()?)?;
        ensure!(length <= maximum, "certificate field exceeds bound");
        let (value, remaining) = self
            .0
            .split_at_checked(length)
            .context("truncated certificate field")?;
        self.0 = remaining;
        Ok(value)
    }
}

#[cfg(test)]
pub(crate) mod tests;
