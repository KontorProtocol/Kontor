use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use malachitebft_core_types::{NilOrVal, Round};
use prost::Message;

use super::{AuthorityMember, CommitteeRecord, Decision};
use crate::consensus::codec::decode_signature;
use crate::consensus::signing::PublicKey;
use crate::consensus::{Address, Height, ValueId, Vote, proto};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Height,
    RoundOrValue,
    Value,
    Signatures,
}

pub(crate) struct ProofVerifier<'a> {
    height: u64,
    value_id: ValueId,
    round: u32,
    total_power: u64,
    power: u64,
    members: BTreeMap<[u8; 20], &'a AuthorityMember>,
    signed: BTreeSet<[u8; 20]>,
    remaining: usize,
    field: Field,
    // One tag, a maximal u64 varint, and one bounded signature record. Neither
    // the declared proof size nor a split page can grow this wire buffer.
    buffer: [u8; 107],
    used: usize,
    target: Option<usize>,
    payload: usize,
    failed: bool,
}

impl<'a> ProofVerifier<'a> {
    pub(crate) fn for_decision(
        decision: &Decision,
        length: usize,
        authority: &'a CommitteeRecord,
    ) -> Result<Self> {
        ensure!(
            decision.height == authority.height
                && decision.committee == authority.id()?
                && decision.descriptor.context == authority.context,
            "certificate authority context differs"
        );
        Self::new(
            decision.height,
            ValueId::new(decision.descriptor.id()?),
            length,
            authority,
        )
    }

    pub(crate) fn new(
        height: u64,
        value_id: ValueId,
        length: usize,
        authority: &'a CommitteeRecord,
    ) -> Result<Self> {
        let total_power = authority.validate()?;
        ensure!(
            height == authority.height,
            "certificate authority height differs"
        );
        ensure!(
            length <= authority.maximum_proof_bytes()?,
            "certificate exceeds committee size bound"
        );
        Ok(Self {
            height,
            value_id,
            round: 0,
            total_power,
            power: 0,
            members: authority
                .members
                .iter()
                .map(|member| (member.address, member))
                .collect(),
            signed: BTreeSet::new(),
            remaining: length,
            field: Field::Height,
            buffer: [0; 107],
            used: 0,
            target: None,
            payload: 0,
            failed: false,
        })
    }

    pub(crate) fn push(&mut self, mut bytes: &[u8]) -> Result<()> {
        ensure!(!self.failed, "certificate stream already failed");
        self.failed = true;
        ensure!(
            bytes.len() <= self.remaining,
            "certificate exceeds declared length"
        );
        self.remaining -= bytes.len();
        while !bytes.is_empty() {
            if let Some(target) = self.target {
                let count = (target - self.used).min(bytes.len());
                self.buffer[self.used..self.used + count].copy_from_slice(&bytes[..count]);
                self.used += count;
                bytes = &bytes[count..];
            } else {
                self.buffer[self.used] = bytes[0];
                self.used += 1;
                bytes = &bytes[1..];
                self.read_prefix()?;
            }
            if self.target == Some(self.used) {
                self.complete_field()?;
                self.used = 0;
                self.target = None;
            }
        }
        self.failed = false;
        Ok(())
    }

    fn read_prefix(&mut self) -> Result<()> {
        let tag = self.buffer[0];
        if self.used == 1 {
            ensure!(
                match self.field {
                    Field::Height => tag == 8,
                    Field::RoundOrValue => tag == 16 || tag == 26,
                    Field::Value => tag == 26,
                    Field::Signatures => tag == 34,
                },
                "unexpected certificate field"
            );
            ensure!(
                self.field != Field::Signatures || self.signed.len() < self.members.len(),
                "certificate has too many signers"
            );
            return Ok(());
        }
        let index = self.used - 2;
        let byte = self.buffer[self.used - 1];
        ensure!(index < 9 || byte <= 1, "certificate integer overflow");
        if byte & 0x80 != 0 {
            return Ok(());
        }
        ensure!(index == 0 || byte != 0, "nonminimal certificate integer");
        let value = self.buffer[1..self.used]
            .iter()
            .enumerate()
            .fold(0u64, |value, (index, byte)| {
                value | (u64::from(byte & 0x7f) << (7 * index))
            });
        match tag {
            8 => {
                ensure!(value == self.height, "certificate height differs");
                self.target = Some(self.used);
            }
            16 => {
                self.round = u32::try_from(value)?;
                ensure!(self.round != 0, "noncanonical zero round");
                self.target = Some(self.used);
            }
            26 | 34 => {
                let maximum = if tag == 26 { 34 } else { 96 };
                ensure!(value <= maximum, "certificate field exceeds bound");
                self.payload = self.used;
                self.target = Some(self.used + usize::try_from(value)?);
            }
            _ => unreachable!("tag was checked before reading its integer"),
        }
        Ok(())
    }

    fn complete_field(&mut self) -> Result<()> {
        match self.buffer[0] {
            8 => self.field = Field::RoundOrValue,
            16 => self.field = Field::Value,
            26 => {
                let bytes = &self.buffer[self.payload..self.used];
                ensure!(
                    bytes.len() == 34 && bytes[..2] == [10, 32],
                    "invalid certificate value encoding"
                );
                ensure!(bytes[2..] == self.value_id.0, "certificate value differs");
                self.field = Field::Signatures;
            }
            34 => {
                let bytes = &self.buffer[self.payload..self.used];
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
                let member = self
                    .members
                    .get(&address)
                    .context("unknown certificate signer")?;
                ensure!(self.signed.insert(address), "duplicate certificate signer");
                let signature =
                    decode_signature(signature.signature.context("missing signature")?)?;
                let vote = Vote::new_precommit(
                    Height::new(self.height),
                    Round::new(self.round),
                    NilOrVal::Val(self.value_id),
                    Address::new(address),
                );
                PublicKey::from_bytes(member.key)?
                    .verify(&vote.to_sign_bytes(), &signature)
                    .context("invalid certificate signature")?;
                self.power = self
                    .power
                    .checked_add(member.power)
                    .context("certificate voting power overflow")?;
            }
            _ => unreachable!("tag was checked before reading its payload"),
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<()> {
        ensure!(!self.failed, "certificate stream already failed");
        ensure!(
            self.remaining == 0 && self.used == 0 && self.field == Field::Signatures,
            "truncated certificate"
        );
        ensure!(
            self.power * 3 > self.total_power * 2,
            "certificate lacks supermajority"
        );
        Ok(())
    }
}
