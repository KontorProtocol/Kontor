use bitcoin::Txid;
use bytes::Bytes;
use malachitebft_signing_ed25519::Signature;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use malachitebft_core_types::Round;
use malachitebft_proto::{self as proto_trait, Error as ProtoError, Protobuf};

use crate::consensus::codec::{decode_signature, encode_signature};
use crate::consensus::proto;
use crate::consensus::proto::proposal_part::Part;
use crate::consensus::{Address, Ctx, Height, Value};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalData(Value);

impl ProposalData {
    pub fn new(value: Value) -> Self {
        Self(value)
    }
    pub fn value(&self) -> &Value {
        &self.0
    }
    pub fn signing_digest(&self, height: Height, round: Round) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"kontor/proposal-parts/v1\0");
        hasher.update(height.as_u64().to_be_bytes());
        hasher.update(round.as_i64().to_be_bytes());
        hasher.update(self.value().descriptor_bytes());
        hasher.finalize().into()
    }

    pub fn txids(&self) -> Vec<Txid> {
        self.0.batch_txids()
    }
    pub fn size_bytes(&self) -> usize {
        self.0.size_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalPart {
    Init(ProposalInit),
    Data(ProposalData),
    Fin(ProposalFin),
}

impl ProposalPart {
    pub fn as_init(&self) -> Option<&ProposalInit> {
        match self {
            Self::Init(init) => Some(init),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&ProposalData> {
        match self {
            Self::Data(data) => Some(data),
            _ => None,
        }
    }

    pub fn as_fin(&self) -> Option<&ProposalFin> {
        match self {
            Self::Fin(fin) => Some(fin),
            _ => None,
        }
    }

    pub fn to_sign_bytes(&self) -> Bytes {
        proto_trait::Protobuf::to_bytes(self).expect("proposal part serialization should not fail")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalInit {
    pub height: Height,
    pub round: Round,
    pub pol_round: Round,
    pub proposer: Address,
}

impl ProposalInit {
    pub fn new(height: Height, round: Round, pol_round: Round, proposer: Address) -> Self {
        Self {
            height,
            round,
            pol_round,
            proposer,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalFin {
    pub signature: Signature,
}

impl ProposalFin {
    pub fn new(signature: Signature) -> Self {
        Self { signature }
    }
}

impl malachitebft_core_types::ProposalPart<Ctx> for ProposalPart {
    fn is_first(&self) -> bool {
        matches!(self, Self::Init(_))
    }

    fn is_last(&self) -> bool {
        matches!(self, Self::Fin(_))
    }
}

impl Protobuf for ProposalPart {
    type Proto = proto::ProposalPart;

    fn from_proto(proto: Self::Proto) -> Result<Self, ProtoError> {
        let part = proto
            .part
            .ok_or_else(|| ProtoError::missing_field::<Self::Proto>("part"))?;

        match part {
            Part::Init(init) => Ok(Self::Init(ProposalInit {
                height: Height::new(init.height),
                round: Round::new(init.round),
                pol_round: Round::from(init.pol_round),
                proposer: init
                    .proposer
                    .ok_or_else(|| ProtoError::missing_field::<Self::Proto>("proposer"))
                    .and_then(Address::from_proto)?,
            })),
            Part::Data(data) => Ok(Self::Data(ProposalData::new(Value::from_proto(
                data.value
                    .ok_or_else(|| ProtoError::missing_field::<proto::ProposalData>("value"))?,
            )?))),
            Part::Fin(fin) => Ok(Self::Fin(ProposalFin {
                signature: fin
                    .signature
                    .ok_or_else(|| ProtoError::missing_field::<Self::Proto>("signature"))
                    .and_then(decode_signature)?,
            })),
        }
    }

    fn to_proto(&self) -> Result<Self::Proto, ProtoError> {
        match self {
            Self::Init(init) => {
                let round = init
                    .round
                    .as_u32()
                    .ok_or_else(|| ProtoError::Other("round should not be nil".to_string()))?;
                Ok(Self::Proto {
                    part: Some(Part::Init(proto::ProposalInit {
                        height: init.height.as_u64(),
                        round,
                        pol_round: init.pol_round.as_u32(),
                        proposer: Some(init.proposer.to_proto()?),
                    })),
                })
            }
            Self::Data(data) => Ok(Self::Proto {
                part: Some(Part::Data(proto::ProposalData {
                    value: Some(data.value().to_proto()?),
                })),
            }),
            Self::Fin(fin) => Ok(Self::Proto {
                part: Some(Part::Fin(proto::ProposalFin {
                    signature: Some(encode_signature(&fin.signature)),
                })),
            }),
        }
    }
}
