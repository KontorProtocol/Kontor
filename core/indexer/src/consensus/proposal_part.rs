use bytes::Bytes;
use malachitebft_signing_ed25519::Signature;
use serde::{Deserialize, Serialize};

use malachitebft_core_types::Round;
use malachitebft_proto::{self as proto_trait, Error as ProtoError, Protobuf};

use crate::consensus::codec::{decode_signature, encode_signature};
use crate::consensus::{Address, Ctx, Height};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalData {
    pub anchor_height: u64,
    pub txids: Vec<[u8; 32]>,
}

impl ProposalData {
    pub fn new(anchor_height: u64, txids: Vec<[u8; 32]>) -> Self {
        Self {
            anchor_height,
            txids,
        }
    }

    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<u64>() + self.txids.len() * 32
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
        proto_trait::Protobuf::to_bytes(self).unwrap()
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
    type Proto = crate::consensus::proto::ProposalPart;

    fn from_proto(proto: Self::Proto) -> Result<Self, ProtoError> {
        use crate::consensus::proto::proposal_part::Part;

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
            Part::Data(data) => {
                let txids: Vec<[u8; 32]> = data
                    .txids
                    .iter()
                    .map(|b| {
                        <[u8; 32]>::try_from(b.as_ref()).map_err(|_| {
                            ProtoError::Other(format!(
                                "Invalid txid length: expected 32, got {}",
                                b.len()
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Data(ProposalData::new(data.anchor_height, txids)))
            }
            Part::Fin(fin) => Ok(Self::Fin(ProposalFin {
                signature: fin
                    .signature
                    .ok_or_else(|| ProtoError::missing_field::<Self::Proto>("signature"))
                    .and_then(decode_signature)?,
            })),
        }
    }

    fn to_proto(&self) -> Result<Self::Proto, ProtoError> {
        use crate::consensus::proto;
        use crate::consensus::proto::proposal_part::Part;

        match self {
            Self::Init(init) => Ok(Self::Proto {
                part: Some(Part::Init(proto::ProposalInit {
                    height: init.height.as_u64(),
                    round: init.round.as_u32().unwrap(),
                    pol_round: init.pol_round.as_u32(),
                    proposer: Some(init.proposer.to_proto()?),
                })),
            }),
            Self::Data(data) => Ok(Self::Proto {
                part: Some(Part::Data(proto::ProposalData {
                    anchor_height: data.anchor_height,
                    txids: data
                        .txids
                        .iter()
                        .map(|t| Bytes::copy_from_slice(t))
                        .collect(),
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
