use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Transaction, Txid};
use bytes::Bytes;
use malachitebft_signing_ed25519::Signature;
use serde::{Deserialize, Serialize};

use malachitebft_core_types::Round;
use malachitebft_proto::{self as proto_trait, Error as ProtoError, Protobuf};

use crate::consensus::codec::{decode_signature, encode_signature};
use crate::consensus::{Address, Ctx, Height};

/// Proposal data streamed during live consensus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalData {
    /// A batch of mempool transactions anchored at a specific block.
    Batch {
        anchor_height: u64,
        anchor_hash: BlockHash,
        transactions: Vec<Transaction>,
    },
    /// A Bitcoin block confirmation — no full tx data needed.
    Block { height: u64, hash: BlockHash },
}

impl ProposalData {
    pub fn new_batch(
        anchor_height: u64,
        anchor_hash: BlockHash,
        transactions: Vec<Transaction>,
    ) -> Self {
        Self::Batch {
            anchor_height,
            anchor_hash,
            transactions,
        }
    }

    pub fn new_block(height: u64, hash: BlockHash) -> Self {
        Self::Block { height, hash }
    }

    pub fn txids(&self) -> Vec<Txid> {
        match self {
            Self::Batch { transactions, .. } => {
                transactions.iter().map(|tx| tx.compute_txid()).collect()
            }
            Self::Block { .. } => Vec::new(),
        }
    }

    pub fn size_bytes(&self) -> usize {
        match self {
            Self::Batch { transactions, .. } => {
                8 + 32
                    + transactions
                        .iter()
                        .map(|tx| bitcoin::consensus::serialize(tx).len())
                        .sum::<usize>()
            }
            Self::Block { .. } => 8 + 32,
        }
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
                let hash_arr: [u8; 32] = data.anchor_hash.as_ref().try_into().map_err(|_| {
                    ProtoError::Other(format!(
                        "Invalid anchor_hash length: got {} bytes, expected 32",
                        data.anchor_hash.len()
                    ))
                })?;
                let hash = BlockHash::from_byte_array(hash_arr);

                if data.is_block {
                    Ok(Self::Data(ProposalData::new_block(
                        data.anchor_height,
                        hash,
                    )))
                } else {
                    let transactions: Vec<Transaction> = data
                        .transactions
                        .iter()
                        .map(|b: &Bytes| {
                            bitcoin::consensus::deserialize(b.as_ref()).map_err(|e| {
                                ProtoError::Other(format!("Failed to deserialize transaction: {e}"))
                            })
                        })
                        .collect::<Result<Vec<_>, ProtoError>>()?;
                    Ok(Self::Data(ProposalData::new_batch(
                        data.anchor_height,
                        hash,
                        transactions,
                    )))
                }
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
            Self::Data(data) => {
                let proto_data = match data {
                    ProposalData::Batch {
                        anchor_height,
                        anchor_hash,
                        transactions,
                    } => proto::ProposalData {
                        anchor_height: *anchor_height,
                        transactions: transactions
                            .iter()
                            .map(|tx| Bytes::from(bitcoin::consensus::serialize(tx)))
                            .collect(),
                        anchor_hash: Bytes::from(anchor_hash.to_byte_array().to_vec()),
                        is_block: false,
                    },
                    ProposalData::Block { height, hash } => proto::ProposalData {
                        anchor_height: *height,
                        transactions: Vec::new(),
                        anchor_hash: Bytes::from(hash.to_byte_array().to_vec()),
                        is_block: true,
                    },
                };
                Ok(Self::Proto {
                    part: Some(Part::Data(proto_data)),
                })
            }
            Self::Fin(fin) => Ok(Self::Proto {
                part: Some(Part::Fin(proto::ProposalFin {
                    signature: Some(encode_signature(&fin.signature)),
                })),
            }),
        }
    }
}
