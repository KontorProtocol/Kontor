use core::fmt;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use bytes::Bytes;
use malachitebft_proto::{Error as ProtoError, Protobuf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::consensus::proto;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Serialize, Deserialize)]
pub struct ValueId(pub [u8; 32]);

impl ValueId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl Protobuf for ValueId {
    type Proto = proto::ValueId;

    fn from_proto(proto: Self::Proto) -> Result<Self, ProtoError> {
        let bytes = proto
            .value
            .ok_or_else(|| ProtoError::missing_field::<Self::Proto>("value"))?;

        let arr = <[u8; 32]>::try_from(bytes.as_ref()).map_err(|_| {
            ProtoError::Other(format!(
                "Invalid ValueId length: got {} bytes, expected 32",
                bytes.len()
            ))
        })?;

        Ok(ValueId(arr))
    }

    fn to_proto(&self) -> Result<Self::Proto, ProtoError> {
        Ok(proto::ValueId {
            value: Some(self.0.to_vec().into()),
        })
    }
}

/// A consensus decision: either a batch of mempool transactions or a block confirmation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Value {
    /// A batch of mempool transactions to execute, anchored at a specific block.
    Batch {
        anchor_height: u64,
        anchor_hash: BlockHash,
        txids: Vec<Txid>,
        /// Full raw transactions, included only in sync responses for unfinalized batches.
        /// Not part of Value::id() — the certificate signs txids only.
        #[serde(skip)]
        raw_txs: Option<Vec<bitcoin::Transaction>>,
    },
    /// A Bitcoin block to execute. All validators agree to process this block.
    Block { height: u64, hash: BlockHash },
}

impl Value {
    pub fn new_batch(anchor_height: u64, anchor_hash: BlockHash, txids: Vec<Txid>) -> Self {
        Self::Batch {
            anchor_height,
            anchor_hash,
            txids,
            raw_txs: None,
        }
    }

    pub fn new_block(height: u64, hash: BlockHash) -> Self {
        Self::Block { height, hash }
    }

    /// Stable identity hash.
    pub fn id(&self) -> ValueId {
        let mut hasher = Sha256::new();
        match self {
            Value::Batch {
                anchor_height,
                anchor_hash,
                txids,
                ..
            } => {
                hasher.update([0u8]); // discriminant
                hasher.update(anchor_height.to_be_bytes());
                hasher.update(anchor_hash.to_byte_array());
                for txid in txids {
                    hasher.update(txid.to_byte_array());
                }
            }
            Value::Block { height, hash } => {
                hasher.update([1u8]); // discriminant
                hasher.update(height.to_be_bytes());
                hasher.update(hash.to_byte_array());
            }
        }
        ValueId(hasher.finalize().into())
    }

    pub fn size_bytes(&self) -> usize {
        match self {
            Value::Batch { txids, .. } => 1 + 8 + 32 + txids.len() * 32,
            Value::Block { .. } => 1 + 8 + 32,
        }
    }

    /// The Bitcoin block height this value references.
    /// For batches: the anchor height. For blocks: the block height.
    pub fn block_height(&self) -> u64 {
        match self {
            Value::Batch { anchor_height, .. } => *anchor_height,
            Value::Block { height, .. } => *height,
        }
    }

    /// The Bitcoin block hash this value references.
    pub fn block_hash(&self) -> BlockHash {
        match self {
            Value::Batch { anchor_hash, .. } => *anchor_hash,
            Value::Block { hash, .. } => *hash,
        }
    }

    /// Returns the txids if this is a Batch, empty slice if Block.
    pub fn batch_txids(&self) -> &[Txid] {
        match self {
            Value::Batch { txids, .. } => txids,
            Value::Block { .. } => &[],
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(self, Value::Block { .. })
    }

    pub fn is_batch(&self) -> bool {
        matches!(self, Value::Batch { .. })
    }
}

impl malachitebft_core_types::Value for Value {
    type Id = ValueId;

    fn id(&self) -> ValueId {
        self.id()
    }
}

impl Protobuf for Value {
    type Proto = proto::Value;

    fn from_proto(proto: Self::Proto) -> Result<Self, ProtoError> {
        let bytes = proto
            .value
            .ok_or_else(|| ProtoError::missing_field::<Self::Proto>("value"))?;

        if bytes.is_empty() {
            return Err(ProtoError::Other("Empty Value bytes".to_string()));
        }

        match bytes[0] {
            0 => {
                // Batch: discriminant(1) + height(8) + hash(32) + txids(N*32)
                let data = &bytes[1..];
                if data.len() < 40 {
                    return Err(ProtoError::Other(format!(
                        "Too few bytes for Batch Value, expected at least 41, got {}",
                        bytes.len()
                    )));
                }
                let anchor_height = u64::from_be_bytes(data[..8].try_into().unwrap());
                let anchor_hash_arr: [u8; 32] = data[8..40].try_into().unwrap();
                let anchor_hash = BlockHash::from_byte_array(anchor_hash_arr);
                let remaining = &data[40..];

                if remaining.len() % 32 != 0 {
                    return Err(ProtoError::Other(format!(
                        "Txid data not a multiple of 32 bytes: got {}",
                        remaining.len()
                    )));
                }

                let txids = remaining
                    .chunks_exact(32)
                    .map(|chunk| {
                        let arr: [u8; 32] = chunk.try_into().unwrap();
                        Txid::from_byte_array(arr)
                    })
                    .collect();

                Ok(Value::Batch {
                    anchor_height,
                    anchor_hash,
                    txids,
                    raw_txs: None,
                })
            }
            1 => {
                // Block: discriminant(1) + height(8) + hash(32)
                let data = &bytes[1..];
                if data.len() != 40 {
                    return Err(ProtoError::Other(format!(
                        "Invalid Block Value length: expected 41, got {}",
                        bytes.len()
                    )));
                }
                let height = u64::from_be_bytes(data[..8].try_into().unwrap());
                let hash_arr: [u8; 32] = data[8..40].try_into().unwrap();
                let hash = BlockHash::from_byte_array(hash_arr);
                Ok(Value::Block { height, hash })
            }
            d => Err(ProtoError::Other(format!(
                "Unknown Value discriminant: {d}"
            ))),
        }
    }

    fn to_proto(&self) -> Result<Self::Proto, ProtoError> {
        let buf = match self {
            Value::Batch {
                anchor_height,
                anchor_hash,
                txids,
                ..
            } => {
                let mut buf = Vec::with_capacity(1 + 40 + txids.len() * 32);
                buf.push(0); // discriminant
                buf.extend_from_slice(&anchor_height.to_be_bytes());
                buf.extend_from_slice(&anchor_hash.to_byte_array());
                for txid in txids {
                    buf.extend_from_slice(&txid.to_byte_array());
                }
                buf
            }
            Value::Block { height, hash } => {
                let mut buf = Vec::with_capacity(1 + 40);
                buf.push(1); // discriminant
                buf.extend_from_slice(&height.to_be_bytes());
                buf.extend_from_slice(&hash.to_byte_array());
                buf
            }
        };
        Ok(proto::Value {
            value: Some(Bytes::from(buf)),
        })
    }
}
