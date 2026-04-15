use core::fmt;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use malachitebft_proto::{Error as ProtoError, Protobuf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::consensus::proto;

/// A transaction in a batch: either just the txid (for finalized/live) or the full raw transaction
/// (for sync of unfinalized batches). Both variants produce the same txid for Value::id().
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BatchTx {
    Id(Txid),
    Raw(bitcoin::Transaction),
}

impl BatchTx {
    pub fn txid(&self) -> Txid {
        match self {
            BatchTx::Id(txid) => *txid,
            BatchTx::Raw(tx) => tx.compute_txid(),
        }
    }
}

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
    /// Each tx is either a txid (finalized/live) or a full raw transaction (sync of unfinalized).
    Batch {
        anchor_height: u64,
        anchor_hash: BlockHash,
        txs: Vec<BatchTx>,
    },
    /// A Bitcoin block to execute. All validators agree to process this block.
    Block { height: u64, hash: BlockHash },
}

impl Value {
    pub fn new_batch(anchor_height: u64, anchor_hash: BlockHash, txids: Vec<Txid>) -> Self {
        Self::Batch {
            anchor_height,
            anchor_hash,
            txs: txids.into_iter().map(BatchTx::Id).collect(),
        }
    }

    pub fn new_batch_raw(
        anchor_height: u64,
        anchor_hash: BlockHash,
        txs: Vec<bitcoin::Transaction>,
    ) -> Self {
        Self::Batch {
            anchor_height,
            anchor_hash,
            txs: txs.into_iter().map(BatchTx::Raw).collect(),
        }
    }

    pub fn new_block(height: u64, hash: BlockHash) -> Self {
        Self::Block { height, hash }
    }

    /// Extract full raw transactions from a batch. Returns empty vec for blocks
    /// or batches that only contain txids.
    pub fn batch_raw_txs(&self) -> Vec<bitcoin::Transaction> {
        match self {
            Value::Batch { txs, .. } => txs
                .iter()
                .filter_map(|tx| match tx {
                    BatchTx::Raw(raw) => Some(raw.clone()),
                    BatchTx::Id(_) => None,
                })
                .collect(),
            Value::Block { .. } => vec![],
        }
    }

    /// Stable identity hash — always based on txids regardless of BatchTx variant.
    pub fn id(&self) -> ValueId {
        let mut hasher = Sha256::new();
        match self {
            Value::Batch {
                anchor_height,
                anchor_hash,
                txs,
            } => {
                hasher.update([0u8]); // discriminant
                hasher.update(anchor_height.to_be_bytes());
                hasher.update(anchor_hash.to_byte_array());
                for tx in txs {
                    hasher.update(tx.txid().to_byte_array());
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
            Value::Batch { txs, .. } => {
                let tx_size: usize = txs
                    .iter()
                    .map(|tx| match tx {
                        BatchTx::Id(_) => 32,
                        BatchTx::Raw(raw) => bitcoin::consensus::serialize(raw).len(),
                    })
                    .sum();
                1 + 8 + 32 + tx_size
            }
            Value::Block { .. } => 1 + 8 + 32,
        }
    }

    pub fn block_height(&self) -> u64 {
        match self {
            Value::Batch { anchor_height, .. } => *anchor_height,
            Value::Block { height, .. } => *height,
        }
    }

    pub fn block_hash(&self) -> BlockHash {
        match self {
            Value::Batch { anchor_hash, .. } => *anchor_hash,
            Value::Block { hash, .. } => *hash,
        }
    }

    /// Returns the txids for a batch (derived from each BatchTx).
    pub fn batch_txids(&self) -> Vec<Txid> {
        match self {
            Value::Batch { txs, .. } => txs.iter().map(|tx| tx.txid()).collect(),
            Value::Block { .. } => vec![],
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(self, Value::Block { .. })
    }

    pub fn is_batch(&self) -> bool {
        matches!(self, Value::Batch { .. })
    }

    /// Upgrade BatchTx::Id entries to BatchTx::Raw where a matching raw tx
    /// is available. Entries without a match keep their BatchTx::Id — this
    /// preserves the Value's identity (id() hash) even if some raw txs
    /// failed to deserialize.
    pub fn set_raw_txs(&mut self, raw_txs: Vec<bitcoin::Transaction>) {
        if let Value::Batch { txs, .. } = self {
            let raw_map: std::collections::HashMap<Txid, bitcoin::Transaction> = raw_txs
                .into_iter()
                .map(|tx| (tx.compute_txid(), tx))
                .collect();
            for entry in txs.iter_mut() {
                if let BatchTx::Id(txid) = entry
                    && let Some(raw) = raw_map.get(txid)
                {
                    *entry = BatchTx::Raw(raw.clone());
                }
            }
        }
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
        let kind = proto
            .kind
            .ok_or_else(|| ProtoError::missing_field::<Self::Proto>("kind"))?;

        match kind {
            proto::value::Kind::Batch(batch) => {
                let anchor_height = batch.anchor_height;
                let anchor_hash_arr: [u8; 32] = (&*batch.anchor_hash)
                    .try_into()
                    .map_err(|_| ProtoError::Other("Invalid anchor_hash length".to_string()))?;
                let anchor_hash = BlockHash::from_byte_array(anchor_hash_arr);

                let txs: Vec<BatchTx> = batch
                    .txs
                    .into_iter()
                    .map(|btx| {
                        let tx = btx
                            .tx
                            .ok_or_else(|| ProtoError::missing_field::<proto::BatchTx>("tx"))?;
                        match tx {
                            proto::batch_tx::Tx::Txid(bytes) => {
                                let arr: [u8; 32] = (&*bytes).try_into().map_err(|_| {
                                    ProtoError::Other("Invalid txid length".to_string())
                                })?;
                                Ok(BatchTx::Id(Txid::from_byte_array(arr)))
                            }
                            proto::batch_tx::Tx::RawTx(bytes) => {
                                let tx = bitcoin::consensus::deserialize(&bytes).map_err(|e| {
                                    ProtoError::Other(format!("Invalid raw tx: {e}"))
                                })?;
                                Ok(BatchTx::Raw(tx))
                            }
                        }
                    })
                    .collect::<Result<Vec<_>, ProtoError>>()?;

                Ok(Value::Batch {
                    anchor_height,
                    anchor_hash,
                    txs,
                })
            }
            proto::value::Kind::Block(block) => {
                let hash_arr: [u8; 32] = (&*block.hash)
                    .try_into()
                    .map_err(|_| ProtoError::Other("Invalid block hash length".to_string()))?;
                let hash = BlockHash::from_byte_array(hash_arr);
                Ok(Value::Block {
                    height: block.height,
                    hash,
                })
            }
        }
    }

    fn to_proto(&self) -> Result<Self::Proto, ProtoError> {
        let kind = match self {
            Value::Batch {
                anchor_height,
                anchor_hash,
                txs,
            } => {
                let proto_txs = txs
                    .iter()
                    .map(|tx| {
                        let inner = match tx {
                            BatchTx::Id(txid) => {
                                proto::batch_tx::Tx::Txid(txid.to_byte_array().to_vec().into())
                            }
                            BatchTx::Raw(raw) => proto::batch_tx::Tx::RawTx(
                                bitcoin::consensus::serialize(raw).into(),
                            ),
                        };
                        proto::BatchTx { tx: Some(inner) }
                    })
                    .collect();

                proto::value::Kind::Batch(proto::BatchValue {
                    anchor_height: *anchor_height,
                    anchor_hash: anchor_hash.to_byte_array().to_vec().into(),
                    txs: proto_txs,
                })
            }
            Value::Block { height, hash } => proto::value::Kind::Block(proto::BlockValue {
                height: *height,
                hash: hash.to_byte_array().to_vec().into(),
            }),
        };
        Ok(proto::Value { kind: Some(kind) })
    }
}
