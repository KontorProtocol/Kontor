use core::fmt;

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

/// The value to decide on: an anchor bitcoin block height + set of txids.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Value {
    pub anchor_height: u64,
    pub txids: Vec<[u8; 32]>,
}

impl Value {
    pub fn new(anchor_height: u64, txids: Vec<[u8; 32]>) -> Self {
        Self {
            anchor_height,
            txids,
        }
    }

    pub fn id(&self) -> ValueId {
        let mut hasher = Sha256::new();
        hasher.update(self.anchor_height.to_be_bytes());
        for txid in &self.txids {
            hasher.update(txid);
        }
        ValueId(hasher.finalize().into())
    }

    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<u64>() + self.txids.len() * 32
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

        if bytes.len() < 8 {
            return Err(ProtoError::Other(format!(
                "Too few bytes for Value, expected at least 8, got {}",
                bytes.len()
            )));
        }

        let anchor_height = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let rest = &bytes[8..];

        if rest.len() % 32 != 0 {
            return Err(ProtoError::Other(format!(
                "Invalid txids length: {} is not a multiple of 32",
                rest.len()
            )));
        }

        let txids: Vec<[u8; 32]> = rest
            .chunks_exact(32)
            .map(|chunk| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk);
                arr
            })
            .collect();

        Ok(Value {
            anchor_height,
            txids,
        })
    }

    fn to_proto(&self) -> Result<Self::Proto, ProtoError> {
        let mut buf = Vec::with_capacity(8 + self.txids.len() * 32);
        buf.extend_from_slice(&self.anchor_height.to_be_bytes());
        for txid in &self.txids {
            buf.extend_from_slice(txid);
        }
        Ok(proto::Value {
            value: Some(Bytes::from(buf)),
        })
    }
}
