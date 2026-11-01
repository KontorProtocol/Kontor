use core::fmt;
use std::cmp::Ordering;
use std::sync::Arc;

use bitcoin::{BlockHash, Transaction, Txid};
use malachitebft_proto::{Error as ProtoError, Protobuf};
use serde::{Deserialize, Serialize};

use crate::consensus::proto;
use crate::protocol::canonical_codec::CodecError;
use crate::protocol::coordinator::certified_input::{
    Command, Descriptor, EraContext, ExactInput, MAX_BATCH_BYTES, MAX_DESCRIPTOR_BYTES,
};

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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "ValueWire", into = "ValueWire")]
pub struct Value(Arc<AvailableValue>);

#[derive(Debug)]
struct AvailableValue {
    input: ExactInput,
    descriptor: Vec<u8>,
    id: ValueId,
    transactions: Vec<Transaction>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueWire {
    descriptor: Vec<u8>,
    body: Vec<u8>,
}

impl TryFrom<ValueWire> for Value {
    type Error = CodecError;

    fn try_from(wire: ValueWire) -> Result<Self, Self::Error> {
        Self::from_input(ExactInput::validate(
            Descriptor::decode(&wire.descriptor)?,
            wire.body,
        )?)
    }
}

impl From<Value> for ValueWire {
    fn from(value: Value) -> Self {
        Self {
            descriptor: value.0.descriptor.clone(),
            body: value.0.input.body().to_vec(),
        }
    }
}

impl Value {
    pub(crate) fn from_input(input: ExactInput) -> Result<Self, CodecError> {
        let descriptor = input.descriptor().encode()?;
        let id = ValueId(input.descriptor().id()?);
        let transactions = input.transactions()?;
        Ok(Self(Arc::new(AvailableValue {
            input,
            descriptor,
            id,
            transactions,
        })))
    }

    pub(crate) fn new_batch_raw(
        context: EraContext,
        anchor_height: u64,
        anchor_hash: BlockHash,
        txs: Vec<Transaction>,
    ) -> Result<Self, CodecError> {
        Self::from_input(ExactInput::batch(
            context,
            anchor_height,
            anchor_hash,
            &txs,
        )?)
    }

    pub(crate) fn input(&self) -> &ExactInput {
        &self.0.input
    }
    pub(crate) fn descriptor(&self) -> &Descriptor {
        self.0.input.descriptor()
    }
    pub(crate) fn descriptor_bytes(&self) -> &[u8] {
        &self.0.descriptor
    }
    pub(crate) fn command(&self) -> &Command {
        &self.descriptor().command
    }

    pub fn batch_raw_txs(&self) -> Vec<Transaction> {
        if self.is_batch() {
            self.0.transactions.clone()
        } else {
            Vec::new()
        }
    }

    pub fn id(&self) -> ValueId {
        self.0.id
    }

    pub fn size_bytes(&self) -> usize {
        self.0.descriptor.len() + self.0.input.body().len()
    }

    pub fn block_height(&self) -> u64 {
        match self.command() {
            Command::Batch { anchor_height, .. } => *anchor_height,
            Command::Block { height, .. } => *height,
        }
    }

    pub fn block_hash(&self) -> BlockHash {
        match self.command() {
            Command::Batch { anchor_hash, .. } => *anchor_hash,
            Command::Block { hash, .. } => *hash,
        }
    }

    pub fn batch_txids(&self) -> Vec<Txid> {
        if self.is_batch() {
            self.0
                .transactions
                .iter()
                .map(Transaction::compute_txid)
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(self.command(), Command::Block { .. })
    }
    pub fn is_batch(&self) -> bool {
        matches!(self.command(), Command::Batch { .. })
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.0.descriptor == other.0.descriptor
    }
}
impl Eq for Value {}
impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.descriptor.cmp(&other.0.descriptor)
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
        if proto.descriptor.len() > MAX_DESCRIPTOR_BYTES || proto.body.len() > MAX_BATCH_BYTES {
            return Err(ProtoError::Other(
                "certified value exceeds framing limit".into(),
            ));
        }
        ValueWire {
            descriptor: proto.descriptor.to_vec(),
            body: proto.body.to_vec(),
        }
        .try_into()
        .map_err(|error| ProtoError::Other(format!("invalid certified value: {error}")))
    }

    fn to_proto(&self) -> Result<Self::Proto, ProtoError> {
        Ok(proto::Value {
            descriptor: self.0.descriptor.clone().into(),
            body: self.0.input.body().to_vec().into(),
        })
    }
}
