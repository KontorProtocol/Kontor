use std::collections::BTreeSet;

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, Transaction};

use crate::protocol::canonical_codec::{CodecError, Decoder, Encoder};
use crate::protocol::identity::{ChainId, ProtocolId, domain_digest};

pub(crate) const MAX_DESCRIPTOR_BYTES: usize = 1024;
pub(crate) const MAX_BATCH_BYTES: usize = 4_186_112;
pub(crate) const MAX_BITCOIN_BYTES: usize = 4_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EraContext {
    pub(crate) chain: ChainId,
    pub(crate) era: [u8; 32],
    pub(crate) protocol: ProtocolId,
    pub(crate) codec: u32,
}

impl EraContext {
    pub(crate) fn encode(self, output: &mut Encoder) -> Result<(), CodecError> {
        output.fixed(&self.chain.0)?;
        output.fixed(&self.era)?;
        output.fixed(&self.protocol.0)?;
        output.fixed(&self.codec.to_be_bytes())
    }

    pub(crate) fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            chain: ChainId(input.fixed()?),
            era: input.fixed()?,
            protocol: ProtocolId(input.fixed()?),
            codec: u32::from_be_bytes(input.fixed()?),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Batch {
        anchor_height: u64,
        anchor_hash: BlockHash,
    },
    Block {
        height: u64,
        hash: BlockHash,
        parent: BlockHash,
        header: [u8; 80],
    },
}

impl Command {
    pub(crate) fn position(&self) -> (u64, BlockHash, bool) {
        match self {
            Self::Block { height, hash, .. } => (*height, *hash, true),
            Self::Batch {
                anchor_height,
                anchor_hash,
            } => (*anchor_height, *anchor_hash, false),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub(crate) context: EraContext,
    pub(crate) command: Command,
    pub(crate) input_count: u32,
    pub(crate) body_length: u32,
    pub(crate) body_digest: [u8; 32],
}

impl Descriptor {
    fn validate(&self) -> Result<(), CodecError> {
        if self.context.codec != 1 {
            return Err(CodecError::InvalidTag);
        }
        let length = self.body_length as usize;
        match &self.command {
            Command::Batch { .. } => {
                if !(4..=MAX_BATCH_BYTES).contains(&length)
                    || self.input_count as usize > (length - 4) / 4
                {
                    return Err(CodecError::InvalidValue);
                }
            }
            Command::Block {
                hash,
                parent,
                header,
                ..
            } => {
                if !(81..=MAX_BITCOIN_BYTES).contains(&length)
                    || self.input_count == 0
                    || self.input_count as usize > (length - 80) / 10
                {
                    return Err(CodecError::InvalidValue);
                }
                let header: Header = deserialize(header).map_err(|_| CodecError::InvalidValue)?;
                if header.block_hash() != *hash || header.prev_blockhash != *parent {
                    return Err(CodecError::InvalidValue);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut output = Encoder::default();
        output.fixed(b"KVD1")?;
        self.context.encode(&mut output)?;
        match &self.command {
            Command::Batch {
                anchor_height,
                anchor_hash,
            } => {
                output.tag(0)?;
                output.u64(*anchor_height)?;
                output.fixed(&anchor_hash.to_byte_array())?;
            }
            Command::Block {
                height,
                hash,
                parent,
                header,
            } => {
                output.tag(1)?;
                output.u64(*height)?;
                output.fixed(&hash.to_byte_array())?;
                output.fixed(&parent.to_byte_array())?;
                output.fixed(header)?;
            }
        }
        output.fixed(&self.input_count.to_be_bytes())?;
        output.fixed(&self.body_length.to_be_bytes())?;
        output.fixed(&self.body_digest)?;
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(CodecError::LengthOverflow);
        }
        let mut input = Decoder::new(bytes);
        if input.fixed::<4>()? != *b"KVD1" {
            return Err(CodecError::InvalidTag);
        }
        let context = EraContext::decode(&mut input)?;
        let command = match input.tag()? {
            0 => Command::Batch {
                anchor_height: input.u64()?,
                anchor_hash: BlockHash::from_byte_array(input.fixed()?),
            },
            1 => Command::Block {
                height: input.u64()?,
                hash: BlockHash::from_byte_array(input.fixed()?),
                parent: BlockHash::from_byte_array(input.fixed()?),
                header: input.fixed()?,
            },
            _ => return Err(CodecError::InvalidTag),
        };
        let value = Self {
            context,
            command,
            input_count: u32::from_be_bytes(input.fixed()?),
            body_length: u32::from_be_bytes(input.fixed()?),
            body_digest: input.fixed()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn id(&self) -> Result<[u8; 32], CodecError> {
        Ok(domain_digest(b"kontor/certified-value/v1", &self.encode()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExactInput {
    descriptor: Descriptor,
    body: Vec<u8>,
}

impl ExactInput {
    pub(crate) fn batch(
        context: EraContext,
        anchor_height: u64,
        anchor_hash: BlockHash,
        transactions: &[Transaction],
    ) -> Result<Self, CodecError> {
        let size = transactions.iter().try_fold(4usize, |total, tx| {
            let length = tx.total_size();
            if length > MAX_BITCOIN_BYTES {
                return Err(CodecError::LengthOverflow);
            }
            total
                .checked_add(4)
                .and_then(|total| total.checked_add(length))
                .filter(|total| *total <= MAX_BATCH_BYTES)
                .ok_or(CodecError::LengthOverflow)
        })?;
        let mut body = Encoder::default();
        body.count(transactions.len())?;
        for transaction in transactions {
            body.bytes(&serialize(transaction))?;
        }
        let body = body.finish();
        if body.len() != size {
            return Err(CodecError::InvalidValue);
        }
        let descriptor = Descriptor {
            context,
            command: Command::Batch {
                anchor_height,
                anchor_hash,
            },
            input_count: u32::try_from(transactions.len())
                .map_err(|_| CodecError::LengthOverflow)?,
            body_length: size as u32,
            body_digest: body_digest(&body),
        };
        Self::validate(descriptor, body)
    }

    pub(crate) fn block(
        context: EraContext,
        height: u64,
        body: Vec<u8>,
    ) -> Result<Self, CodecError> {
        let block = decode_block(&body)?;
        let descriptor = Descriptor {
            context,
            command: Command::Block {
                height,
                hash: block.block_hash(),
                parent: block.header.prev_blockhash,
                header: serialize(&block.header)
                    .try_into()
                    .map_err(|_| CodecError::InvalidValue)?,
            },
            input_count: u32::try_from(block.txdata.len())
                .map_err(|_| CodecError::LengthOverflow)?,
            body_length: body.len() as u32,
            body_digest: body_digest(&body),
        };
        descriptor.validate()?;
        Ok(Self { descriptor, body })
    }

    pub(crate) fn validate(descriptor: Descriptor, body: Vec<u8>) -> Result<Self, CodecError> {
        descriptor.validate()?;
        if body.len() != descriptor.body_length as usize
            || body_digest(&body) != descriptor.body_digest
        {
            return Err(CodecError::InvalidValue);
        }
        match &descriptor.command {
            Command::Batch { .. } => {
                if decode_batch(&body)?.len() != descriptor.input_count as usize {
                    return Err(CodecError::InvalidValue);
                }
            }
            Command::Block { header, .. } => {
                let block = decode_block(&body)?;
                if block.txdata.len() != descriptor.input_count as usize || &body[..80] != header {
                    return Err(CodecError::InvalidValue);
                }
            }
        }
        Ok(Self { descriptor, body })
    }

    pub(crate) fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn transactions(&self) -> Result<Vec<Transaction>, CodecError> {
        match self.descriptor.command {
            Command::Batch { .. } => decode_batch(&self.body),
            Command::Block { .. } => Ok(decode_block(&self.body)?.txdata),
        }
    }
}

fn body_digest(bytes: &[u8]) -> [u8; 32] {
    domain_digest(b"kontor/certified-input-body/v1", bytes)
}

fn decode_batch(bytes: &[u8]) -> Result<Vec<Transaction>, CodecError> {
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(CodecError::LengthOverflow);
    }
    let mut input = Decoder::new(bytes);
    let count = input.count(4)?;
    // A count prefix is not allocation authority. Reserve only for entries whose
    // complete length-delimited transaction has actually decoded successfully.
    let mut transactions = Vec::new();
    for _ in 0..count {
        let bytes = input.bytes()?;
        if bytes.len() > MAX_BITCOIN_BYTES {
            return Err(CodecError::LengthOverflow);
        }
        let transaction: Transaction = deserialize(bytes).map_err(|_| CodecError::InvalidValue)?;
        if serialize(&transaction) != bytes {
            return Err(CodecError::InvalidValue);
        }
        transactions
            .try_reserve(1)
            .map_err(|_| CodecError::Allocation)?;
        transactions.push(transaction);
    }
    input.finish()?;
    Ok(transactions)
}

fn decode_block(bytes: &[u8]) -> Result<Block, CodecError> {
    if bytes.len() > MAX_BITCOIN_BYTES {
        return Err(CodecError::LengthOverflow);
    }
    let block: Block = deserialize(bytes).map_err(|_| CodecError::InvalidValue)?;
    let coinbase = block.txdata.first().ok_or(CodecError::InvalidValue)?;
    let committed_witness = coinbase.output.iter().any(|output| {
        let script = output.script_pubkey.as_bytes();
        script.len() >= 38 && script.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
    });
    // rust-bitcoin accepts witness-free blocks before inspecting their commitment
    // output. Retained history must reject a stripped committed SegWit body.
    let stripped = committed_witness
        && block
            .txdata
            .iter()
            .all(|tx| tx.input.iter().all(|input| input.witness.is_empty()));
    let mut txids = BTreeSet::new();
    if serialize(&block) != bytes
        || block.weight().to_wu() > 4_000_000
        || !coinbase.is_coinbase()
        || block.txdata.iter().skip(1).any(Transaction::is_coinbase)
        || !block
            .txdata
            .iter()
            .all(|tx| txids.insert(tx.compute_txid()))
        || !block.check_merkle_root()
        || !block.check_witness_commitment()
        || stripped
    {
        return Err(CodecError::InvalidValue);
    }
    Ok(block)
}

#[cfg(test)]
mod tests;
