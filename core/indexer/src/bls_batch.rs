use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

pub const KBL1_MAGIC: &[u8; 4] = b"KBL1";
pub const PROTOCOL_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

pub const POP_PREFIX: &[u8] = b"KONTOR-POP-V1";
pub const OP_PREFIX: &[u8] = b"KONTOR-OP-V1";

pub const BLS_PUBKEY_LEN: usize = 96;
pub const BLS_SIG_LEN: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kbl1Batch {
    pub compressed_calls: Vec<u8>,
    pub aggregate_signature: [u8; BLS_SIG_LEN],
    pub new_signers: Vec<[u8; BLS_PUBKEY_LEN]>,
}

pub fn parse_kbl1_batch(payload: &[u8]) -> Result<Kbl1Batch> {
    if payload.len() < 4 + 4 {
        bail!("KBL1 payload too short");
    }
    if &payload[..4] != KBL1_MAGIC {
        bail!("not a KBL1 payload");
    }

    let mut offset = 4;
    let compressed_len = u32::from_le_bytes(
        payload
            .get(offset..offset + 4)
            .ok_or_else(|| anyhow!("missing compressed_calls_len"))?
            .try_into()
            .expect("slice is 4 bytes"),
    ) as usize;
    offset += 4;

    let compressed_calls = payload
        .get(offset..offset + compressed_len)
        .ok_or_else(|| anyhow!("compressed_calls out of bounds"))?
        .to_vec();
    offset += compressed_len;

    let aggregate_signature: [u8; BLS_SIG_LEN] = payload
        .get(offset..offset + BLS_SIG_LEN)
        .ok_or_else(|| anyhow!("aggregate_signature out of bounds"))?
        .try_into()
        .expect("slice is 48 bytes");
    offset += BLS_SIG_LEN;

    let new_signers_len = u32::from_le_bytes(
        payload
            .get(offset..offset + 4)
            .ok_or_else(|| anyhow!("missing new_signers_len"))?
            .try_into()
            .expect("slice is 4 bytes"),
    ) as usize;
    offset += 4;

    let new_signers_bytes = payload
        .get(offset..offset + new_signers_len)
        .ok_or_else(|| anyhow!("new_signers out of bounds"))?;
    offset += new_signers_len;

    if offset != payload.len() {
        bail!("trailing bytes after KBL1 payload");
    }
    if new_signers_len % BLS_PUBKEY_LEN != 0 {
        bail!("new_signers_len must be a multiple of {BLS_PUBKEY_LEN}");
    }

    let mut new_signers = Vec::with_capacity(new_signers_len / BLS_PUBKEY_LEN);
    for chunk in new_signers_bytes.chunks(BLS_PUBKEY_LEN) {
        let pk: [u8; BLS_PUBKEY_LEN] = chunk.try_into().expect("chunk size is 96");
        new_signers.push(pk);
    }

    Ok(Kbl1Batch {
        compressed_calls,
        aggregate_signature,
        new_signers,
    })
}

pub fn decompress_calls_zstd(compressed: &[u8]) -> Result<Vec<u8>> {
    Ok(zstd::stream::decode_all(Cursor::new(compressed))?)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignerRef {
    RegistryId(u32),
    BundleIndex(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryCallV1 {
    pub signer: SignerRef,
    pub contract_id: u32,
    pub function_index: u16,
    pub args: Vec<u8>,
    pub nonce: u64,
    pub gas_limit: u64,
}

#[derive(Debug, Clone)]
pub struct ParsedCall {
    pub call: BinaryCallV1,
    pub bytes: Vec<u8>,
}

pub fn parse_concatenated_calls(bytes: &[u8]) -> Result<Vec<ParsedCall>> {
    let mut remaining = bytes;
    let mut out = Vec::new();

    while !remaining.is_empty() {
        let before_len = remaining.len();
        let (call, rest) = postcard::take_from_bytes::<BinaryCallV1>(remaining)?;
        let consumed_len = before_len
            .checked_sub(rest.len())
            .ok_or_else(|| anyhow!("postcard parser length underflow"))?;
        let consumed = remaining
            .get(..consumed_len)
            .ok_or_else(|| anyhow!("postcard consumed slice out of bounds"))?
            .to_vec();
        out.push(ParsedCall {
            call,
            bytes: consumed,
        });
        remaining = rest;
    }

    Ok(out)
}

pub fn pop_message(pubkey_bytes: &[u8; BLS_PUBKEY_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(POP_PREFIX.len() + BLS_PUBKEY_LEN);
    out.extend_from_slice(POP_PREFIX);
    out.extend_from_slice(pubkey_bytes);
    out
}

pub fn op_message(op_index: u32, call_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(OP_PREFIX.len() + 4 + call_bytes.len());
    out.extend_from_slice(OP_PREFIX);
    out.extend_from_slice(&op_index.to_le_bytes());
    out.extend_from_slice(call_bytes);
    out
}
