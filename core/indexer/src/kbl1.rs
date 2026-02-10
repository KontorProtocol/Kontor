use anyhow::{Context, Result, anyhow, ensure};
use indexer_types::{ContractAddress, Signer, deserialize, serialize};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::io::{Cursor, Read};

pub const KBL1_MAGIC: &[u8; 4] = b"KBL1";
pub const KBL1_SIG_LEN: usize = 48;

// Hardening limits for decoding.
pub const MAX_DECOMPRESSED_OPS_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OPS_PER_BATCH: usize = 10_000;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kbl1OpV1 {
    Call {
        signer: Signer,
        gas_limit: u64,
        #[serde_as(as = "DisplayFromStr")]
        contract: ContractAddress,
        expr: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kbl1BatchV1 {
    pub signature: [u8; KBL1_SIG_LEN],
    pub ops: Vec<Kbl1OpV1>,
}

pub fn decode_kbl1_v1(payload: &[u8]) -> Result<Kbl1BatchV1> {
    ensure!(payload.starts_with(KBL1_MAGIC), "missing KBL1 magic");
    ensure!(
        payload.len() >= 4 + 4 + KBL1_SIG_LEN,
        "KBL1 payload too short"
    );

    let compressed_len = u32::from_le_bytes(
        payload[4..8]
            .try_into()
            .map_err(|_| anyhow!("invalid compressed length"))?,
    ) as usize;

    let compressed_start = 8;
    let compressed_end = compressed_start + compressed_len;
    ensure!(
        payload.len() >= compressed_end + KBL1_SIG_LEN,
        "KBL1 payload truncated"
    );
    ensure!(
        payload.len() == compressed_end + KBL1_SIG_LEN,
        "KBL1 payload has trailing bytes"
    );

    let compressed = &payload[compressed_start..compressed_end];
    let signature: [u8; KBL1_SIG_LEN] = payload[compressed_end..compressed_end + KBL1_SIG_LEN]
        .try_into()
        .map_err(|_| anyhow!("invalid KBL1 signature length"))?;

    let decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed))
        .context("KBL1 zstd decoder init failed")?;
    let mut ops_bytes = Vec::new();
    decoder
        .take((MAX_DECOMPRESSED_OPS_BYTES + 1) as u64)
        .read_to_end(&mut ops_bytes)
        .context("KBL1 zstd decompress failed")?;
    ensure!(
        ops_bytes.len() <= MAX_DECOMPRESSED_OPS_BYTES,
        "KBL1 decompressed ops too large"
    );

    let ops =
        deserialize::<Vec<Kbl1OpV1>>(&ops_bytes).context("KBL1 ops postcard decode failed")?;
    ensure!(ops.len() <= MAX_OPS_PER_BATCH, "KBL1 too many ops");

    Ok(Kbl1BatchV1 { signature, ops })
}

pub fn encode_kbl1_v1(
    ops: &[Kbl1OpV1],
    signature: [u8; KBL1_SIG_LEN],
    zstd_level: i32,
) -> Result<Vec<u8>> {
    let ops_bytes = serialize(&ops).context("KBL1 ops postcard encode failed")?;
    let compressed = zstd::stream::encode_all(Cursor::new(ops_bytes), zstd_level)
        .context("KBL1 zstd compress failed")?;
    ensure!(
        compressed.len() <= u32::MAX as usize,
        "KBL1 compressed ops too large"
    );

    let mut out = Vec::with_capacity(4 + 4 + compressed.len() + KBL1_SIG_LEN);
    out.extend_from_slice(KBL1_MAGIC);
    out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    out.extend_from_slice(&compressed);
    out.extend_from_slice(&signature);
    Ok(out)
}

