use std::io::Read;
use std::ops::Range;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

pub const KBL1_MAGIC: &[u8; 4] = b"KBL1";
const MAX_DECOMPRESSED_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Prefix for the signed message bytes of a KBL1 call op.
///
/// This is *domain separation* at the message level (the BLS DST stays constant).
pub const KONTOR_KBL1_CALL_MESSAGE_PREFIX: &[u8] = b"KONTOR_OP_V1";

pub fn kbl1_message_for_op_bytes(op_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(KONTOR_KBL1_CALL_MESSAGE_PREFIX.len() + op_bytes.len());
    msg.extend_from_slice(KONTOR_KBL1_CALL_MESSAGE_PREFIX);
    msg.extend_from_slice(op_bytes);
    msg
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerRefV1 {
    /// Existing signer (deterministic registry ID).
    Id(u32),
    /// Allows bundling calls for signers registered earlier in the same batch,
    /// without requiring the bundler to predict the assigned registry ID.
    XOnly([u8; 32]),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchOpV1 {
    /// Register/bind an x-only Taproot pubkey to a BLS pubkey.
    ///
    /// This carries the same binding proofs implemented by `signer_registry::register_signer`.
    RegisterSigner {
        xonly_pubkey: [u8; 32],
        bls_pubkey: Vec<u8>,
        schnorr_sig: Vec<u8>,
        bls_sig: Vec<u8>,
    },
    /// A binary contract call executed with the resolved signer identity.
    ///
    /// IMPORTANT: The postcard bytes of this op (as it appears in the decompressed stream) are
    /// what get signed and aggregated under BLS. Do not re-serialize for verification.
    Call {
        signer: SignerRefV1,
        nonce: u64,
        gas_limit: u64,
        contract_id: u32,
        function_index: u16,
        args: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct DecodedKbl1Batch {
    pub aggregate_signature: [u8; 48],
    pub decompressed_ops: Vec<u8>,
    pub ops: Vec<BatchOpV1>,
    pub op_ranges: Vec<Range<usize>>,
}

pub fn is_kbl1_payload(data: &[u8]) -> bool {
    data.starts_with(KBL1_MAGIC)
}

fn decompress_zstd_capped(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = zstd::stream::Decoder::new(std::io::Cursor::new(data))
        .map_err(|e| anyhow!("zstd decoder init failed: {e}"))?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| anyhow!("zstd decode failed: {e}"))?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > MAX_DECOMPRESSED_BATCH_BYTES {
            return Err(anyhow!(
                "kbl1 decompressed payload exceeds max size {} bytes",
                MAX_DECOMPRESSED_BATCH_BYTES
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

pub fn decode_kbl1_batch(data: &[u8]) -> Result<DecodedKbl1Batch> {
    if data.len() < 4 + 4 + 48 {
        return Err(anyhow!("kbl1 payload too short"));
    }
    if &data[..4] != KBL1_MAGIC {
        return Err(anyhow!("invalid kbl1 magic"));
    }

    let compressed_len =
        u32::from_le_bytes(data[4..8].try_into().expect("slice is 4 bytes")) as usize;

    let compressed_start: usize = 8;
    let sig_start = compressed_start
        .checked_add(compressed_len)
        .ok_or_else(|| anyhow!("kbl1 compressed_len overflow"))?;
    let sig_end = sig_start
        .checked_add(48)
        .ok_or_else(|| anyhow!("kbl1 signature offset overflow"))?;

    if sig_end != data.len() {
        return Err(anyhow!(
            "invalid kbl1 payload size (expected {} bytes, got {})",
            sig_end,
            data.len()
        ));
    }

    let compressed = &data[compressed_start..sig_start];
    let aggregate_signature: [u8; 48] = data[sig_start..sig_end]
        .try_into()
        .expect("signature slice is 48 bytes");

    let decompressed_ops = decompress_zstd_capped(compressed)?;

    let mut cursor = decompressed_ops.as_slice();
    let mut offset = 0usize;
    let mut ops = Vec::new();
    let mut op_ranges = Vec::new();

    while !cursor.is_empty() {
        let before = cursor.len();
        let (op, remaining) = postcard::take_from_bytes::<BatchOpV1>(cursor)
            .map_err(|e| anyhow!("failed to parse batch op: {e}"))?;
        let consumed = before
            .checked_sub(remaining.len())
            .ok_or_else(|| anyhow!("batch op parse consumed invalid length"))?;
        if consumed == 0 {
            return Err(anyhow!("batch op parse consumed 0 bytes"));
        }
        ops.push(op);
        op_ranges.push(offset..offset + consumed);
        offset += consumed;
        cursor = remaining;
    }

    Ok(DecodedKbl1Batch {
        aggregate_signature,
        decompressed_ops,
        ops,
        op_ranges,
    })
}

#[cfg(test)]
mod tests {
    use blst::min_sig::{AggregateSignature, SecretKey as BlsSecretKey, Signature as BlsSignature};

    use super::*;
    use crate::bls;

    #[test]
    fn kbl1_aggregate_signature_verifies_for_op_bytes() -> Result<(), anyhow::Error> {
        let sk1 = BlsSecretKey::key_gen(&[1u8; 32], &[]).expect("bls sk1");
        let sk2 = BlsSecretKey::key_gen(&[2u8; 32], &[]).expect("bls sk2");

        let op1 = BatchOpV1::Call {
            signer: SignerRefV1::Id(1),
            nonce: 1,
            gas_limit: 100,
            contract_id: 1,
            function_index: 0,
            args: vec![],
        };
        let op2 = BatchOpV1::Call {
            signer: SignerRefV1::Id(2),
            nonce: 2,
            gas_limit: 100,
            contract_id: 1,
            function_index: 0,
            args: vec![],
        };

        let op1_bytes = postcard::to_allocvec(&op1)?;
        let op2_bytes = postcard::to_allocvec(&op2)?;

        let messages = [
            kbl1_message_for_op_bytes(&op1_bytes),
            kbl1_message_for_op_bytes(&op2_bytes),
        ];
        let message_refs = [messages[0].as_slice(), messages[1].as_slice()];

        let sig1: BlsSignature = sk1.sign(message_refs[0], bls::KONTOR_BLS_DST, &[]);
        let sig2: BlsSignature = sk2.sign(message_refs[1], bls::KONTOR_BLS_DST, &[]);
        let sig_refs = [&sig1, &sig2];
        let aggregate = AggregateSignature::aggregate(&sig_refs, true).expect("aggregate sig");
        let agg_sig = aggregate.to_signature().to_bytes();

        let public_keys = [sk1.sk_to_pk().to_bytes(), sk2.sk_to_pk().to_bytes()];

        bls::verify_aggregate_signature(&agg_sig, &public_keys, &message_refs)?;
        Ok(())
    }

    #[test]
    fn kbl1_aggregate_signature_rejects_mutated_message() -> Result<(), anyhow::Error> {
        let sk1 = BlsSecretKey::key_gen(&[3u8; 32], &[]).expect("bls sk1");
        let sk2 = BlsSecretKey::key_gen(&[4u8; 32], &[]).expect("bls sk2");

        let op1 = BatchOpV1::Call {
            signer: SignerRefV1::Id(1),
            nonce: 1,
            gas_limit: 100,
            contract_id: 1,
            function_index: 0,
            args: vec![],
        };
        let op2 = BatchOpV1::Call {
            signer: SignerRefV1::Id(2),
            nonce: 2,
            gas_limit: 100,
            contract_id: 1,
            function_index: 0,
            args: vec![],
        };

        let op1_bytes = postcard::to_allocvec(&op1)?;
        let op2_bytes = postcard::to_allocvec(&op2)?;

        let messages = [
            kbl1_message_for_op_bytes(&op1_bytes),
            kbl1_message_for_op_bytes(&op2_bytes),
        ];
        let message_refs = [messages[0].as_slice(), messages[1].as_slice()];

        let sig1: BlsSignature = sk1.sign(message_refs[0], bls::KONTOR_BLS_DST, &[]);
        let sig2: BlsSignature = sk2.sign(message_refs[1], bls::KONTOR_BLS_DST, &[]);
        let sig_refs = [&sig1, &sig2];
        let aggregate = AggregateSignature::aggregate(&sig_refs, true).expect("aggregate sig");
        let agg_sig = aggregate.to_signature().to_bytes();

        let public_keys = [sk1.sk_to_pk().to_bytes(), sk2.sk_to_pk().to_bytes()];

        let mut bad_messages = messages.clone();
        bad_messages[0].push(0u8);
        let bad_refs = [bad_messages[0].as_slice(), bad_messages[1].as_slice()];

        assert!(bls::verify_aggregate_signature(&agg_sig, &public_keys, &bad_refs).is_err());
        Ok(())
    }
}
