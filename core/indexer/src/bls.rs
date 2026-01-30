use anyhow::{Result, anyhow};
use blst::BLST_ERROR;
use blst::min_sig::{PublicKey, Signature};

// Protocol-level BLS signatures use the min_sig scheme:
// - signature (and aggregate) is 48 bytes
// - public key is 96 bytes
//
// NOTE: Keep this separate from Horizon-Portal's BLS signing; Portal uses its own DST/message
// format (e.g. `HORIZON_PORTAL_BLS_DST`). Kontor batching/registry has its own message prefixes.
pub const KONTOR_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

pub fn parse_public_key(bytes: &[u8; 96]) -> Result<PublicKey> {
    PublicKey::key_validate(bytes).map_err(|e| anyhow!("invalid BLS public key bytes: {:?}", e))
}

pub fn parse_signature(bytes: &[u8; 48]) -> Result<Signature> {
    Signature::sig_validate(bytes, true)
        .map_err(|e| anyhow!("invalid BLS signature bytes: {:?}", e))
}

pub fn verify_signature(pk: &PublicKey, sig: &Signature, message: &[u8]) -> Result<()> {
    let verify_result = sig.verify(true, message, KONTOR_BLS_DST, &[], pk, true);
    if verify_result != BLST_ERROR::BLST_SUCCESS {
        return Err(anyhow!(
            "BLS signature verification failed: {:?}",
            verify_result
        ));
    }
    Ok(())
}

pub fn verify_aggregate_signature(
    aggregate_signature: &[u8; 48],
    public_keys: &[[u8; 96]],
    messages: &[&[u8]],
) -> Result<()> {
    if public_keys.len() != messages.len() {
        return Err(anyhow!(
            "aggregate signature verification requires equal public_keys/messages lengths ({} != {})",
            public_keys.len(),
            messages.len()
        ));
    }
    if public_keys.is_empty() {
        return Err(anyhow!(
            "aggregate signature verification requires at least one message"
        ));
    }

    let sig = parse_signature(aggregate_signature)?;
    let pks: Vec<PublicKey> = public_keys
        .iter()
        .map(parse_public_key)
        .collect::<Result<Vec<_>>>()?;
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();

    let verify_result = sig.aggregate_verify(true, messages, KONTOR_BLS_DST, &pk_refs, true);
    if verify_result != BLST_ERROR::BLST_SUCCESS {
        return Err(anyhow!(
            "BLS aggregate signature verification failed: {:?}",
            verify_result
        ));
    }
    Ok(())
}
