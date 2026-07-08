//! Pure-Rust logic of the Kontor SDK: `Inst` (de)serialization, BLS key
//! material + signing, the WIT/WAVE codec, and WIT validation. This crate
//! has no FFI dependency (no wit-bindgen, no uniffi) and no target pin, so
//! it compiles both to `wasm32-unknown-unknown` (via the `kontor-sdk-wasm`
//! wit-bindgen wrapper) and to native / mobile targets (via the
//! `kontor-sdk-native` uniffi wrapper). The bodies here are the single
//! source of truth for these consensus-critical operations.

pub mod wit_resource;

pub use wit_resource::WitResource;

// Re-export the shared numerics crate so downstream wrappers can bridge its
// types without adding a separate dependency edge.
pub use numerics;

use bls_crypto::blst::BLST_ERROR;
use bls_crypto::blst::min_sig::{
    AggregateSignature, PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
    Signature as BlsSignature,
};
use bls_crypto::{KONTOR_BLS_DST, derive_bls_secret_key_eip2333};
use indexer_types::{insts_bytes_to_json, insts_json_to_bytes};
use wit_validator::Validator;

pub fn serialize_inst(json_str: String) -> Result<Vec<u8>, String> {
    insts_json_to_bytes(json_str)
}

pub fn deserialize_inst(bytes: Vec<u8>) -> Result<String, String> {
    insts_bytes_to_json(bytes)
}

pub fn bls_secret_key_gen(ikm: Vec<u8>) -> Result<Vec<u8>, String> {
    // blst's `key_gen` is the KeyGen function from
    // draft-irtf-cfrg-bls-signature-05 — HKDF over input keying
    // material. Entropy origin is the host's problem (TS callers
    // pull bytes from webcrypto); we just enforce the BLS spec's
    // 32-byte IKM floor.
    if ikm.len() < 32 {
        return Err(format!(
            "BLS key_gen requires >= 32 bytes of IKM, got {}",
            ikm.len()
        ));
    }
    let sk = BlsSecretKey::key_gen(&ikm, &[]).map_err(|e| format!("BLS key_gen failed: {e:?}"))?;
    Ok(sk.to_bytes().to_vec())
}

pub fn bls_secret_from_seed_eip2333(seed: Vec<u8>, path: Vec<u32>) -> Result<Vec<u8>, String> {
    let sk = derive_bls_secret_key_eip2333(&seed, &path).map_err(|e| e.to_string())?;
    Ok(sk.to_bytes().to_vec())
}

pub fn bls_pubkey_from_secret(secret: Vec<u8>) -> Result<Vec<u8>, String> {
    let sk = bls_secret_key_from_bytes(&secret)?;
    Ok(sk.sk_to_pk().to_bytes().to_vec())
}

pub fn bls_sign(secret: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, String> {
    let sk = bls_secret_key_from_bytes(&secret)?;
    Ok(sk.sign(&message, KONTOR_BLS_DST, &[]).to_bytes().to_vec())
}

pub fn bls_verify(pubkey: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> Result<bool, String> {
    let pk =
        BlsPublicKey::key_validate(&pubkey).map_err(|e| format!("invalid BLS pubkey: {e:?}"))?;
    let sig = BlsSignature::sig_validate(&signature, true)
        .map_err(|e| format!("invalid BLS signature: {e:?}"))?;
    Ok(sig.verify(true, &message, KONTOR_BLS_DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS)
}

pub fn aggregate_signing_message(
    claim_json: String,
    nonce: u64,
    sponsored: bool,
    inst_json: String,
) -> Result<Vec<u8>, String> {
    let claim: indexer_types::SignerRef =
        serde_json::from_str(&claim_json).map_err(|e| format!("invalid claim JSON: {e}"))?;
    let inst: indexer_types::Inst =
        serde_json::from_str(&inst_json).map_err(|e| format!("invalid inst JSON: {e}"))?;
    inst.aggregate_signing_message(&claim, nonce, sponsored)
        .map_err(|e| format!("aggregate_signing_message failed: {e}"))
}

pub fn bls_aggregate_signatures(signatures: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    if signatures.is_empty() {
        return Err("bls_aggregate_signatures: need at least one signature".to_string());
    }
    let parsed: Vec<BlsSignature> = signatures
        .iter()
        .enumerate()
        .map(|(i, s)| {
            BlsSignature::sig_validate(s.as_slice(), true)
                .map_err(|e| format!("signature {i} failed subgroup validation: {e:?}"))
        })
        .collect::<Result<_, _>>()?;
    let refs: Vec<&BlsSignature> = parsed.iter().collect();
    // `aggregate(_, false)`: signatures were already subgroup-checked
    // above, no need to re-run inside `aggregate`.
    let agg = AggregateSignature::aggregate(&refs, false)
        .map_err(|e| format!("aggregation failed: {e:?}"))?;
    Ok(agg.to_signature().to_bytes().to_vec())
}

/// Plain-Rust mirror of the WIT `validation-result` variant. Kept free of
/// wit-bindgen types so this crate compiles for native targets; the
/// `kontor-sdk` wrapper maps it onto the generated `ValidationResult`.
pub enum WitValidation {
    Ok,
    ParseError(String),
    ValidationErrors(Vec<WitValidationError>),
}

/// Plain-Rust mirror of the WIT `validation-error` record.
pub struct WitValidationError {
    pub message: String,
    pub location: String,
}

pub fn validate_wit(wit_content: String) -> WitValidation {
    match Validator::validate_str(&wit_content) {
        Ok((result, resolve)) => {
            if result.is_valid() {
                WitValidation::Ok
            } else {
                let errors = result
                    .errors
                    .into_iter()
                    .map(|e| WitValidationError {
                        message: e.message,
                        location: if e.span.is_known() {
                            resolve.render_location(e.span)
                        } else {
                            String::from("<unknown>")
                        },
                    })
                    .collect();
                WitValidation::ValidationErrors(errors)
            }
        }
        Err(e) => WitValidation::ParseError(e.message),
    }
}

/// Parse a 32-byte BLS secret key buffer into a `BlsSecretKey`, mapping
/// length / scalar-range errors to strings for the boundary.
fn bls_secret_key_from_bytes(secret: &[u8]) -> Result<BlsSecretKey, String> {
    let bytes: &[u8; 32] = secret
        .try_into()
        .map_err(|_| format!("BLS secret must be 32 bytes, got {}", secret.len()))?;
    BlsSecretKey::from_bytes(bytes).map_err(|e| format!("invalid BLS secret: {e:?}"))
}
