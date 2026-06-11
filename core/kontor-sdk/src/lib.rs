mod numerics_api;
mod wit_resource;

use bls_crypto::blst::BLST_ERROR;
use bls_crypto::blst::min_sig::{
    AggregateSignature, PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
    Signature as BlsSignature,
};
use bls_crypto::{KONTOR_BLS_DST, derive_bls_secret_key_eip2333};
use indexer_types::*;
use wit_resource::WitResource;
use wit_validator::Validator;

wit_bindgen::generate!({ world: "root", runtime_path: "indexer_types::wit_bindgen::rt"});

use exports::root::component::wit_codec::{Guest as WitCodecGuest, GuestWit};

impl WitCodecGuest for Lib {
    type Wit = WitResource;
}

impl GuestWit for WitResource {
    fn new(text: String) -> Self {
        WitResource::new(text)
    }

    fn encode_call(&self, fn_name: String, args_json: String) -> Result<String, String> {
        WitResource::encode_call(self, fn_name, args_json)
    }

    fn decode_result(&self, fn_name: String, wave: String) -> Result<String, String> {
        WitResource::decode_result(self, fn_name, wave)
    }

    fn parse(&self) -> Result<String, String> {
        WitResource::parse(self)
    }
}

pub struct Lib {}

impl Guest for Lib {
    fn serialize_inst(json_str: String) -> Result<Vec<u8>, String> {
        insts_json_to_bytes(json_str)
    }

    fn deserialize_inst(bytes: Vec<u8>) -> Result<String, String> {
        insts_bytes_to_json(bytes)
    }

    fn bls_secret_key_gen(ikm: Vec<u8>) -> Result<Vec<u8>, String> {
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
        let sk =
            BlsSecretKey::key_gen(&ikm, &[]).map_err(|e| format!("BLS key_gen failed: {e:?}"))?;
        Ok(sk.to_bytes().to_vec())
    }

    fn bls_secret_from_seed_eip2333(seed: Vec<u8>, path: Vec<u32>) -> Result<Vec<u8>, String> {
        let sk = derive_bls_secret_key_eip2333(&seed, &path).map_err(|e| e.to_string())?;
        Ok(sk.to_bytes().to_vec())
    }

    fn bls_pubkey_from_secret(secret: Vec<u8>) -> Result<Vec<u8>, String> {
        let sk = bls_secret_key_from_bytes(&secret)?;
        Ok(sk.sk_to_pk().to_bytes().to_vec())
    }

    fn bls_sign(secret: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, String> {
        let sk = bls_secret_key_from_bytes(&secret)?;
        Ok(sk.sign(&message, KONTOR_BLS_DST, &[]).to_bytes().to_vec())
    }

    fn bls_verify(pubkey: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> Result<bool, String> {
        let pk = BlsPublicKey::key_validate(&pubkey)
            .map_err(|e| format!("invalid BLS pubkey: {e:?}"))?;
        let sig = BlsSignature::sig_validate(&signature, true)
            .map_err(|e| format!("invalid BLS signature: {e:?}"))?;
        Ok(sig.verify(true, &message, KONTOR_BLS_DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS)
    }

    fn aggregate_signing_message(
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

    fn bls_aggregate_signatures(signatures: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
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

    fn validate_wit(wit_content: String) -> ValidationResult {
        match Validator::validate_str(&wit_content) {
            Ok((result, resolve)) => {
                if result.is_valid() {
                    ValidationResult::Ok
                } else {
                    let errors = result
                        .errors
                        .into_iter()
                        .map(|e| ValidationError {
                            message: e.message,
                            location: if e.span.is_known() {
                                resolve.render_location(e.span)
                            } else {
                                String::from("<unknown>")
                            },
                        })
                        .collect();
                    ValidationResult::ValidationErrors(errors)
                }
            }
            Err(e) => ValidationResult::ParseError(e.message),
        }
    }
}

export!(Lib);

/// Parse a 32-byte BLS secret key buffer into a `BlsSecretKey`, mapping
/// length / scalar-range errors to strings for the WIT boundary.
fn bls_secret_key_from_bytes(secret: &[u8]) -> Result<BlsSecretKey, String> {
    let bytes: &[u8; 32] = secret
        .try_into()
        .map_err(|_| format!("BLS secret must be 32 bytes, got {}", secret.len()))?;
    BlsSecretKey::from_bytes(bytes).map_err(|e| format!("invalid BLS secret: {e:?}"))
}
