mod numerics_api;
mod wit_resource;

use bls_crypto::blst::min_sig::SecretKey as BlsSecretKey;
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

    fn encode_op_return(entries: Vec<OpReturnEntry>) -> Result<Vec<u8>, String> {
        op_return_encode(entries)
    }

    fn decode_op_return(bytes: Vec<u8>) -> Result<Vec<OpReturnEntry>, String> {
        op_return_decode(bytes)
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

// OP_RETURN codec — bridges the WIT-generated `OpReturnEntry` /
// `SignerRef` (bare names below) to their `indexer_types` twins, which
// own the postcard wire format.

fn op_return_encode(entries: Vec<OpReturnEntry>) -> Result<Vec<u8>, String> {
    let payload = entries
        .into_iter()
        .map(op_return_entry_to_indexer)
        .collect::<Result<Vec<indexer_types::OpReturnEntry>, String>>()?;
    indexer_types::serialize(&payload).map_err(|e| e.to_string())
}

fn op_return_decode(bytes: Vec<u8>) -> Result<Vec<OpReturnEntry>, String> {
    let payload: Vec<indexer_types::OpReturnEntry> =
        indexer_types::deserialize(&bytes).map_err(|e| e.to_string())?;
    Ok(payload
        .into_iter()
        .map(op_return_entry_from_indexer)
        .collect())
}

fn op_return_entry_to_indexer(
    entry: OpReturnEntry,
) -> Result<indexer_types::OpReturnEntry, String> {
    Ok(indexer_types::OpReturnEntry {
        input_index: entry.input_index,
        recipient: signer_ref_to_indexer(entry.recipient)?,
    })
}

fn signer_ref_to_indexer(claim: SignerRef) -> Result<indexer_types::SignerRef, String> {
    match claim {
        SignerRef::SignerId(id) => Ok(indexer_types::SignerRef::SignerId(id)),
        SignerRef::XOnlyPubkey(hex) => indexer_types::SignerRef::pubkey_from_hex(&hex),
    }
}

fn op_return_entry_from_indexer(entry: indexer_types::OpReturnEntry) -> OpReturnEntry {
    let recipient = match entry.recipient {
        indexer_types::SignerRef::SignerId(id) => SignerRef::SignerId(id),
        indexer_types::SignerRef::XOnlyPubkey(pk) => SignerRef::XOnlyPubkey(pk.to_string()),
    };
    OpReturnEntry {
        input_index: entry.input_index,
        recipient,
    }
}
