mod numerics_api;

// `wit_bindgen` is not a direct dependency; it reaches us re-exported from
// `indexer-types` (`pub use wit_bindgen;`). Bring it into scope so the
// `generate!` macro path below resolves — same mechanism the pre-refactor
// crate relied on via its `use indexer_types::*;` glob.
use indexer_types::wit_bindgen;
use kontor_sdk::WitResource;

wit_bindgen::generate!({ world: "root", runtime_path: "indexer_types::wit_bindgen::rt", generate_all });

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
        kontor_sdk::serialize_inst(json_str)
    }

    fn deserialize_inst(bytes: Vec<u8>) -> Result<String, String> {
        kontor_sdk::deserialize_inst(bytes)
    }

    fn bls_secret_key_gen(ikm: Vec<u8>) -> Result<Vec<u8>, String> {
        kontor_sdk::bls_secret_key_gen(ikm)
    }

    fn bls_secret_from_seed_eip2333(seed: Vec<u8>, path: Vec<u32>) -> Result<Vec<u8>, String> {
        kontor_sdk::bls_secret_from_seed_eip2333(seed, path)
    }

    fn bls_pubkey_from_secret(secret: Vec<u8>) -> Result<Vec<u8>, String> {
        kontor_sdk::bls_pubkey_from_secret(secret)
    }

    fn bls_sign(secret: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, String> {
        kontor_sdk::bls_sign(secret, message)
    }

    fn bls_verify(pubkey: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> Result<bool, String> {
        kontor_sdk::bls_verify(pubkey, message, signature)
    }

    fn aggregate_signing_message(
        claim_json: String,
        nonce: u64,
        sponsored: bool,
        inst_json: String,
    ) -> Result<Vec<u8>, String> {
        kontor_sdk::aggregate_signing_message(claim_json, nonce, sponsored, inst_json)
    }

    fn bls_aggregate_signatures(signatures: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
        kontor_sdk::bls_aggregate_signatures(signatures)
    }

    fn validate_wit(wit_content: String) -> ValidationResult {
        match kontor_sdk::validate_wit(wit_content) {
            kontor_sdk::WitValidation::Ok => ValidationResult::Ok,
            kontor_sdk::WitValidation::ParseError(msg) => ValidationResult::ParseError(msg),
            kontor_sdk::WitValidation::ValidationErrors(errors) => {
                ValidationResult::ValidationErrors(
                    errors
                        .into_iter()
                        .map(|e| ValidationError {
                            message: e.message,
                            location: e.location,
                        })
                        .collect(),
                )
            }
        }
    }
}

export!(Lib);
