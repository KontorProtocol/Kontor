mod numerics_api;
mod wit_resource;

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
    fn serialize_inst(json_str: String) -> Vec<u8> {
        insts_json_to_bytes(json_str)
    }

    fn deserialize_inst(bytes: Vec<u8>) -> String {
        insts_bytes_to_json(bytes)
    }

    fn serialize_op_return_data(json_str: String) -> Vec<u8> {
        op_return_data_json_to_bytes(json_str)
    }

    fn deserialize_op_return_data(bytes: Vec<u8>) -> String {
        op_return_data_bytes_to_json(bytes)
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
