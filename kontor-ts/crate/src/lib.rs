#![no_std]
extern crate alloc;

use alloc::{string::String, vec::Vec};

use indexer_types::*;
use wit_validator::Validator;

wit_bindgen::generate!({ world: "root", runtime_path: "indexer_types::wit_bindgen::rt"});

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
                                alloc::string::String::from("<unknown>")
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn call_batch_roundtrip() {
        let json = r#"{"ops":[{"Call":{"gas_limit":1000000,"contract":"foo_1_2","expr":"foo()"}}],"aggregate":null}"#.to_string();
        let bytes = insts_json_to_bytes(json.clone());
        let roundtrip = insts_bytes_to_json(bytes);
        assert_eq!(
            roundtrip,
            r#"{"ops":[{"Call":{"gas_limit":1000000,"contract":"foo_1_2","nonce":null,"expr":"foo()"}}],"aggregate":null}"#
        );
    }
}
