#![no_std]
extern crate alloc;

use alloc::{string::String, vec::Vec};

use indexer_types::*;
use wit_validator::Validator;

wit_bindgen::generate!({ world: "root", runtime_path: "indexer_types::wit_bindgen::rt"});

pub struct Lib {}

impl Guest for Lib {
    fn serialize_inst(json_str: String) -> Vec<u8> {
        inst_json_to_bytes(json_str)
    }

    fn deserialize_inst(bytes: Vec<u8>) -> String {
        inst_bytes_to_json(bytes)
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

    fn get_bls_constants() -> BlsConstants {
        BlsConstants {
            kontor_bls_dst: String::from(core::str::from_utf8(KONTOR_BLS_DST).unwrap()),
            kontor_op_prefix: String::from(core::str::from_utf8(KONTOR_OP_PREFIX).unwrap()),
            bls_signature_bytes: BLS_SIGNATURE_BYTES as u32,
            max_bls_bulk_ops: MAX_BLS_BULK_OPS as u32,
            max_bls_bulk_total_message_bytes: MAX_BLS_BULK_TOTAL_MESSAGE_BYTES as u32,
            schnorr_binding_prefix: String::from(core::str::from_utf8(SCHNORR_BINDING_PREFIX).unwrap()),
            bls_binding_prefix: String::from(core::str::from_utf8(BLS_BINDING_PREFIX).unwrap()),
        }
    }

    fn bls_bulk_op_signing_message(json_str: String) -> Vec<u8> {
        bls_bulk_op_signing_message_from_json(json_str)
    }
}

export!(Lib);
