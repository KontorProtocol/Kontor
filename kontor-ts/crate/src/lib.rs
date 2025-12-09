#![no_std]
extern crate alloc;

use alloc::{string::String, vec::Vec};

use indexer_types::*;

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
}

export!(Lib);
