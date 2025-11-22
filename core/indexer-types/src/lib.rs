use anyhow::Result;
use macros::contract_address;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
pub use wit_bindgen;

#[derive(Debug, Clone)]
pub struct ContractAddress {
    pub name: String,
    pub height: u64,
    pub tx_index: u64,
}

contract_address!(ContractAddress);

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Inst {
    Publish {
        gas_limit: u64,
        name: String,
        bytes: Vec<u8>,
    },
    Call {
        gas_limit: u64,
        #[serde_as(as = "DisplayFromStr")]
        contract: ContractAddress,
        expr: String,
    },
    Issuance,
}

pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(postcard::to_allocvec(value)?)
}

pub fn deserialize<T: for<'a> Deserialize<'a>>(buffer: &[u8]) -> Result<T> {
    Ok(postcard::from_bytes(buffer)?)
}

pub fn inst_json_to_bytes(json: String) -> Vec<u8> {
    let inst = serde_json::from_str::<Inst>(&json).expect("Invalid JSON string");
    serialize(&inst).expect("Failed to serialize to postcard")
}

pub fn inst_bytes_to_json(bytes: Vec<u8>) -> String {
    let inst = deserialize::<Inst>(&bytes).expect("Failed to deserialize from postcard");
    serde_json::to_string(&inst).expect("Failed to serialize to JSON")
}
