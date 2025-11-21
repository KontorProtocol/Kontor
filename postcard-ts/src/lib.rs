use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use wit_bindgen::generate;

generate!("root");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAddress {
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
}

impl std::str::FromStr for ContractAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('_').collect();
        if parts.len() != 3 {
            return Err(format!("expected 3 parts separated by '_', got: {s}"));
        }
        let name = parts[0].to_string();
        let height = parts[1]
            .parse::<i64>()
            .map_err(|e| format!("invalid height: {e}"))?;
        let tx_index = parts[2]
            .parse::<i64>()
            .map_err(|e| format!("invalid tx_index: {e}"))?;

        Ok(ContractAddress {
            name,
            height,
            tx_index,
        })
    }
}

impl std::fmt::Display for ContractAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_{}_{}", self.name, self.height, self.tx_index)
    }
}

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

pub struct Lib {}

impl Guest for Lib {
    fn serialize(json_str: String) -> Vec<u8> {
        let inst = serde_json::from_str::<Inst>(&json_str).expect("Invalid JSON string");
        postcard::to_allocvec(&inst).expect("Failed to serialize to postcard")
    }

    fn deserialize(bytes: Vec<u8>) -> String {
        let inst =
            postcard::from_bytes::<Inst>(&bytes).expect("Failed to deserialize from postcard");
        serde_json::to_string(&inst).expect("Failed to serialize to JSON")
    }
}

export!(Lib);
