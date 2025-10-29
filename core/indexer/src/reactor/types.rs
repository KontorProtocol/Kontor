use serde::{Deserialize, Serialize};

use crate::runtime::{ContractAddress, wit::Signer};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpMetadata {
    pub input_index: i64,
    pub signer: Signer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    Publish {
        metadata: OpMetadata,
        name: String,
        bytes: Vec<u8>,
    },
    Call {
        metadata: OpMetadata,
        contract: ContractAddress,
        expr: String,
    },
}

impl Op {
    pub fn metadata(&self) -> &OpMetadata {
        match self {
            Op::Publish { metadata, .. } => metadata,
            Op::Call { metadata, .. } => metadata,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Inst {
    #[serde(rename = "p")]
    Publish {
        #[serde(rename = "n")]
        name: String,
        #[serde(rename = "b")]
        bytes: Vec<u8>,
    },
    #[serde(rename = "c")]
    Call {
        #[serde(rename = "c")]
        contract: ContractAddress,
        #[serde(rename = "e")]
        expr: String,
    },
}
