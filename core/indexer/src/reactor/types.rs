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
        gas_limit: u64,
        name: String,
        bytes: Vec<u8>,
    },
    Call {
        metadata: OpMetadata,
        gas_limit: u64,
        contract: ContractAddress,
        expr: String,
    },
    Issuance {
        metadata: OpMetadata,
    },
}

impl Op {
    pub fn metadata(&self) -> &OpMetadata {
        match self {
            Op::Publish { metadata, .. } => metadata,
            Op::Call { metadata, .. } => metadata,
            Op::Issuance { metadata, .. } => metadata,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Inst {
    Publish {
        gas_limit: u64,
        name: String,
        bytes: Vec<u8>,
    },
    Call {
        gas_limit: u64,
        contract: ContractAddress,
        expr: String,
    },
    Issuance,
}
