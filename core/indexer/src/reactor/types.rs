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
// HERE
// not use cbor!
// look at serde site, look at list of all serialization methods
// DETERMINITSTIC AND SMALL -- postcard? common library EXPLICITLY SAYS DETERMISTIC

// reveal endpoint takes arbitrary data?
// reproduce byte for byte script data
// that would require deterministic serialization

pub enum Inst {
    #[serde(rename = "p")]
    Publish {
        #[serde(rename = "g")]
        gas_limit: u64,
        #[serde(rename = "n")]
        name: String,
        #[serde(rename = "b")]
        bytes: Vec<u8>,
    },
    #[serde(rename = "c")]
    Call {
        #[serde(rename = "g")]
        gas_limit: u64,
        #[serde(rename = "c")]
        contract: ContractAddress,
        #[serde(rename = "e")]
        expr: String,
    },
    #[serde(rename = "i")]
    Issuance,
}
