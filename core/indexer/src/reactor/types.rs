use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

use crate::runtime::{ContractAddress, wit::Signer};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpMetadata {
    pub input_index: i64,
    pub signer: Signer,
}

#[serde_as]
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
        #[serde_as(as = "DisplayFromStr")]
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

impl From<indexer_types::ContractAddress> for ContractAddress {
    fn from(value: indexer_types::ContractAddress) -> Self {
        Self {
            name: value.name,
            height: value.height,
            tx_index: value.tx_index,
        }
    }
}

impl From<ContractAddress> for indexer_types::ContractAddress {
    fn from(value: ContractAddress) -> Self {
        Self {
            name: value.name,
            height: value.height,
            tx_index: value.tx_index,
        }
    }
}
