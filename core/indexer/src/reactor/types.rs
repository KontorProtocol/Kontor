use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use ts_rs::TS;

use crate::runtime::{ContractAddress, kontor::built_in::context::OpReturnData, wit::Signer};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/bindings.d.ts")]
pub struct OpMetadata {
    #[ts(as = "String")]
    pub previous_output: bitcoin::OutPoint,
    #[ts(type = "number")]
    pub input_index: i64,
    pub signer: Signer,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/bindings.d.ts")]
pub enum Op {
    Publish {
        metadata: OpMetadata,
        #[ts(type = "number")]
        gas_limit: u64,
        name: String,
        bytes: Vec<u8>,
    },
    Call {
        metadata: OpMetadata,
        #[ts(type = "number")]
        gas_limit: u64,
        #[ts(as = "String")]
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

impl From<indexer_types::OpReturnData> for OpReturnData {
    fn from(value: indexer_types::OpReturnData) -> Self {
        match value {
            indexer_types::OpReturnData::PubKey(x) => Self::PubKey(x.to_string()),
        }
    }
}
