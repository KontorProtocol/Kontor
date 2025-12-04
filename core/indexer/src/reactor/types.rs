use crate::runtime::{ContractAddress, kontor::built_in::context::OpReturnData};

impl From<&indexer_types::ContractAddress> for ContractAddress {
    fn from(value: &indexer_types::ContractAddress) -> Self {
        Self {
            name: value.name.clone(),
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
