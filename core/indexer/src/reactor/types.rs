use crate::runtime::ContractAddress;

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
