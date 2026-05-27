use crate::runtime::{ContractAddress, kontor::built_in::context::SignerRef};

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

impl From<indexer_types::SignerRef> for SignerRef {
    fn from(value: indexer_types::SignerRef) -> Self {
        match value {
            indexer_types::SignerRef::SignerId(id) => Self::SignerId(id),
            indexer_types::SignerRef::XOnlyPubkey(x) => Self::XOnlyPubkey(x.to_string()),
        }
    }
}
