extern crate alloc;

use stdlib::Storage;

mod error {
    pub type Error = String;
}

#[derive(Storage)]
struct ProxyStorage {
    contract_address: ContractAddress,
}

#[derive(Clone)]
struct ContractAddress {
    name: String,
    height: i64,
    tx_index: i64,
}
