extern crate alloc;

use stdlib::Model;

mod error {
    pub type Error = String;
}

#[derive(Model)]
struct ProxyStorage {
    contract_address: ContractAddress,
}

#[derive(Clone)]
struct ContractAddress {
    name: String,
    height: i64,
    tx_index: i64,
}
