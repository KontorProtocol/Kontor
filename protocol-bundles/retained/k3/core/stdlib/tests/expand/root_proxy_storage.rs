extern crate alloc;

use stdlib::KeyPath;
use context::{ProcContext, ViewContext};
use stdlib::Root;

#[path = "support/context.rs"]
mod context;

mod error {
    pub type Error = String;
}

#[derive(Root, stdlib::Storage)]
struct ProxyStorage {
    contract_address: ContractAddress,
}

#[derive(Clone)]
struct ContractAddress {
    name: String,
    height: i64,
    tx_index: i64,
}
