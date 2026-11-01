extern crate alloc;

use stdlib::KeyPath;
use context::{ProcContext, ViewContext};
use stdlib::StorageRoot;

mod error {
    pub type Error = String;
}

#[path = "support/context.rs"]
mod context;

#[derive(StorageRoot)]
struct ProxyStorage {
    contract_address: ContractAddress,
}

#[derive(Clone)]
struct ContractAddress {
    name: String,
    height: i64,
    tx_index: i64,
}
