extern crate alloc;

use stdlib::Model;

mod error {
    pub type Error = String;
}

#[derive(Model)]
pub struct ContractAddress {
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
}
