use stdlib::Model;

#[derive(Model)]
pub struct ContractAddress {
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
}
