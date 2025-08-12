#[derive(stdlib::Store)]
struct ContractAddress {
    name: String,
    height: i64,
    tx_index: i64,
}
