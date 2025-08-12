struct ContractAddress {
    name: String,
    height: i64,
    tx_index: i64,
}
impl stdlib::Store for ContractAddress {
    fn __set(
        ctx: &impl stdlib::WriteContext,
        base_path: stdlib::DotPathBuf,
        value: ContractAddress,
    ) {
        ctx.__set(base_path.push("name"), value.name);
        ctx.__set(base_path.push("height"), value.height);
        ctx.__set(base_path.push("tx_index"), value.tx_index);
    }
}
