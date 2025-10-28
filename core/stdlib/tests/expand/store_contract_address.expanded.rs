struct ContractAddress {
    name: String,
    height: i64,
    tx_index: i64,
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for ContractAddress {
    fn __set(
        ctx: &crate::context::ProcStorage,
        base_path: stdlib::DotPathBuf,
        value: ContractAddress,
    ) {
        ctx.__set(base_path.push("name"), value.name);
        ctx.__set(base_path.push("height"), value.height);
        ctx.__set(base_path.push("tx_index"), value.tx_index);
    }
}
