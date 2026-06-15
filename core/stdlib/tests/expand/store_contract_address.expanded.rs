struct ContractAddress {
    name: String,
    height: i64,
    tx_index: i64,
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for ContractAddress {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
        value: ContractAddress,
    ) {
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(0u8), value.name);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(1u8), value.height);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(2u8), value.tx_index);
    }
}
