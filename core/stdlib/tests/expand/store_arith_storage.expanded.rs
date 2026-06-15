pub struct ArithStorage {
    pub last_op: Option<Op>,
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for ArithStorage {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
        value: ArithStorage,
    ) {
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(0u8), value.last_op);
    }
}
