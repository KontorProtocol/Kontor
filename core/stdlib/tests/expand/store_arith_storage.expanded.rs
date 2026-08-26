pub struct ArithStorage {
    pub last_op: Option<Op>,
}
#[automatically_derived]
impl<__S: stdlib::WriteStorage + stdlib::ReadStorage + ?Sized> stdlib::Store<__S>
for ArithStorage {
    fn __set(ctx: &alloc::rc::Rc<__S>, base_path: stdlib::KeyPath, value: ArithStorage) {
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(0u8), value.last_op);
    }
}
