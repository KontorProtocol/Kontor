pub struct Operand {
    pub y: u64,
}
#[automatically_derived]
impl<__S: stdlib::WriteStorage + stdlib::ReadStorage + ?Sized> stdlib::Store<__S>
for Operand {
    fn __set(ctx: &alloc::rc::Rc<__S>, base_path: stdlib::KeyPath, value: Operand) {
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(0u8), value.y);
    }
}
