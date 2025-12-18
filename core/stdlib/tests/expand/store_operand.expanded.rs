pub struct Operand {
    pub y: u64,
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for Operand {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
        value: Operand,
    ) {
        stdlib::WriteStorage::__set(ctx, base_path.push("y"), value.y);
    }
}
