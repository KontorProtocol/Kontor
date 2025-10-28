pub struct Operand {
    pub y: u64,
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for Operand {
    fn __set(
        ctx: &crate::context::ProcStorage,
        base_path: stdlib::DotPathBuf,
        value: Operand,
    ) {
        ctx.__set(base_path.push("y"), value.y);
    }
}
