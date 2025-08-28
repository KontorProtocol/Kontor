pub struct Operand {
    pub y: u64,
}
#[automatically_derived]
impl stdlib::Store for Operand {
    fn __set(
        ctx: &impl stdlib::WriteContext,
        base_path: stdlib::DotPathBuf,
        value: Operand,
    ) {
        ctx.__set(base_path.push("y"), value.y);
    }
}
