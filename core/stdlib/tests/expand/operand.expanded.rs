use stdlib::Store;
pub struct Operand {
    pub y: u64,
}
impl Store for Operand {
    fn __set(ctx: &impl WriteContext, base_path: DotPathBuf, value: Operand) {
        ctx.__set(base_path.push("y"), value.y);
    }
}
