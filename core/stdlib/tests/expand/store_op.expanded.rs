pub enum Op {
    Id,
    Sum(Operand),
    Mul(Operand),
    Div(Operand),
}
impl stdlib::Store for Op {
    fn __set(ctx: &impl stdlib::WriteContext, base_path: stdlib::DotPathBuf, value: Op) {
        match value {
            Op::Id => ctx.__set(base_path.push("id"), ()),
            Op::Sum(inner) => ctx.__set(base_path.push("sum"), inner),
            Op::Mul(inner) => ctx.__set(base_path.push("mul"), inner),
            Op::Div(inner) => ctx.__set(base_path.push("div"), inner),
        }
    }
}
