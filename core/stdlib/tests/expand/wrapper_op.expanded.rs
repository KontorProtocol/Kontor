use stdlib::Wrapper;
pub enum Op {
    Id,
    Sum(Operand),
    Mul(Operand),
    Div(Operand),
}
pub enum OpWrapper {
    Id,
    Sum(OperandWrapper),
    Mul(OperandWrapper),
    Div(OperandWrapper),
}
#[automatically_derived]
impl ::core::clone::Clone for OpWrapper {
    #[inline]
    fn clone(&self) -> OpWrapper {
        match self {
            OpWrapper::Id => OpWrapper::Id,
            OpWrapper::Sum(__self_0) => {
                OpWrapper::Sum(::core::clone::Clone::clone(__self_0))
            }
            OpWrapper::Mul(__self_0) => {
                OpWrapper::Mul(::core::clone::Clone::clone(__self_0))
            }
            OpWrapper::Div(__self_0) => {
                OpWrapper::Div(::core::clone::Clone::clone(__self_0))
            }
        }
    }
}
impl OpWrapper {
    pub fn new(ctx: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
        ctx.__matching_path(
                &::alloc::__export::must_use({
                    ::alloc::fmt::format(
                        format_args!(
                            "^{0}.({1})(\\..*|$)", base_path, ["id", "sum", "mul", "div"]
                            .join("|"),
                        ),
                    )
                }),
            )
            .map(|path| match path {
                p if p.starts_with(base_path.push("id").as_ref()) => OpWrapper::Id,
                p if p.starts_with(base_path.push("sum").as_ref()) => {
                    OpWrapper::Sum(OperandWrapper::new(ctx, base_path.push("sum")))
                }
                p if p.starts_with(base_path.push("mul").as_ref()) => {
                    OpWrapper::Mul(OperandWrapper::new(ctx, base_path.push("mul")))
                }
                p if p.starts_with(base_path.push("div").as_ref()) => {
                    OpWrapper::Div(OperandWrapper::new(ctx, base_path.push("div")))
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Matching path not found"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> Op {
        match self {
            OpWrapper::Id => Op::Id,
            OpWrapper::Sum(inner_wrapper) => Op::Sum(inner_wrapper.load(ctx)),
            OpWrapper::Mul(inner_wrapper) => Op::Mul(inner_wrapper.load(ctx)),
            OpWrapper::Div(inner_wrapper) => Op::Div(inner_wrapper.load(ctx)),
        }
    }
}
