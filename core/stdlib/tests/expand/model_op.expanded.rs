use stdlib::Model;
pub enum Op {
    Id,
    Sum(Operand),
    Mul(Operand),
    Div(Operand),
}
pub enum OpModel {
    Id,
    Sum(OperandModel),
    Mul(OperandModel),
    Div(OperandModel),
}
impl OpModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        stdlib::ReadStorage::__extend_path_with_match(
                &ctx,
                &base_path,
                &["id", "sum", "mul", "div"],
            )
            .map(|path| match path {
                p if p.starts_with(base_path.push("id").as_ref()) => OpModel::Id,
                p if p.starts_with(base_path.push("sum").as_ref()) => {
                    OpModel::Sum(OperandModel::new(ctx.clone(), base_path.push("sum")))
                }
                p if p.starts_with(base_path.push("mul").as_ref()) => {
                    OpModel::Mul(OperandModel::new(ctx.clone(), base_path.push("mul")))
                }
                p if p.starts_with(base_path.push("div").as_ref()) => {
                    OpModel::Div(OperandModel::new(ctx.clone(), base_path.push("div")))
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Matching path not found"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self) -> Op {
        match self {
            OpModel::Id => Op::Id,
            OpModel::Sum(inner) => Op::Sum(inner.load()),
            OpModel::Mul(inner) => Op::Mul(inner.load()),
            OpModel::Div(inner) => Op::Div(inner.load()),
        }
    }
}
pub enum OpWriteModel {
    Id,
    Sum(OperandWriteModel),
    Mul(OperandWriteModel),
    Div(OperandWriteModel),
}
impl OpWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        stdlib::ReadStorage::__extend_path_with_match(
                &ctx,
                &base_path,
                &["id", "sum", "mul", "div"],
            )
            .map(|path| match path {
                p if p.starts_with(base_path.push("id").as_ref()) => OpWriteModel::Id,
                p if p.starts_with(base_path.push("sum").as_ref()) => {
                    OpWriteModel::Sum(
                        OperandWriteModel::new(ctx.clone(), base_path.push("sum")),
                    )
                }
                p if p.starts_with(base_path.push("mul").as_ref()) => {
                    OpWriteModel::Mul(
                        OperandWriteModel::new(ctx.clone(), base_path.push("mul")),
                    )
                }
                p if p.starts_with(base_path.push("div").as_ref()) => {
                    OpWriteModel::Div(
                        OperandWriteModel::new(ctx.clone(), base_path.push("div")),
                    )
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Matching path not found"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self) -> Op {
        match self {
            OpWriteModel::Id => Op::Id,
            OpWriteModel::Sum(inner) => Op::Sum(inner.load()),
            OpWriteModel::Mul(inner) => Op::Mul(inner.load()),
            OpWriteModel::Div(inner) => Op::Div(inner.load()),
        }
    }
}
