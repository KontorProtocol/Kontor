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
        base_path: stdlib::KeyPath,
    ) -> Self {
        stdlib::ReadStorage::__extend_path_with_match(
                &ctx,
                &base_path,
                &["id", "sum", "mul", "div"],
            )
            .map(|variant| match variant.as_str() {
                "id" => OpModel::Id,
                "sum" => {
                    OpModel::Sum(OperandModel::new(ctx.clone(), base_path.push("sum")))
                }
                "mul" => {
                    OpModel::Mul(OperandModel::new(ctx.clone(), base_path.push("mul")))
                }
                "div" => {
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
        base_path: stdlib::KeyPath,
    ) -> Self {
        stdlib::ReadStorage::__extend_path_with_match(
                &ctx,
                &base_path,
                &["id", "sum", "mul", "div"],
            )
            .map(|variant| match variant.as_str() {
                "id" => OpWriteModel::Id,
                "sum" => {
                    OpWriteModel::Sum(
                        OperandWriteModel::new(ctx.clone(), base_path.push("sum")),
                    )
                }
                "mul" => {
                    OpWriteModel::Mul(
                        OperandWriteModel::new(ctx.clone(), base_path.push("mul")),
                    )
                }
                "div" => {
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
