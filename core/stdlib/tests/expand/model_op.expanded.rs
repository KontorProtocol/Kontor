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
                &[
                    stdlib::interned_element(0u8),
                    stdlib::interned_element(1u8),
                    stdlib::interned_element(2u8),
                    stdlib::interned_element(3u8),
                ],
            )
            .map(|__idx| match __idx {
                0u32 => OpModel::Id,
                1u32 => {
                    OpModel::Sum(
                        OperandModel::new(ctx.clone(), base_path.push_interned(1u8)),
                    )
                }
                2u32 => {
                    OpModel::Mul(
                        OperandModel::new(ctx.clone(), base_path.push_interned(2u8)),
                    )
                }
                3u32 => {
                    OpModel::Div(
                        OperandModel::new(ctx.clone(), base_path.push_interned(3u8)),
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
                &[
                    stdlib::interned_element(0u8),
                    stdlib::interned_element(1u8),
                    stdlib::interned_element(2u8),
                    stdlib::interned_element(3u8),
                ],
            )
            .map(|__idx| match __idx {
                0u32 => OpWriteModel::Id,
                1u32 => {
                    OpWriteModel::Sum(
                        OperandWriteModel::new(ctx.clone(), base_path.push_interned(1u8)),
                    )
                }
                2u32 => {
                    OpWriteModel::Mul(
                        OperandWriteModel::new(ctx.clone(), base_path.push_interned(2u8)),
                    )
                }
                3u32 => {
                    OpWriteModel::Div(
                        OperandWriteModel::new(ctx.clone(), base_path.push_interned(3u8)),
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
