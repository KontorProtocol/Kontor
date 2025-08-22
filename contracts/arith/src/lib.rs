macros::contract!(name = "arith");

#[derive(Clone, Default, StorageRoot)]
struct ArithStorage {
    pub last_op: Option<Op>,
}

impl Guest for Arith {
    fn init(ctx: &ProcContext) {
        ArithStorage {
            last_op: Some(Op::Id),
        }
        .init(ctx)
    }

    fn eval(ctx: &ProcContext, x: u64, op: Op) -> ArithReturn {
        storage(ctx).set_last_op(ctx, Some(op));
        ArithReturn {
            value: match op {
                Op::Id => x,
                Op::Sum(operand) => x + operand.y,
                Op::Mul(operand) => x * operand.y,
                Op::Div(operand) => x / operand.y,
            },
        }
    }

    fn last_op(ctx: &ViewContext) -> Option<Op> {
        storage(ctx).last_op(ctx).map(|op| op.load(ctx))
    }
}
