use stdlib::*;

contract!(name = "arith");

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

    fn checked_sub(_: &ViewContext, x: String, y: String) -> Result<u64, Error> {
        let x = x.parse::<u64>()?;
        let y = y.parse::<u64>()?;
        x.checked_sub(y)
            .ok_or(Error::Message("less than 0".to_string()))
    }
}
