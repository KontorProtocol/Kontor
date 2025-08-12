macros::contract!(name = "arith");

#[derive(Clone, Store)]
struct ArithStorage {
    pub last_op: Option<Op>,
}

impl ArithStorage {
    pub fn init(self, ctx: &impl WriteContext) {
        ctx.__set(DotPathBuf::new(), self)
    }
}

struct Storage;

impl Storage {
    pub fn last_op(ctx: &impl ReadContext) -> Option<OpWrapper> {
        let base_path = DotPathBuf::new().push("last_op");
        if ctx.__is_void(&base_path) {
            None
        } else {
            Some(OpWrapper::new(ctx, base_path))
        }
    }

    pub fn set_last_op(ctx: &impl WriteContext, value: Option<Op>) {
        let base_path = DotPathBuf::new().push("last_op");
        match value {
            Some(op) => ctx.__set(base_path, op),
            None => ctx.__set(base_path, ()),
        }
    }
}

impl Guest for Arith {
    fn init(ctx: &ProcContext) {
        ArithStorage {
            last_op: Some(Op::Id),
        }
        .init(ctx)
    }

    fn eval(ctx: &ProcContext, x: u64, op: Op) -> ArithReturn {
        Storage::set_last_op(ctx, Some(op));
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
        Storage::last_op(ctx).map(|op| op.load(ctx))
    }
}

export!(Arith);
