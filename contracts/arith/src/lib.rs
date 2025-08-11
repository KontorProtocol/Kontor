macros::contract!(name = "arith");

impl Store for Operand {
    fn __set(ctx: &impl WriteContext, base_path: DotPathBuf, value: Operand) {
        ctx.__set(base_path.push("y"), value.y);
    }
}

struct OperandWrapper {
    pub base_path: DotPathBuf,
}

#[allow(dead_code)]
impl OperandWrapper {
    pub fn new(_: &impl ReadContext, base_path: DotPathBuf) -> Self {
        Self { base_path }
    }

    pub fn y(&self, ctx: &impl ReadContext) -> u64 {
        ctx.__get(self.base_path.push("y")).unwrap()
    }

    pub fn set_y(&self, ctx: &impl WriteContext, value: u64) {
        ctx.__set(self.base_path.push("y"), value);
    }

    pub fn load(&self, ctx: &impl ReadContext) -> Operand {
        Operand { y: self.y(ctx) }
    }
}

impl Store for Op {
    fn __set(ctx: &impl WriteContext, base_path: DotPathBuf, value: Op) {
        match value {
            Op::Id => ctx.__set(base_path.push("id"), ()),
            Op::Sum(operand) => ctx.__set(base_path.push("sum"), operand),
            Op::Mul(operand) => ctx.__set(base_path.push("mul"), operand),
            Op::Div(operand) => ctx.__set(base_path.push("div"), operand),
        }
    }
}

enum OpWrapper {
    Id,
    Sum(OperandWrapper),
    Mul(OperandWrapper),
    Div(OperandWrapper),
}

impl OpWrapper {
    pub fn new(ctx: &impl ReadContext, base_path: DotPathBuf) -> Self {
        let path = ctx
            .matching_path(&format!(r"^{}.(id|sum|mul|div)(\..*|$)", base_path))
            .unwrap();
        match path {
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
                panic!("Matching path not found")
            }
        }
    }

    pub fn load(&self, ctx: &impl ReadContext) -> Op {
        match self {
            OpWrapper::Id => Op::Id,
            OpWrapper::Sum(operand_wrapper) => Op::Sum(operand_wrapper.load(ctx)),
            OpWrapper::Mul(operand_wrapper) => Op::Mul(operand_wrapper.load(ctx)),
            OpWrapper::Div(operand_wrapper) => Op::Div(operand_wrapper.load(ctx)),
        }
    }
}

#[derive(Clone)]
struct ArithStorage {
    pub last_op: Option<Op>,
}

// generated
impl Store for ArithStorage {
    fn __set(ctx: &impl WriteContext, base_path: DotPathBuf, value: ArithStorage) {
        match value.last_op {
            Some(op) => ctx.__set(base_path.push("last_op"), op),
            None => ctx.__set(base_path.push("last_op"), ()),
        }
    }
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
        if ctx.is_void(&base_path) {
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
