macros::contract!(name = "arith");

impl Store for Operand {
    fn __set(&self, ctx: &impl WriteContext, base_path: DotPathBuf) {
        ctx.write_storage()
            .set_u64(&base_path.push("y").to_string(), self.y);
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
        ctx.read_storage()
            .get_u64(&self.base_path.push("y").to_string())
            .unwrap()
    }

    pub fn set_y(&self, ctx: &impl WriteContext, value: u64) {
        ctx.write_storage()
            .set_u64(&self.base_path.push("y").to_string(), value)
    }

    pub fn load(&self, ctx: &impl ReadContext) -> Operand {
        Operand { y: self.y(ctx) }
    }
}

impl Store for Op {
    fn __set(&self, ctx: &impl WriteContext, base_path: DotPathBuf) {
        match self {
            Op::Id => ctx
                .write_storage()
                .set_void(&base_path.push("id").to_string()),
            Op::Sum(operand) => operand.__set(ctx, base_path.push("sum")),
            Op::Mul(operand) => operand.__set(ctx, base_path.push("mul")),
            Op::Div(operand) => operand.__set(ctx, base_path.push("div")),
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
            .read_storage()
            .matching_path(&format!(r"^{}.(id|sum|mul|div)(\..*|$)", base_path))
            .unwrap();
        match path {
            p if p.starts_with(&base_path.push("id").to_string()) => OpWrapper::Id,
            p if p.starts_with(&base_path.push("sum").to_string()) => {
                OpWrapper::Sum(OperandWrapper::new(ctx, base_path.push("sum")))
            }
            p if p.starts_with(&base_path.push("mul").to_string()) => {
                OpWrapper::Mul(OperandWrapper::new(ctx, base_path.push("mul")))
            }
            p if p.starts_with(&base_path.push("div").to_string()) => {
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
    fn __set(&self, ctx: &impl WriteContext, base_path: DotPathBuf) {
        match self.last_op {
            Some(op) => op.__set(ctx, base_path.push("last_op")),
            None => ctx
                .write_storage()
                .set_void(&base_path.push("last_op").to_string()),
        }
    }
}

impl ArithStorage {
    pub fn init(&self, ctx: &impl WriteContext) {
        self.__set(ctx, DotPathBuf::new())
    }
}

struct Storage;

impl Storage {
    pub fn last_op(ctx: &impl ReadContext) -> Option<OpWrapper> {
        let base_path = DotPathBuf::new().push("last_op");
        if ctx.read_storage().is_void(&base_path.to_string()) {
            None
        } else {
            Some(OpWrapper::new(ctx, base_path))
        }
    }

    pub fn set_last_op(ctx: &impl WriteContext, value: Option<Op>) {
        let base_path = DotPathBuf::new().push("last_op");
        match value {
            Some(op) => op.__set(ctx, base_path),
            None => ctx.write_storage().set_void(&base_path.to_string()),
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
