use stdlib::*;

contract!(name = "arith");

// TODO: Fix import! macro for cross-contract calls
// import!(name = "fib", height = 0, tx_index = 0, path = "fib/wit");

#[derive(Clone, Default, StorageRoot)]
struct ArithStorage {
    // Store as string since Op doesn't impl Store
    pub last_op_str: Option<String>,
}

impl Guest for Arith {
    fn init(ctx: &ProcContext) {
        ArithStorage {
            last_op_str: Some("id".to_string()),
        }
        .init(ctx)
    }

    fn eval(ctx: &ProcContext, x: u64, op: Op) -> ArithReturn {
        let op_str = match &op {
            Op::Id => "id".to_string(),
            Op::Sum(_) => "sum".to_string(),
            Op::Mul(_) => "mul".to_string(),
            Op::Div(_) => "div".to_string(),
        };
        storage(ctx).set_last_op_str(ctx, Some(op_str));
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
        storage(ctx).last_op_str(ctx).map(|s| {
            match s.as_str() {
                "id" => Op::Id,
                "sum" => Op::Sum(Operand { y: 0 }),
                "mul" => Op::Mul(Operand { y: 0 }),
                "div" => Op::Div(Operand { y: 0 }),
                _ => Op::Id,
            }
        })
    }

    fn checked_sub(_: &ViewContext, x: String, y: String) -> Result<u64, Error> {
        let x = x.parse::<u64>()
            .map_err(|e| Error::Message(format!("Failed to parse x: {}", e)))?;
        let y = y.parse::<u64>()
            .map_err(|e| Error::Message(format!("Failed to parse y: {}", e)))?;
        x.checked_sub(y)
            .ok_or(Error::Message("less than 0".to_string()))
    }

    // for cycle detection test
    fn fib(_ctx: &ProcContext, n: u64) -> u64 {
        // TODO: Re-enable when import! is fixed
        // fib::fib(ctx.signer(), n)
        n // Placeholder
    }
}
