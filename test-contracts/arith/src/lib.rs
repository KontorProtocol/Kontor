#![no_std]
contract!(name = "arith");

use stdlib::*;

interface!(name = "fib", path = "fib/wit");

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
        ctx.model().set_last_op(Some(op));
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
        ctx.model().last_op().map(|op| op.load())
    }

    fn checked_sub(_: &ViewContext, x: String, y: String) -> Result<u64, Error> {
        let x = x.parse::<u64>()?;
        let y = y.parse::<u64>()?;
        x.checked_sub(y)
            .ok_or(Error::Message("less than 0".to_string()))
    }

    // for cycle detection test
    fn fib(ctx: &ProcContext, contract_address: ContractAddress, n: u64) -> u64 {
        fib::fib(&contract_address, ctx.signer(), get_contract_address(), n)
    }
}
