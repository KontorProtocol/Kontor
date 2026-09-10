#![no_std]
contract!(name = "arith");

use alloc::vec;
use built_in_types::numbers_types::{Decimal, Integer};
use stdlib::*;

interface!(name = "fib", path = "../fib/wit");

#[derive(Clone, Default, StorageRoot)]
struct ArithStorage {
    pub last_op: Option<Op>,
}

impl Guest for Arith {
    fn init(ctx: &ProcContext) -> Contract {
        ArithStorage {
            last_op: Some(Op::Id),
        }
        .init(ctx);
        ctx.contract()
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

    fn mul_add_div_rem(
        _: &ViewContext,
        a: String,
        b: String,
        carry: String,
        divisor: String,
    ) -> Result<Vec<String>, Error> {
        Integer::from(a.as_str())
            .checked_mul_add_div_rem(
                Integer::from(b.as_str()),
                Integer::from(carry.as_str()),
                Integer::from(divisor.as_str()),
            )
            .map(|(quotient, remainder)| vec![quotient.to_string(), remainder.to_string()])
    }

    fn integer_ops(_: &ViewContext, a: String, b: String) -> Result<Vec<String>, Error> {
        let a = Integer::from(a.as_str());
        let b = Integer::from(b.as_str());
        Ok(vec![
            a.add(b)?.to_string(),
            a.sub(b)?.to_string(),
            a.mul(b)?.to_string(),
        ])
    }

    fn decimal_units(_: &ViewContext, value: String) -> Vec<String> {
        const UNIT: Integer = Integer::from_u128(10u128.pow(18));
        let value = Decimal::from(value.as_str());
        let units = value.to_raw_units();
        vec![
            units.to_string(),
            Decimal::from_raw_units(units).to_string(),
            Decimal::from_raw_units(UNIT).to_string(),
        ]
    }

    // for cycle detection test
    fn fib(ctx: &ProcContext, contract_address: ContractAddress, n: u64) -> u64 {
        fib::fib(&contract_address, ctx.signer(), ctx.contract().address(), n)
    }
}
