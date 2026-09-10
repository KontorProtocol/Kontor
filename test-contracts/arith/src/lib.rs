#![no_std]
contract!(name = "arith");

use alloc::vec;
use built_in_types::numbers_types::{Decimal, Integer};
use stdlib::*;

interface!(name = "fib", path = "../fib/wit");

#[derive(Clone, Default, StorageRoot)]
struct ArithStorage {
    pub last_op: Option<Op>,
    pub optional_integer: Option<Integer>,
    pub decimals: Map<u64, Decimal>,
    pub numbers: Map<u64, NumericRecord>,
}

#[derive(Clone, Storage)]
#[index(by_integer, by = integer, sort = decimal, include = (integer))]
struct NumericRecord {
    integer: Integer,
    decimal: Decimal,
}

impl Guest for Arith {
    fn init(ctx: &ProcContext) -> Contract {
        ArithStorage {
            last_op: Some(Op::Id),
            ..ArithStorage::default()
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

    fn put_numbers(ctx: &ProcContext, key: u64, integer: String, decimal: String) {
        let integer = Integer::from(integer.as_str());
        let decimal = Decimal::from(decimal.as_str());
        let model = ctx.model();
        model.set_optional_integer(Some(integer));
        model.decimals().set(&key, decimal);
        model
            .numbers()
            .set(&key, NumericRecord { integer, decimal });
    }

    fn change_integer(ctx: &ProcContext, key: u64, integer: String) {
        ctx.model()
            .numbers()
            .get(&key)
            .unwrap()
            .set_integer(Integer::from(integer.as_str()));
    }

    fn remove_numbers(ctx: &ProcContext, key: u64) {
        let model = ctx.model();
        model.set_optional_integer(None);
        model.decimals().remove(&key);
        model.numbers().remove(&key);
    }

    fn stored_numbers(ctx: &ViewContext, key: u64) -> Option<Vec<String>> {
        let model = ctx.model();
        model.numbers().get(&key).map(|record| {
            vec![
                record.integer().to_string(),
                record.decimal().to_string(),
                model.decimals().get(&key).unwrap().to_string(),
            ]
        })
    }

    fn optional_integer(ctx: &ViewContext) -> Option<String> {
        ctx.model()
            .optional_integer()
            .map(|value| value.to_string())
    }

    fn number_keys(ctx: &ViewContext) -> Vec<u64> {
        ctx.model().decimals().keys().collect()
    }

    fn number_index(ctx: &ViewContext, integer: String) -> Vec<String> {
        ctx.model()
            .numbers()
            .by_integer(Integer::from(integer.as_str()))
            .values()
            .map(|value| format!("{}:{}", value.integer, value.decimal))
            .collect()
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
