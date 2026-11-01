use anyhow::Result;
use wasmtime::component::Access;

use super::{
    Decimal, Error, Integer, NumericOrdering, Runtime, fuel::Fuel, numerics, wit::kontor::built_in,
};

impl built_in::numbers::Host for Runtime {}

impl<T: Send> built_in::numbers::HostWithStore<T> for Runtime {
    async fn u64_to_integer(mut accessor: Access<'_, T, Self>, i: u64) -> Result<Integer> {
        Fuel::NumbersU64ToInteger.consume(&mut accessor)?;
        Ok(numerics::u64_to_integer(i))
    }

    async fn s64_to_integer(mut accessor: Access<'_, T, Self>, i: i64) -> Result<Integer> {
        Fuel::NumbersS64ToInteger.consume(&mut accessor)?;
        Ok(numerics::s64_to_integer(i))
    }

    async fn string_to_integer(
        mut accessor: Access<'_, T, Self>,
        s: String,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersStringToInteger(s.len() as u64).consume(&mut accessor)?;
        Ok(numerics::string_to_integer(&s))
    }

    async fn integer_to_string(mut accessor: Access<'_, T, Self>, i: Integer) -> Result<String> {
        let s = numerics::integer_to_string(i);
        Fuel::NumbersIntegerToString(s.len() as u64).consume(&mut accessor)?;
        Ok(s)
    }

    async fn eq_integer(mut accessor: Access<'_, T, Self>, a: Integer, b: Integer) -> Result<bool> {
        Fuel::NumbersEqInteger.consume(&mut accessor)?;
        Ok(numerics::eq_integer(a, b))
    }

    async fn cmp_integer(
        mut accessor: Access<'_, T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<NumericOrdering> {
        Fuel::NumbersCmpInteger.consume(&mut accessor)?;
        Ok(numerics::cmp_integer(a, b))
    }

    async fn add_integer(
        mut accessor: Access<'_, T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersAddInteger.consume(&mut accessor)?;
        Ok(numerics::add_integer(a, b))
    }

    async fn sub_integer(
        mut accessor: Access<'_, T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersSubInteger.consume(&mut accessor)?;
        Ok(numerics::sub_integer(a, b))
    }

    async fn mul_integer(
        mut accessor: Access<'_, T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersMulInteger.consume(&mut accessor)?;
        Ok(numerics::mul_integer(a, b))
    }

    async fn div_integer(
        mut accessor: Access<'_, T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersDivInteger.consume(&mut accessor)?;
        Ok(numerics::div_integer(a, b))
    }

    async fn mul_add_div_rem_integer(
        mut accessor: Access<'_, T, Self>,
        a: Integer,
        b: Integer,
        carry: Integer,
        divisor: Integer,
    ) -> Result<Result<(Integer, Integer), Error>> {
        Fuel::NumbersMulAddDivRemInteger.consume(&mut accessor)?;
        Ok(numerics::mul_add_div_rem_integer(a, b, carry, divisor))
    }

    async fn sqrt_integer(
        mut accessor: Access<'_, T, Self>,
        i: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersSqrtInteger.consume(&mut accessor)?;
        Ok(numerics::sqrt_integer(i))
    }

    async fn integer_to_decimal(
        mut accessor: Access<'_, T, Self>,
        i: Integer,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersIntegerToDecimal.consume(&mut accessor)?;
        Ok(numerics::integer_to_decimal(i))
    }

    async fn decimal_to_integer(
        mut accessor: Access<'_, T, Self>,
        d: Decimal,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersDecimalToInteger.consume(&mut accessor)?;
        Ok(numerics::decimal_to_integer(d))
    }

    async fn u64_to_decimal(
        mut accessor: Access<'_, T, Self>,
        i: u64,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersU64ToDecimal.consume(&mut accessor)?;
        Ok(numerics::u64_to_decimal(i))
    }

    async fn s64_to_decimal(
        mut accessor: Access<'_, T, Self>,
        i: i64,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersS64ToDecimal.consume(&mut accessor)?;
        Ok(numerics::s64_to_decimal(i))
    }

    async fn f64_to_decimal(
        mut accessor: Access<'_, T, Self>,
        f: f64,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersF64ToDecimal.consume(&mut accessor)?;
        Ok(numerics::f64_to_decimal(f))
    }

    async fn string_to_decimal(
        mut accessor: Access<'_, T, Self>,
        s: String,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersStringToDecimal(s.len() as u64).consume(&mut accessor)?;
        Ok(numerics::string_to_decimal(&s))
    }

    async fn decimal_to_string(mut accessor: Access<'_, T, Self>, d: Decimal) -> Result<String> {
        let s = numerics::decimal_to_string(d);
        Fuel::NumbersDecimalToString(s.len() as u64).consume(&mut accessor)?;
        Ok(s)
    }

    async fn eq_decimal(
        mut accessor: Access<'_, T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<bool, Error>> {
        Fuel::NumbersEqDecimal.consume(&mut accessor)?;
        Ok(numerics::eq_decimal(a, b))
    }

    async fn cmp_decimal(
        mut accessor: Access<'_, T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<NumericOrdering> {
        Fuel::NumbersCmpDecimal.consume(&mut accessor)?;
        Ok(numerics::cmp_decimal(a, b))
    }

    async fn add_decimal(
        mut accessor: Access<'_, T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersAddDecimal.consume(&mut accessor)?;
        Ok(numerics::add_decimal(a, b))
    }

    async fn sub_decimal(
        mut accessor: Access<'_, T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersSubDecimal.consume(&mut accessor)?;
        Ok(numerics::sub_decimal(a, b))
    }

    async fn mul_decimal(
        mut accessor: Access<'_, T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersMulDecimal.consume(&mut accessor)?;
        Ok(numerics::mul_decimal(a, b))
    }

    async fn div_decimal(
        mut accessor: Access<'_, T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersDivDecimal.consume(&mut accessor)?;
        Ok(numerics::div_decimal(a, b))
    }

    async fn log10_decimal(
        mut accessor: Access<'_, T, Self>,
        a: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersLog10Decimal.consume(&mut accessor)?;
        Ok(numerics::log10_decimal(a))
    }
}
