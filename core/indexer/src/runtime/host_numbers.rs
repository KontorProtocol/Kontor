use anyhow::Result;
use wasmtime::component::Accessor;

use super::{
    Decimal, Error, Integer, NumericOrdering, Runtime, fuel::Fuel, numerics, wit::kontor::built_in,
};

impl built_in::numbers::Host for Runtime {}

impl<T> built_in::numbers::HostWithStore<T> for Runtime {
    async fn u64_to_integer(accessor: &Accessor<T, Self>, i: u64) -> Result<Integer> {
        Fuel::NumbersU64ToInteger.consume(accessor)?;
        Ok(numerics::u64_to_integer(i))
    }

    async fn s64_to_integer(accessor: &Accessor<T, Self>, i: i64) -> Result<Integer> {
        Fuel::NumbersS64ToInteger.consume(accessor)?;
        Ok(numerics::s64_to_integer(i))
    }

    async fn string_to_integer(
        accessor: &Accessor<T, Self>,
        s: String,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersStringToInteger(s.len() as u64).consume(accessor)?;
        Ok(numerics::string_to_integer(&s))
    }

    async fn integer_to_string(accessor: &Accessor<T, Self>, i: Integer) -> Result<String> {
        let s = numerics::integer_to_string(i);
        Fuel::NumbersIntegerToString(s.len() as u64).consume(accessor)?;
        Ok(s)
    }

    async fn eq_integer(accessor: &Accessor<T, Self>, a: Integer, b: Integer) -> Result<bool> {
        Fuel::NumbersEqInteger.consume(accessor)?;
        Ok(numerics::eq_integer(a, b))
    }

    async fn cmp_integer(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<NumericOrdering> {
        Fuel::NumbersCmpInteger.consume(accessor)?;
        Ok(numerics::cmp_integer(a, b))
    }

    async fn add_integer(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersAddInteger.consume(accessor)?;
        Ok(numerics::add_integer(a, b))
    }

    async fn sub_integer(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersSubInteger.consume(accessor)?;
        Ok(numerics::sub_integer(a, b))
    }

    async fn mul_integer(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersMulInteger.consume(accessor)?;
        Ok(numerics::mul_integer(a, b))
    }

    async fn div_integer(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersDivInteger.consume(accessor)?;
        Ok(numerics::div_integer(a, b))
    }

    async fn mul_add_div_rem_integer(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
        carry: Integer,
        divisor: Integer,
    ) -> Result<Result<(Integer, Integer), Error>> {
        Fuel::NumbersMulAddDivRemInteger.consume(accessor)?;
        Ok(numerics::mul_add_div_rem_integer(a, b, carry, divisor))
    }

    async fn sqrt_integer(
        accessor: &Accessor<T, Self>,
        i: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersSqrtInteger.consume(accessor)?;
        Ok(numerics::sqrt_integer(i))
    }

    async fn integer_to_decimal(
        accessor: &Accessor<T, Self>,
        i: Integer,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersIntegerToDecimal.consume(accessor)?;
        Ok(numerics::integer_to_decimal(i))
    }

    async fn decimal_to_integer(
        accessor: &Accessor<T, Self>,
        d: Decimal,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersDecimalToInteger.consume(accessor)?;
        Ok(numerics::decimal_to_integer(d))
    }

    async fn u64_to_decimal(
        accessor: &Accessor<T, Self>,
        i: u64,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersU64ToDecimal.consume(accessor)?;
        Ok(numerics::u64_to_decimal(i))
    }

    async fn s64_to_decimal(
        accessor: &Accessor<T, Self>,
        i: i64,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersS64ToDecimal.consume(accessor)?;
        Ok(numerics::s64_to_decimal(i))
    }

    async fn f64_to_decimal(
        accessor: &Accessor<T, Self>,
        f: f64,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersF64ToDecimal.consume(accessor)?;
        Ok(numerics::f64_to_decimal(f))
    }

    async fn string_to_decimal(
        accessor: &Accessor<T, Self>,
        s: String,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersStringToDecimal(s.len() as u64).consume(accessor)?;
        Ok(numerics::string_to_decimal(&s))
    }

    async fn decimal_to_string(accessor: &Accessor<T, Self>, d: Decimal) -> Result<String> {
        let s = numerics::decimal_to_string(d);
        Fuel::NumbersDecimalToString(s.len() as u64).consume(accessor)?;
        Ok(s)
    }

    async fn eq_decimal(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<bool, Error>> {
        Fuel::NumbersEqDecimal.consume(accessor)?;
        Ok(numerics::eq_decimal(a, b))
    }

    async fn cmp_decimal(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<NumericOrdering> {
        Fuel::NumbersCmpDecimal.consume(accessor)?;
        Ok(numerics::cmp_decimal(a, b))
    }

    async fn add_decimal(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersAddDecimal.consume(accessor)?;
        Ok(numerics::add_decimal(a, b))
    }

    async fn sub_decimal(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersSubDecimal.consume(accessor)?;
        Ok(numerics::sub_decimal(a, b))
    }

    async fn mul_decimal(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersMulDecimal.consume(accessor)?;
        Ok(numerics::mul_decimal(a, b))
    }

    async fn div_decimal(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersDivDecimal.consume(accessor)?;
        Ok(numerics::div_decimal(a, b))
    }

    async fn log10_decimal(
        accessor: &Accessor<T, Self>,
        a: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersLog10Decimal.consume(accessor)?;
        Ok(numerics::log10_decimal(a))
    }
}
