use anyhow::Result;
use wasmtime::component::Accessor;

use super::{
    Decimal, Error, Integer, NumericOrdering, Runtime, fuel::Fuel, numerics, wit::kontor::built_in,
};

impl built_in::numbers::Host for Runtime {}

impl built_in::numbers::HostWithStore for Runtime {
    async fn u64_to_integer<T>(accessor: &Accessor<T, Self>, i: u64) -> Result<Integer> {
        Fuel::NumbersU64ToInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::u64_to_integer(i))
    }

    async fn s64_to_integer<T>(accessor: &Accessor<T, Self>, i: i64) -> Result<Integer> {
        Fuel::NumbersS64ToInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::s64_to_integer(i))
    }

    async fn string_to_integer<T>(
        accessor: &Accessor<T, Self>,
        s: String,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersStringToInteger(s.len() as u64)
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::string_to_integer(&s))
    }

    async fn integer_to_string<T>(accessor: &Accessor<T, Self>, i: Integer) -> Result<String> {
        let s = numerics::integer_to_string(i);
        Fuel::NumbersIntegerToString(s.len() as u64)
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(s)
    }

    async fn eq_integer<T>(accessor: &Accessor<T, Self>, a: Integer, b: Integer) -> Result<bool> {
        Fuel::NumbersEqInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::eq_integer(a, b))
    }

    async fn cmp_integer<T>(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<NumericOrdering> {
        Fuel::NumbersCmpInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::cmp_integer(a, b))
    }

    async fn add_integer<T>(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersAddInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::add_integer(a, b))
    }

    async fn sub_integer<T>(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersSubInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::sub_integer(a, b))
    }

    async fn mul_integer<T>(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersMulInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::mul_integer(a, b))
    }

    async fn div_integer<T>(
        accessor: &Accessor<T, Self>,
        a: Integer,
        b: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersDivInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::div_integer(a, b))
    }

    async fn sqrt_integer<T>(
        accessor: &Accessor<T, Self>,
        i: Integer,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersSqrtInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::sqrt_integer(i))
    }

    async fn integer_to_decimal<T>(
        accessor: &Accessor<T, Self>,
        i: Integer,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersIntegerToDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::integer_to_decimal(i))
    }

    async fn decimal_to_integer<T>(
        accessor: &Accessor<T, Self>,
        d: Decimal,
    ) -> Result<Result<Integer, Error>> {
        Fuel::NumbersDecimalToInteger
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::decimal_to_integer(d))
    }

    async fn u64_to_decimal<T>(
        accessor: &Accessor<T, Self>,
        i: u64,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersU64ToDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::u64_to_decimal(i))
    }

    async fn s64_to_decimal<T>(
        accessor: &Accessor<T, Self>,
        i: i64,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersS64ToDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::s64_to_decimal(i))
    }

    async fn f64_to_decimal<T>(
        accessor: &Accessor<T, Self>,
        f: f64,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersF64ToDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::f64_to_decimal(f))
    }

    async fn string_to_decimal<T>(
        accessor: &Accessor<T, Self>,
        s: String,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersStringToDecimal(s.len() as u64)
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::string_to_decimal(&s))
    }

    async fn decimal_to_string<T>(accessor: &Accessor<T, Self>, d: Decimal) -> Result<String> {
        let s = numerics::decimal_to_string(d);
        Fuel::NumbersDecimalToString(s.len() as u64)
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(s)
    }

    async fn eq_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<bool, Error>> {
        Fuel::NumbersEqDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::eq_decimal(a, b))
    }

    async fn cmp_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<NumericOrdering> {
        Fuel::NumbersCmpDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::cmp_decimal(a, b))
    }

    async fn add_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersAddDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::add_decimal(a, b))
    }

    async fn sub_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersSubDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::sub_decimal(a, b))
    }

    async fn mul_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersMulDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::mul_decimal(a, b))
    }

    async fn div_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
        b: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersDivDecimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::div_decimal(a, b))
    }

    async fn log10_decimal<T>(
        accessor: &Accessor<T, Self>,
        a: Decimal,
    ) -> Result<Result<Decimal, Error>> {
        Fuel::NumbersLog10Decimal
            .consume(
                accessor,
                accessor
                    .with(|mut access| access.get().gauge.clone())
                    .as_ref(),
            )
            .await?;
        Ok(numerics::log10_decimal(a))
    }
}
