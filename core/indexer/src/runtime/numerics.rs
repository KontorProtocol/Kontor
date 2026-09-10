//! Thin wrapper around the shared `numerics` crate. The arithmetic
//! logic lives there; this module just bridges between the indexer's
//! wit_bindgen-generated `Decimal`/`Integer`/`Sign`/`Ordering`/`Error`
//! types and the shared crate's identically-shaped types.
//!
//! Why the split: `@kontor/sdk` also needs the same arithmetic for
//! TS-side Decimal/Integer classes. Putting the math in a shared crate
//! gives both sides byte-for-byte identical semantics with zero
//! re-implementation risk.

use ::numerics as core_numerics;

use super::{Decimal, Error, Integer, NumericOrdering};

// The wit-shape ↔ numerics-crate conversions live in `built-in-types` (which
// owns the shared types); the wrappers below use them via `.into()`.

// ─── wrapper functions: same signatures as before, delegating ───────

pub fn u64_to_integer(i: u64) -> Integer {
    core_numerics::u64_to_integer(i).into()
}

pub fn s64_to_integer(i: i64) -> Integer {
    core_numerics::s64_to_integer(i).into()
}

pub fn string_to_integer(s: &str) -> Result<Integer, Error> {
    core_numerics::string_to_integer(s)
        .map(Into::into)
        .map_err(Into::into)
}

pub fn integer_to_string(i: Integer) -> String {
    core_numerics::integer_to_string(i.into())
}

pub fn eq_integer(a: Integer, b: Integer) -> bool {
    core_numerics::eq_integer(a.into(), b.into())
}

pub fn cmp_integer(a: Integer, b: Integer) -> NumericOrdering {
    core_numerics::cmp_integer(a.into(), b.into()).into()
}

pub fn add_integer(a: Integer, b: Integer) -> Result<Integer, Error> {
    core_numerics::add_integer(a.into(), b.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn sub_integer(a: Integer, b: Integer) -> Result<Integer, Error> {
    core_numerics::sub_integer(a.into(), b.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn mul_integer(a: Integer, b: Integer) -> Result<Integer, Error> {
    core_numerics::mul_integer(a.into(), b.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn div_integer(a: Integer, b: Integer) -> Result<Integer, Error> {
    core_numerics::div_integer(a.into(), b.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn sqrt_integer(i: Integer) -> Result<Integer, Error> {
    core_numerics::sqrt_integer(i.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn mul_add_div_rem_integer(
    a: Integer,
    b: Integer,
    carry: Integer,
    divisor: Integer,
) -> Result<(Integer, Integer), Error> {
    core_numerics::mul_add_div_rem_integer(a.into(), b.into(), carry.into(), divisor.into())
        .map(|(quotient, remainder)| (quotient.into(), remainder.into()))
        .map_err(Into::into)
}

pub fn integer_to_decimal(i: Integer) -> Result<Decimal, Error> {
    core_numerics::integer_to_decimal(i.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn decimal_to_integer(d: Decimal) -> Result<Integer, Error> {
    core_numerics::decimal_to_integer(d.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn u64_to_decimal(i: u64) -> Result<Decimal, Error> {
    core_numerics::u64_to_decimal(i)
        .map(Into::into)
        .map_err(Into::into)
}

pub fn s64_to_decimal(i: i64) -> Result<Decimal, Error> {
    core_numerics::s64_to_decimal(i)
        .map(Into::into)
        .map_err(Into::into)
}

pub fn f64_to_decimal(f: f64) -> Result<Decimal, Error> {
    core_numerics::f64_to_decimal(f)
        .map(Into::into)
        .map_err(Into::into)
}

pub fn string_to_decimal(s: &str) -> Result<Decimal, Error> {
    core_numerics::string_to_decimal(s)
        .map(Into::into)
        .map_err(Into::into)
}

pub fn decimal_to_string(d: Decimal) -> String {
    core_numerics::decimal_to_string(d.into())
}

pub fn eq_decimal(a: Decimal, b: Decimal) -> Result<bool, Error> {
    core_numerics::eq_decimal(a.into(), b.into()).map_err(Into::into)
}

pub fn cmp_decimal(a: Decimal, b: Decimal) -> NumericOrdering {
    core_numerics::cmp_decimal(a.into(), b.into()).into()
}

pub fn add_decimal(a: Decimal, b: Decimal) -> Result<Decimal, Error> {
    core_numerics::add_decimal(a.into(), b.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn sub_decimal(a: Decimal, b: Decimal) -> Result<Decimal, Error> {
    core_numerics::sub_decimal(a.into(), b.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn mul_decimal(a: Decimal, b: Decimal) -> Result<Decimal, Error> {
    core_numerics::mul_decimal(a.into(), b.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn div_decimal(a: Decimal, b: Decimal) -> Result<Decimal, Error> {
    core_numerics::div_decimal(a.into(), b.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn log10_decimal(a: Decimal) -> Result<Decimal, Error> {
    core_numerics::log10_decimal(a.into())
        .map(Into::into)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use anyhow::Result as TestResult;

    use super::*;
    use crate::runtime::{CheckedArithmetics, ContractAddress, TransactionContext, from_wave_expr};
    use crate::test_utils::test_runtime;

    #[tokio::test]
    async fn reward_arithmetic_through_contract_host() -> TestResult<()> {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        runtime
            .set_context(1, Some(TransactionContext::builder().build()), None, None)
            .await;
        runtime
            .storage
            .insert_contract(
                "arith",
                include_bytes!("../../../../test-contracts/binaries/arith.wasm.br"),
            )
            .await?;
        let address = ContractAddress {
            name: "arith".into(),
            height: 1,
            tx_index: 0,
        };
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        for (a, b, carry, divisor, expected) in [
            ("10", "2", "1", "3", ("7", "0")),
            ("1", "1", "0", "3", ("0", "1")),
            (max, max, "1", max, (max, "1")),
        ] {
            let value = runtime
                .execute(
                    None,
                    None,
                    &address,
                    &format!("mul-add-div-rem(\"{a}\", \"{b}\", \"{carry}\", \"{divisor}\")"),
                )
                .await?;
            let actual = from_wave_expr::<Result<Vec<String>, Error>>(&value)?;
            assert_eq!(actual, vec![expected.0.to_string(), expected.1.to_string()]);
            let native = Integer::from(a).checked_mul_add_div_rem(
                Integer::from(b),
                Integer::from(carry),
                Integer::from(divisor),
            )?;
            assert_eq!(actual, vec![native.0.to_string(), native.1.to_string()]);
        }
        for a in [max.to_string(), format!("-{max}")] {
            let value = runtime
                .execute(
                    None,
                    None,
                    &address,
                    &format!("integer-ops(\"{a}\", \"0\")"),
                )
                .await?;
            assert_eq!(
                from_wave_expr::<Result<Vec<String>, Error>>(&value)?,
                vec![a.clone(), a, "0".into()]
            );
        }
        let value = runtime
            .execute(None, None, &address, "decimal-units(\"-1.25\")")
            .await?;
        assert_eq!(
            from_wave_expr::<Vec<String>>(&value),
            vec!["-1250000000000000000", "-1.25", "1"]
        );
        let value = runtime
            .execute(
                None,
                None,
                &address,
                &format!("integer-ops(\"{max}\", \"1\")"),
            )
            .await?;
        assert!(matches!(
            from_wave_expr::<Result<Vec<String>, Error>>(&value),
            Err(Error::Overflow(_))
        ));
        for (expr, expected) in [
            (
                "mul-add-div-rem(\"1\", \"1\", \"0\", \"0\")".to_string(),
                "zero",
            ),
            (
                "mul-add-div-rem(\"-1\", \"1\", \"0\", \"1\")".to_string(),
                "negative",
            ),
            (
                format!("mul-add-div-rem(\"{max}\", \"{max}\", \"0\", \"1\")"),
                "overflow",
            ),
        ] {
            let value = runtime.execute(None, None, &address, &expr).await?;
            let error = from_wave_expr::<Result<Vec<String>, Error>>(&value).unwrap_err();
            assert!(matches!(
                (expected, error),
                ("zero", Error::DivByZero(_))
                    | ("negative", Error::Validation(_))
                    | ("overflow", Error::Overflow(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn test_numerics() {
        assert!(Integer::from(123) == 123.into());
        assert!(
            Integer::from("57843975908437589027340573245")
                == "57843975908437589027340573245".into()
        );
        assert_eq!(Integer::from(123) + 123.into(), 246.into());
        assert_eq!(Integer::from(123).add(123.into()).unwrap(), 246.into());
        assert_eq!(Integer::from(123) - 21.into(), 102.into());
        assert_eq!(Integer::from(123).sub(21.into()).unwrap(), 102.into());
        assert_eq!(Integer::from(5) * 6.into(), 30.into());
        assert_eq!(Integer::from(5).mul(6.into()).unwrap(), 30.into());
        assert_eq!(Integer::from(5) / 2.into(), 2.into());
        assert_eq!(Integer::from(5).div(2.into()).unwrap(), 2.into());
        assert_eq!(Integer::from(-5) / 2.into(), (-2).into());
        assert_eq!(
            Integer::from("-1000000000000000000000000000") / (-2).into(),
            ("500000000000000000000000000").into()
        );
        assert_eq!(
            Decimal::try_from(Integer::from(123)).unwrap() / 10u64.try_into().unwrap(),
            "12.3".into()
        );
        assert_eq!(
            decimal_to_integer(Decimal::from("1.999")).unwrap(),
            Integer::from("1")
        );
        assert_eq!(
            decimal_to_integer(Decimal::from("-1.999")).unwrap(),
            Integer::from("-1")
        );
    }

    #[test]
    fn test_runtime_decimal_operations() {
        assert!(Decimal::try_from(123.0f64).unwrap() == "123".into());
        assert!(
            Decimal::from("57843975908.437589027340573245")
                == "57843975908.437589027340573245".into()
        );
        assert_eq!(
            Decimal::try_from(123.0f64).unwrap() + "123.0".into(),
            "246.0".into()
        );
        assert_eq!(
            Decimal::try_from(123.0)
                .unwrap()
                .add(Decimal::try_from(123.0f64).unwrap())
                .unwrap(),
            Decimal::try_from(246.0f64).unwrap()
        );
        assert_eq!(
            Decimal::try_from(123.0f64).unwrap() - Decimal::try_from(21.0f64).unwrap(),
            Decimal::try_from(102.0f64).unwrap()
        );
        assert_eq!(
            Decimal::try_from(123.0)
                .unwrap()
                .sub(Decimal::try_from(21.0f64).unwrap())
                .unwrap(),
            Decimal::try_from(102.0f64).unwrap()
        );
        assert_eq!(
            Decimal::try_from(-123.0f64).unwrap() * Decimal::try_from(0.5f64).unwrap(),
            Decimal::try_from(-61.5f64).unwrap()
        );
        assert_eq!(
            Decimal::try_from(-123.0)
                .unwrap()
                .mul(Decimal::try_from(0.5f64).unwrap())
                .unwrap(),
            Decimal::try_from(-61.5f64).unwrap()
        );
        assert!(
            catch_unwind(|| Decimal::from("1000000000000000000000000000000000000")
                * "1000000000000000000000000000000000000".into())
            .is_err()
        );
        assert_eq!(
            Decimal::try_from(-123.0f64).unwrap() / Decimal::try_from(2.0f64).unwrap(),
            Decimal::try_from(-61.5f64).unwrap()
        );
        assert_eq!(
            Decimal::try_from(-123.0)
                .unwrap()
                .div(Decimal::try_from(2.0f64).unwrap())
                .unwrap(),
            Decimal::try_from(-61.5f64).unwrap()
        );
        assert!(
            catch_unwind(
                || Decimal::try_from(10.0f64).unwrap() / Decimal::try_from(0.0f64).unwrap()
            )
            .is_err()
        );
        assert_eq!(
            Decimal::from("-1000000000000000000000000000") / Decimal::try_from(-2i64).unwrap(),
            ("500000000000000000000000000").into()
        );
        assert_eq!(
            Decimal::from("-100000000000000000000000000000000000000000000.000001")
                / Decimal::try_from(-2i64).unwrap(),
            ("50000000000000000000000000000000000000000000.0000005").into()
        );
    }

    #[test]
    fn test_numerics_limits() {
        let decimal_whole_limit = "115792089237316195423570985008687907853269984665640564039457";
        let max_int =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let oversized_int =
            "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert_eq!(
            Decimal::try_from(Integer::from(decimal_whole_limit)).unwrap(),
            Decimal::from(decimal_whole_limit)
        );
        assert!(Decimal::try_from(Integer::from(decimal_whole_limit) + Integer::from(1)).is_err());
        let max = Integer::from(max_int);
        assert!(Decimal::try_from(max).is_err());
        assert!(catch_unwind(|| Integer::from(oversized_int)).is_err());
        assert!(
            catch_unwind(|| Decimal::from(
                "115792089237316195423570985008687907853269984665640564039457.585"
            ))
            .is_err()
        );
        assert!(add_integer(max, Integer::from(1)).is_err());
        assert!(sub_integer(max, Integer::from(-1)).is_err());
        assert!(mul_integer(max, Integer::from(2)).is_err());
        assert_eq!(
            add_integer(
                sub_integer(max, Integer::from(1)).unwrap(),
                Integer::from(1)
            )
            .unwrap(),
            max
        );
        assert_eq!(mul_integer(max, Integer::from(1)).unwrap(), max);
    }

    #[test]
    fn test_numerics_defaults() {
        let x = Decimal::default();
        assert_eq!(x, 0u64.try_into().unwrap());
        let x = Integer::default();
        assert_eq!(x, Integer::from(0));
    }

    #[test]
    fn test_decimals_scientific() {
        let x = Decimal::from("1e-9");
        assert_eq!(x, Decimal::from("0.000000001"));
        let x = Decimal::from("1e-3");
        assert_eq!(x, Decimal::from("0.001"));
        let x = Decimal::from("100_000");
        assert_eq!(x, Decimal::from("100000"));
    }
}
