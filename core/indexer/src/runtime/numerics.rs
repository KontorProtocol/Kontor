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
use num::BigInt;

use super::{Decimal, Error, Integer, NumericOrdering, NumericSign};

// ─── type conversions: indexer (wit_bindgen) ↔ shared (numerics) ─────

impl From<NumericSign> for core_numerics::Sign {
    fn from(s: NumericSign) -> Self {
        match s {
            NumericSign::Plus => core_numerics::Sign::Plus,
            NumericSign::Minus => core_numerics::Sign::Minus,
        }
    }
}

impl From<core_numerics::Sign> for NumericSign {
    fn from(s: core_numerics::Sign) -> Self {
        match s {
            core_numerics::Sign::Plus => NumericSign::Plus,
            core_numerics::Sign::Minus => NumericSign::Minus,
        }
    }
}

impl From<NumericOrdering> for core_numerics::Ordering {
    fn from(o: NumericOrdering) -> Self {
        match o {
            NumericOrdering::Less => core_numerics::Ordering::Less,
            NumericOrdering::Equal => core_numerics::Ordering::Equal,
            NumericOrdering::Greater => core_numerics::Ordering::Greater,
        }
    }
}

impl From<core_numerics::Ordering> for NumericOrdering {
    fn from(o: core_numerics::Ordering) -> Self {
        match o {
            core_numerics::Ordering::Less => NumericOrdering::Less,
            core_numerics::Ordering::Equal => NumericOrdering::Equal,
            core_numerics::Ordering::Greater => NumericOrdering::Greater,
        }
    }
}

impl From<Integer> for core_numerics::Integer {
    fn from(i: Integer) -> Self {
        core_numerics::Integer {
            r0: i.r0,
            r1: i.r1,
            r2: i.r2,
            r3: i.r3,
            sign: i.sign.into(),
        }
    }
}

impl From<core_numerics::Integer> for Integer {
    fn from(i: core_numerics::Integer) -> Self {
        Integer {
            r0: i.r0,
            r1: i.r1,
            r2: i.r2,
            r3: i.r3,
            sign: i.sign.into(),
        }
    }
}

impl From<Decimal> for core_numerics::Decimal {
    fn from(d: Decimal) -> Self {
        core_numerics::Decimal {
            r0: d.r0,
            r1: d.r1,
            r2: d.r2,
            r3: d.r3,
            sign: d.sign.into(),
        }
    }
}

impl From<core_numerics::Decimal> for Decimal {
    fn from(d: core_numerics::Decimal) -> Self {
        Decimal {
            r0: d.r0,
            r1: d.r1,
            r2: d.r2,
            r3: d.r3,
            sign: d.sign.into(),
        }
    }
}

impl From<core_numerics::Error> for Error {
    fn from(e: core_numerics::Error) -> Self {
        match e {
            core_numerics::Error::Message(s) => Error::Message(s),
            core_numerics::Error::Overflow(s) => Error::Overflow(s),
            core_numerics::Error::DivByZero(s) => Error::DivByZero(s),
            core_numerics::Error::Syntax(s) => Error::Syntax(s),
            core_numerics::Error::Validation(s) => Error::Validation(s),
        }
    }
}

// BigInt round-trip — kept here because a few indexer callsites use it
// directly (e.g. token gas-conversion). The shared crate exposes the
// limb-level conversions; this bridges to/from the indexer's Integer.

impl TryFrom<BigInt> for Integer {
    type Error = Error;
    fn try_from(big: BigInt) -> Result<Self, Error> {
        let i: core_numerics::Integer = big.try_into().map_err(Error::from)?;
        Ok(i.into())
    }
}

impl From<Integer> for BigInt {
    fn from(i: Integer) -> BigInt {
        let n: core_numerics::Integer = i.into();
        n.into()
    }
}

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

pub fn sqrt_decimal(a: Decimal) -> Result<Decimal, Error> {
    core_numerics::sqrt_decimal(a.into())
        .map(Into::into)
        .map_err(Into::into)
}

pub fn trunc_decimal(a: Decimal) -> Decimal {
    core_numerics::trunc_decimal(a.into()).into()
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use super::*;
    use crate::runtime::CheckedArithmetics;

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
        let max_int =
            "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457";
        let min_int =
            "-115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457";
        let oversized_int =
            "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_458";
        let oversized_dec =
            "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457.585";

        assert_eq!(
            Decimal::try_from(Integer::from(max_int)).unwrap(),
            Decimal::from(max_int)
        );
        assert_eq!(
            Decimal::try_from(Integer::from(min_int)).unwrap(),
            Decimal::from(min_int)
        );
        assert!(catch_unwind(|| Integer::from(oversized_int)).is_err());
        assert!(catch_unwind(|| Decimal::from(oversized_dec)).is_err());
        assert!(add_integer(Integer::from(max_int), Integer::from(1)).is_err());
        assert_eq!(
            add_integer(Integer::from(max_int), Integer::from(-1)).unwrap(),
            Integer::from(
                "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_456"
            ),
        );
        assert!(sub_integer(Integer::from(max_int), Integer::from(-1)).is_err());
        assert_eq!(
            sub_integer(Integer::from(max_int), Integer::from(1)).unwrap(),
            Integer::from(
                "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_456"
            ),
        );
        assert!(mul_integer(Integer::from(max_int), Integer::from(2)).is_err());
        assert_eq!(
            mul_integer(Integer::from(max_int), Integer::from(1)).unwrap(),
            Integer::from(max_int)
        );
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
