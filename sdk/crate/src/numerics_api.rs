//! Implementation of the `numerics-api` interface. Mirrors the WIT
//! `kontor:built-in/numbers` shape exactly; arithmetic delegates to the
//! shared `numerics` crate so SDK and chain produce byte-identical
//! results.
//!
//! The wit_bindgen-generated types in this module (Decimal/Integer/
//! Sign/Ordering/NumericsError) are distinct Rust types from
//! `numerics::*` even though their shape is identical — trivial
//! From/Into impls bridge them.

use ::numerics as core_numerics;

use crate::Lib;
use crate::exports::root::component::numerics::{
    Decimal, Guest as NumericsGuest, Integer, NumericsError, Ordering, Sign,
};

// ─── type bridges: wit_bindgen ↔ shared crate ────────────────────────

impl From<Sign> for core_numerics::Sign {
    fn from(s: Sign) -> Self {
        match s {
            Sign::Plus => core_numerics::Sign::Plus,
            Sign::Minus => core_numerics::Sign::Minus,
        }
    }
}

impl From<core_numerics::Sign> for Sign {
    fn from(s: core_numerics::Sign) -> Self {
        match s {
            core_numerics::Sign::Plus => Sign::Plus,
            core_numerics::Sign::Minus => Sign::Minus,
        }
    }
}

impl From<core_numerics::Ordering> for Ordering {
    fn from(o: core_numerics::Ordering) -> Self {
        match o {
            core_numerics::Ordering::Less => Ordering::Less,
            core_numerics::Ordering::Equal => Ordering::Equal,
            core_numerics::Ordering::Greater => Ordering::Greater,
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

impl From<core_numerics::Error> for NumericsError {
    fn from(e: core_numerics::Error) -> Self {
        match e {
            core_numerics::Error::Message(s) => NumericsError::Message(s),
            core_numerics::Error::Overflow(s) => NumericsError::Overflow(s),
            core_numerics::Error::DivByZero(s) => NumericsError::DivByZero(s),
            core_numerics::Error::Syntax(s) => NumericsError::Syntax(s),
            core_numerics::Error::Validation(s) => NumericsError::Validation(s),
        }
    }
}

// ─── Guest impl: delegates to the shared crate ───────────────────────

impl NumericsGuest for Lib {
    fn u64_to_integer(i: u64) -> Integer {
        core_numerics::u64_to_integer(i).into()
    }

    fn s64_to_integer(i: i64) -> Integer {
        core_numerics::s64_to_integer(i).into()
    }

    fn string_to_integer(s: String) -> Result<Integer, NumericsError> {
        core_numerics::string_to_integer(&s)
            .map(Into::into)
            .map_err(Into::into)
    }

    fn integer_to_string(i: Integer) -> String {
        core_numerics::integer_to_string(i.into())
    }

    fn eq_integer(a: Integer, b: Integer) -> bool {
        core_numerics::eq_integer(a.into(), b.into())
    }

    fn cmp_integer(a: Integer, b: Integer) -> Ordering {
        core_numerics::cmp_integer(a.into(), b.into()).into()
    }

    fn add_integer(a: Integer, b: Integer) -> Result<Integer, NumericsError> {
        core_numerics::add_integer(a.into(), b.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn sub_integer(a: Integer, b: Integer) -> Result<Integer, NumericsError> {
        core_numerics::sub_integer(a.into(), b.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn mul_integer(a: Integer, b: Integer) -> Result<Integer, NumericsError> {
        core_numerics::mul_integer(a.into(), b.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn div_integer(a: Integer, b: Integer) -> Result<Integer, NumericsError> {
        core_numerics::div_integer(a.into(), b.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn sqrt_integer(i: Integer) -> Result<Integer, NumericsError> {
        core_numerics::sqrt_integer(i.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn integer_to_decimal(i: Integer) -> Result<Decimal, NumericsError> {
        core_numerics::integer_to_decimal(i.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn decimal_to_integer(d: Decimal) -> Result<Integer, NumericsError> {
        core_numerics::decimal_to_integer(d.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn u64_to_decimal(i: u64) -> Result<Decimal, NumericsError> {
        core_numerics::u64_to_decimal(i)
            .map(Into::into)
            .map_err(Into::into)
    }

    fn s64_to_decimal(i: i64) -> Result<Decimal, NumericsError> {
        core_numerics::s64_to_decimal(i)
            .map(Into::into)
            .map_err(Into::into)
    }

    fn f64_to_decimal(f: f64) -> Result<Decimal, NumericsError> {
        core_numerics::f64_to_decimal(f)
            .map(Into::into)
            .map_err(Into::into)
    }

    fn string_to_decimal(s: String) -> Result<Decimal, NumericsError> {
        core_numerics::string_to_decimal(&s)
            .map(Into::into)
            .map_err(Into::into)
    }

    fn decimal_to_string(d: Decimal) -> String {
        core_numerics::decimal_to_string(d.into())
    }

    fn eq_decimal(a: Decimal, b: Decimal) -> Result<bool, NumericsError> {
        core_numerics::eq_decimal(a.into(), b.into()).map_err(Into::into)
    }

    fn cmp_decimal(a: Decimal, b: Decimal) -> Ordering {
        core_numerics::cmp_decimal(a.into(), b.into()).into()
    }

    fn add_decimal(a: Decimal, b: Decimal) -> Result<Decimal, NumericsError> {
        core_numerics::add_decimal(a.into(), b.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn sub_decimal(a: Decimal, b: Decimal) -> Result<Decimal, NumericsError> {
        core_numerics::sub_decimal(a.into(), b.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn mul_decimal(a: Decimal, b: Decimal) -> Result<Decimal, NumericsError> {
        core_numerics::mul_decimal(a.into(), b.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn div_decimal(a: Decimal, b: Decimal) -> Result<Decimal, NumericsError> {
        core_numerics::div_decimal(a.into(), b.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn log10_decimal(a: Decimal) -> Result<Decimal, NumericsError> {
        core_numerics::log10_decimal(a.into())
            .map(Into::into)
            .map_err(Into::into)
    }
}
