//! Kontor's canonical Integer/Decimal arithmetic, shared between the
//! indexer runtime (host of the WIT `kontor:built-in/numbers` interface)
//! and `@kontor/sdk` (which re-exports these through its WASM Component
//! for use by TS dapps).
//!
//! Both Integer and Decimal are 256-bit signed values represented as
//! four `u64` limbs plus a sign. Decimal carries 18 fractional digits
//! (scale = 10^18). The implementation delegates to `fastnum::D256`
//! for decimal arithmetic and `num::BigInt` for unbounded-integer
//! arithmetic; the limb-based shape exists for the WIT wire format.

use core::cmp::Ordering as CoreOrdering;
use std::sync::LazyLock;

use fastnum::{
    D256, U256,
    bint::UInt,
    dec256,
    decimal::{self, Context, SignalsTraps},
};
use num::{BigInt, bigint::Sign as BigSign};

/// Decimal scale (18 fractional digits, i.e. 10^18).
const DECIMAL_18_DECS: D256 = dec256!(1_000_000_000_000_000_000);
const MIN_DECIMAL: D256 = dec256!(0.000_000_000_000_000_001);
const MAX_UINT64: D256 = dec256!(18446744073709551615);

/// Largest representable Integer/Decimal magnitude: 2^256 - 1.
static MAX_INT: LazyLock<BigInt> = LazyLock::new(|| {
    "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457"
        .parse::<BigInt>()
        .unwrap()
});

const CTX: Context = Context::default().with_signal_traps(SignalsTraps::empty());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sign {
    #[default]
    Plus,
    Minus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ordering {
    Less,
    Equal,
    Greater,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Integer {
    pub r0: u64,
    pub r1: u64,
    pub r2: u64,
    pub r3: u64,
    pub sign: Sign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Decimal {
    pub r0: u64,
    pub r1: u64,
    pub r2: u64,
    pub r3: u64,
    pub sign: Sign,
}

/// Error variants align with the WIT `error` variant Kontor contracts
/// see at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Message(String),
    Overflow(String),
    DivByZero(String),
    Syntax(String),
    Validation(String),
}

// ─── conversions: Integer ↔ BigInt ────────────────────────────────────

impl TryFrom<BigInt> for Integer {
    type Error = Error;

    fn try_from(big: BigInt) -> Result<Self, Error> {
        let (sign_, digits) = big.to_u64_digits();
        if digits.len() > 4 {
            return Err(Error::Overflow("oversized integer".to_string()));
        }
        let sign = if sign_ == BigSign::Minus {
            Sign::Minus
        } else {
            Sign::Plus
        };
        Ok(Integer {
            r0: if !digits.is_empty() { digits[0] } else { 0 },
            r1: if digits.len() > 1 { digits[1] } else { 0 },
            r2: if digits.len() > 2 { digits[2] } else { 0 },
            r3: if digits.len() > 3 { digits[3] } else { 0 },
            sign,
        })
    }
}

impl From<Integer> for BigInt {
    fn from(i: Integer) -> BigInt {
        let mut big: BigInt = i.r3.into();
        big = (big << 64) + i.r2;
        big = (big << 64) + i.r1;
        big = (big << 64) + i.r0;
        if i.sign == Sign::Minus {
            big = -big;
        }
        big
    }
}

// ─── conversions: Decimal ↔ D256 ─────────────────────────────────────

impl From<D256> for Decimal {
    fn from(dec_: D256) -> Self {
        let dec = dec_.with_ctx(CTX).quantize(MIN_DECIMAL);
        let mut dig: U256 = dec.digits();

        let filter: U256 = UInt::from_u64(0xffffffffffffffff);
        let r0 = dig.bitand(filter).to_u64().expect("masked to 64 bits");
        dig >>= 64;
        let r1 = dig.bitand(filter).to_u64().expect("masked to 64 bits");
        dig >>= 64;
        let r2 = dig.bitand(filter).to_u64().expect("masked to 64 bits");
        dig >>= 64;
        let r3 = dig.bitand(filter).to_u64().expect("masked to 64 bits");

        let sign = if dec.sign() == decimal::Sign::Minus {
            Sign::Minus
        } else {
            Sign::Plus
        };

        Decimal {
            r0,
            r1,
            r2,
            r3,
            sign,
        }
    }
}

impl From<Decimal> for D256 {
    fn from(d: Decimal) -> D256 {
        let d0 = D256::from(d.r0);
        let d1 = D256::from(d.r1);
        let d2 = D256::from(d.r2);
        let d3 = D256::from(d.r3);

        let ii: D256 = MAX_UINT64 + 1; // effectively left-shift 64
        let mut dec = d0 + d1 * ii + d2 * ii * ii + d3 * ii * ii * ii;

        if d.sign == Sign::Minus {
            dec = -dec;
        }

        dec / DECIMAL_18_DECS
    }
}

// ─── Integer ops ─────────────────────────────────────────────────────

pub fn u64_to_integer(i: u64) -> Integer {
    Integer {
        r0: i,
        r1: 0,
        r2: 0,
        r3: 0,
        sign: Sign::Plus,
    }
}

pub fn s64_to_integer(i: i64) -> Integer {
    let sign = if i < 0 { Sign::Minus } else { Sign::Plus };
    Integer {
        r0: i.unsigned_abs(),
        r1: 0,
        r2: 0,
        r3: 0,
        sign,
    }
}

pub fn string_to_integer(s: &str) -> Result<Integer, Error> {
    let i = match s.parse::<BigInt>() {
        Ok(i) => i,
        Err(e) => return Err(Error::Syntax(e.to_string())),
    };
    let max_int = MAX_INT.clone();
    if i > max_int || i < -max_int {
        return Err(Error::Overflow("result overflows Integer".to_string()));
    }
    i.try_into()
}

pub fn integer_to_string(i: Integer) -> String {
    let big: BigInt = i.into();
    big.to_string()
}

pub fn eq_integer(a: Integer, b: Integer) -> bool {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    big_a == big_b
}

pub fn cmp_integer(a: Integer, b: Integer) -> Ordering {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    match big_a.cmp(&big_b) {
        CoreOrdering::Less => Ordering::Less,
        CoreOrdering::Equal => Ordering::Equal,
        CoreOrdering::Greater => Ordering::Greater,
    }
}

pub fn add_integer(a: Integer, b: Integer) -> Result<Integer, Error> {
    let max_int = MAX_INT.clone();
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    let res = big_a + big_b;
    if res > max_int || res < -max_int {
        return Err(Error::Overflow("result overflows Integer".to_string()));
    }
    res.try_into()
}

pub fn sub_integer(a: Integer, b: Integer) -> Result<Integer, Error> {
    let max_int = MAX_INT.clone();
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    let res = big_a - big_b;
    if res > max_int || res < -max_int {
        return Err(Error::Overflow("result overflows Integer".to_string()));
    }
    res.try_into()
}

pub fn mul_integer(a: Integer, b: Integer) -> Result<Integer, Error> {
    let max_int = MAX_INT.clone();
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    let res = big_a * big_b;
    if res > max_int || res < -max_int {
        return Err(Error::Overflow("result overflows Integer".to_string()));
    }
    res.try_into()
}

pub fn div_integer(a: Integer, b: Integer) -> Result<Integer, Error> {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    if big_b == BigInt::ZERO {
        return Err(Error::DivByZero("integer divide by zero".to_string()));
    }
    (big_a / big_b).try_into()
}

pub fn sqrt_integer(i: Integer) -> Result<Integer, Error> {
    let big_i: BigInt = i.into();
    big_i.sqrt().try_into()
}

// ─── Decimal ops ─────────────────────────────────────────────────────

pub fn integer_to_decimal(i: Integer) -> Result<Decimal, Error> {
    let big: BigInt = i.into();
    let dec_ = big
        .to_string()
        .parse::<D256>()
        .map_err(|e| Error::Syntax(e.to_string()))?;
    let dec = dec_.with_ctx(CTX).quantize(MIN_DECIMAL);
    if dec.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()));
    }
    Ok(dec.into())
}

pub fn decimal_to_integer(d: Decimal) -> Result<Integer, Error> {
    let dec: D256 = d.into();
    let big = dec
        .trunc()
        .to_string()
        .parse::<BigInt>()
        .map_err(|e| Error::Syntax(e.to_string()))?;
    big.try_into()
}

fn num_to_decimal(n: impl Into<D256>) -> Result<Decimal, Error> {
    let dec: D256 = n.into();
    let res = dec.with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()));
    }
    Ok(res.into())
}

pub fn u64_to_decimal(i: u64) -> Result<Decimal, Error> {
    num_to_decimal(i)
}

pub fn s64_to_decimal(i: i64) -> Result<Decimal, Error> {
    num_to_decimal(i)
}

pub fn f64_to_decimal(f: f64) -> Result<Decimal, Error> {
    num_to_decimal(f)
}

pub fn string_to_decimal(s: &str) -> Result<Decimal, Error> {
    let dec = match s.parse::<D256>() {
        Ok(d) => d,
        Err(e) => return Err(Error::Syntax(e.to_string())),
    };
    let res = dec.with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()));
    }
    Ok(res.into())
}

pub fn decimal_to_string(d: Decimal) -> String {
    let dec: D256 = d.into();
    dec.to_string()
}

pub fn eq_decimal(a: Decimal, b: Decimal) -> Result<bool, Error> {
    let dec_a_: D256 = a.into();
    let dec_b_: D256 = b.into();

    let dec_a = dec_a_.with_ctx(CTX).quantize(MIN_DECIMAL);
    if dec_a.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()));
    }
    let dec_b = dec_b_.with_ctx(CTX).quantize(MIN_DECIMAL);
    if dec_b.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()));
    }
    Ok(dec_a == dec_b)
}

pub fn cmp_decimal(a: Decimal, b: Decimal) -> Ordering {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    match dec_a.cmp(&dec_b) {
        CoreOrdering::Less => Ordering::Less,
        CoreOrdering::Equal => Ordering::Equal,
        CoreOrdering::Greater => Ordering::Greater,
    }
}

pub fn add_decimal(a: Decimal, b: Decimal) -> Result<Decimal, Error> {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    let res = (dec_a + dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()));
    }
    Ok(res.into())
}

pub fn sub_decimal(a: Decimal, b: Decimal) -> Result<Decimal, Error> {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    let res = (dec_a - dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()));
    }
    Ok(res.into())
}

pub fn sqrt_decimal(a: Decimal) -> Result<Decimal, Error> {
    let dec_a: D256 = a.into();
    let res = dec_a.sqrt().with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal sqrt".to_string()));
    }
    Ok(res.into())
}

/// Truncate toward zero (drop the fractional part). Infallible. Contracts use this for
/// EXPLICIT round-down where they want an integer-valued decimal (e.g. AMM swap output).
pub fn trunc_decimal(a: Decimal) -> Decimal {
    let dec_a: D256 = a.into();
    dec_a.trunc().into()
}

pub fn mul_decimal(a: Decimal, b: Decimal) -> Result<Decimal, Error> {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    let res = (dec_a * dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()));
    }
    Ok(res.into())
}

pub fn div_decimal(a: Decimal, b: Decimal) -> Result<Decimal, Error> {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    if dec_b.is_zero() {
        return Err(Error::DivByZero("decimal divide by zero".to_string()));
    }
    let res = (dec_a / dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()));
    }
    Ok(res.into())
}

pub fn log10_decimal(a: Decimal) -> Result<Decimal, Error> {
    let dec_a: D256 = a.into();
    let res = (dec_a.log10()).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()));
    }
    Ok(res.into())
}
