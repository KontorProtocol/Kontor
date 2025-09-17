use std::cmp::Ordering;

use anyhow::Result;
use fastnum::{
    D256, U256,
    bint::UInt,
    dec256,
    decimal::{self, Context, SignalsTraps},
};
use num::{BigInt, Zero, bigint::Sign};

use super::{Decimal, Error, Integer, NumericOrdering, NumericSign};

const DECIMAL_18_DECS: D256 = dec256!(1_000_000_000_000_000_000);
const MIN_DECIMAL: D256 = dec256!(0.000_000_000_000_000_001);
const MAX_UINT64: D256 = dec256!(18446744073709551616);
const CTX: Context = Context::default().with_signal_traps(SignalsTraps::empty());

impl From<BigInt> for Integer {
    fn from(big: BigInt) -> Self {
        let (sign_, digits) = big.to_u64_digits();
        if digits.len() > 4 {
            panic!("oversized integer");
        }
        let sign = if sign_ == Sign::Minus {
            NumericSign::Minus
        } else {
            NumericSign::Plus
        };

        Integer {
            r0: if !digits.is_empty() { digits[0] } else { 0 },
            r1: if digits.len() > 1 { digits[1] } else { 0 },
            r2: if digits.len() > 2 { digits[2] } else { 0 },
            r3: if digits.len() > 3 { digits[3] } else { 0 },
            sign,
        }
    }
}

impl From<Integer> for BigInt {
    fn from(i: Integer) -> BigInt {
        let mut big: BigInt = i.r3.into();
        big = (big << 64) + i.r2;
        big = (big << 64) + i.r1;
        big = (big << 64) + i.r0;

        if i.sign == NumericSign::Minus {
            big = -big
        };

        big
    }
}

impl From<D256> for Decimal {
    fn from(dec_: D256) -> Self {
        let dec = dec_.with_ctx(CTX).quantize(MIN_DECIMAL);
        let mut dig: U256 = dec.digits();

        let filter: U256 = UInt::from_u64(0xffffffffffffffff);
        let r0 = dig.bitand(filter);
        dig >>= 64;
        let r1 = dig.bitand(filter);
        dig >>= 64;
        let r2 = dig.bitand(filter);
        dig >>= 64;
        let r3 = dig.bitand(filter);

        let sign = if dec.sign() == decimal::Sign::Minus {
            NumericSign::Minus
        } else {
            NumericSign::Plus
        };

        Decimal {
            r0: r0.to_u64().unwrap(),
            r1: r1.to_u64().unwrap(),
            r2: r2.to_u64().unwrap(),
            r3: r3.to_u64().unwrap(),
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

        let ii = MAX_UINT64;
        let mut dec = d0 + d1 * ii + d2 * ii * ii + d3 * ii * ii * ii;

        if d.sign == NumericSign::Minus {
            dec = -dec
        };

        dec / DECIMAL_18_DECS
    }
}

pub fn u64_to_integer(i: u64) -> Result<Integer> {
    Ok(Integer {
        r0: i,
        r1: 0,
        r2: 0,
        r3: 0,
        sign: NumericSign::Plus,
    })
}

pub fn s64_to_integer(i: i64) -> Result<Integer> {
    let sign = if i < 0 {
        NumericSign::Minus
    } else {
        NumericSign::Plus
    };
    Ok(Integer {
        r0: i.unsigned_abs(),
        r1: 0,
        r2: 0,
        r3: 0,
        sign,
    })
}

pub fn string_to_integer(s: &str) -> Result<Integer> {
    let i = s.parse::<BigInt>()?;
    Ok(i.into())
}

pub fn integer_to_string(i: Integer) -> Result<String> {
    let big_i: BigInt = i.into();
    Ok(big_i.to_string())
}

pub fn eq_integer(a: Integer, b: Integer) -> Result<bool> {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    Ok(big_a == big_b)
}

pub fn cmp_integer(a: Integer, b: Integer) -> Result<NumericOrdering> {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    Ok(match big_a.cmp(&big_b) {
        Ordering::Less => NumericOrdering::Less,
        Ordering::Equal => NumericOrdering::Equal,
        Ordering::Greater => NumericOrdering::Greater,
    })
}

pub fn add_integer(a: Integer, b: Integer) -> Result<Integer> {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    Ok((big_a + big_b).into())
}

pub fn sub_integer(a: Integer, b: Integer) -> Result<Integer> {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    Ok((big_a - big_b).into())
}

pub fn mul_integer(a: Integer, b: Integer) -> Result<Integer> {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    Ok((big_a * big_b).into())
}

pub fn div_integer(a: Integer, b: Integer) -> Result<Integer> {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    if big_b == BigInt::ZERO {
        return Err(Error::DivByZero("integer divide by zero".to_string()).into());
    }
    Ok((big_a / big_b).into())
}

pub fn integer_to_decimal(i: Integer) -> Result<Decimal> {
    let big: BigInt = i.into();
    let dec_ = big.to_string().parse::<D256>()?;
    let dec = dec_.with_ctx(CTX).quantize(MIN_DECIMAL);
    if dec.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(dec.into())
}

fn num_to_decimal(n: impl Into<D256>) -> Result<Decimal> {
    let dec: D256 = n.into();
    let res = dec.with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(res.into())
}

pub fn u64_to_decimal(i: u64) -> Result<Decimal> {
    num_to_decimal(i)
}

pub fn s64_to_decimal(i: i64) -> Result<Decimal> {
    num_to_decimal(i)
}

pub fn f64_to_decimal(f: f64) -> Result<Decimal> {
    num_to_decimal(f)
}

pub fn string_to_decimal(s: &str) -> Result<Decimal> {
    let dec = s.parse::<D256>()?;
    let res = dec.with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(res.into())
}

pub fn decimal_to_string(d: Decimal) -> Result<String> {
    let dec: D256 = d.into();
    Ok(dec.to_string())
}

pub fn eq_decimal(a: Decimal, b: Decimal) -> Result<bool> {
    let dec_a_: D256 = a.into();
    let dec_b_: D256 = b.into();

    let dec_a = dec_a_.with_ctx(CTX).quantize(MIN_DECIMAL);
    if dec_a.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }

    let dec_b = dec_b_.with_ctx(CTX).quantize(MIN_DECIMAL);
    if dec_b.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }

    Ok(dec_a == dec_b)
}

pub fn cmp_decimal(a: Decimal, b: Decimal) -> Result<NumericOrdering> {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    Ok(match dec_a.cmp(&dec_b) {
        Ordering::Less => NumericOrdering::Less,
        Ordering::Equal => NumericOrdering::Equal,
        Ordering::Greater => NumericOrdering::Greater,
    })
}

pub fn add_decimal(a: Decimal, b: Decimal) -> Result<Decimal> {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    let res = (dec_a + dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(res.into())
}

pub fn sub_decimal(a: Decimal, b: Decimal) -> Result<Decimal> {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    let res = (dec_a - dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(res.into())
}

pub fn mul_decimal(a: Decimal, b: Decimal) -> Result<Decimal> {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    let res = (dec_a * dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(res.into())
}

pub fn div_decimal(a: Decimal, b: Decimal) -> Result<Decimal> {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    if dec_b.is_zero() {
        return Err(Error::DivByZero("decimal divide by zero".to_string()).into());
    }
    let res = (dec_a / dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(res.into())
}

pub fn log10(a: Decimal) -> Result<Decimal> {
    let dec_a: D256 = a.into();
    let res = (dec_a.log10()).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(res.into())
}

pub fn decimal_to_integer_floor(d: Decimal) -> Result<Integer> {
    let dec: D256 = d.into();

    // For floor, we can use the decimal library's built-in truncation
    // towards zero, then adjust for negative numbers with fractional parts
    let truncated = dec.trunc();

    // Convert truncated to string, then to BigInt
    let truncated_str = truncated.to_string();
    // Remove any scientific notation by parsing the number
    let big_int: BigInt = if truncated_str.contains('E') || truncated_str.contains('e') {
        // For scientific notation, the truncated value should be parseable
        truncated_str.parse().unwrap_or_else(|_| BigInt::from(0))
    } else {
        truncated_str.parse().unwrap_or_else(|_| BigInt::from(0))
    };

    // If negative and there was a fractional part, go one more negative
    if dec.is_sign_negative() && dec != truncated {
        Ok((big_int - BigInt::from(1)).into())
    } else {
        Ok(big_int.into())
    }
}

pub fn decimal_to_integer_ceil(d: Decimal) -> Result<Integer> {
    let dec: D256 = d.into();

    // For ceil, we truncate and then add 1 if there was a positive fractional part
    let truncated = dec.trunc();

    // Convert truncated to string, then to BigInt
    let truncated_str = truncated.to_string();
    // Remove any scientific notation by parsing the number
    let big_int: BigInt = if truncated_str.contains('E') || truncated_str.contains('e') {
        // For scientific notation, the truncated value should be parseable
        truncated_str.parse().unwrap_or_else(|_| BigInt::from(0))
    } else {
        truncated_str.parse().unwrap_or_else(|_| BigInt::from(0))
    };

    // If positive and there was a fractional part, go one more positive
    if dec.is_sign_positive() && dec != truncated {
        Ok((big_int + BigInt::from(1)).into())
    } else {
        Ok(big_int.into())
    }
}

pub fn mul_div_down_integer(a: Integer, b: Integer, c: Integer) -> Result<Integer> {
    let ai: BigInt = a.into();
    let bi: BigInt = b.into();
    let ci: BigInt = c.into();
    if ci == BigInt::ZERO {
        return Err(Error::DivByZero("integer divide by zero".to_string()).into());
    }
    Ok(((ai * bi) / ci).into())
}

pub fn mul_div_up_integer(a: Integer, b: Integer, c: Integer) -> Result<Integer> {
    let ai: BigInt = a.into();
    let bi: BigInt = b.into();
    let ci: BigInt = c.into();
    if ci == BigInt::ZERO {
        return Err(Error::DivByZero("integer divide by zero".to_string()).into());
    }
    let prod = ai * bi;
    let q = &prod / &ci;
    let r = prod % &ci;
    Ok(if r.is_zero() { q } else { q + 1 }.into())
}

pub fn sqrt_integer(a: Integer) -> Result<Integer> {
    let ai: BigInt = a.into();
    if ai.sign() == Sign::Minus {
        return Err(Error::Overflow("sqrt of negative integer".to_string()).into());
    }
    // Integer sqrt via binary search on BigInt
    let mut lo = BigInt::from(0);
    let mut hi = ai.clone();
    while &lo < &hi {
        let mid = (&lo + &hi + 1) >> 1;
        if &mid * &mid <= ai {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Ok(lo.into())
}

pub fn mul_sqrt_integer(a: Integer, b: Integer) -> Result<Integer> {
    let ai: BigInt = a.into();
    let bi: BigInt = b.into();
    if ai.sign() == Sign::Minus || bi.sign() == Sign::Minus {
        return Err(Error::Overflow("sqrt of negative product".to_string()).into());
    }
    let prod = ai * bi;
    // integer sqrt
    let mut lo = BigInt::from(0);
    let mut hi = prod.clone();
    while &lo < &hi {
        let mid = (&lo + &hi + 1) >> 1;
        if &mid * &mid <= prod {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Ok(lo.into())
}
