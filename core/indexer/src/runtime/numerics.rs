use std::cmp::Ordering;

use anyhow::Result;
use fastnum::{
    D256, dec256,
    decimal::{Context, SignalsTraps},
};
use num::{BigInt, bigint::Sign};

use super::{Decimal, Error, Integer, NumericOrdering, NumericSign};

const MIN_DECIMAL: D256 = dec256!(0.000_000_000_000_000_001);
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
    Ok(Decimal {
        value: dec.to_string(),
    })
}

fn num_to_decimal(n: impl Into<D256>) -> Result<Decimal> {
    let dec: D256 = n.into();
    let res = dec.with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(Decimal {
        value: res.to_string(),
    })
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
    Ok(Decimal {
        value: res.to_string(),
    })
}

pub fn eq_decimal(a: &Decimal, b: &Decimal) -> Result<bool> {
    let dec_a_ = a.value.parse::<D256>()?;
    let dec_b_ = b.value.parse::<D256>()?;

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

pub fn cmp_decimal(a: &Decimal, b: &Decimal) -> Result<NumericOrdering> {
    let dec_a = a.value.parse::<D256>()?;
    let dec_b = b.value.parse::<D256>()?;
    Ok(match dec_a.cmp(&dec_b) {
        Ordering::Less => NumericOrdering::Less,
        Ordering::Equal => NumericOrdering::Equal,
        Ordering::Greater => NumericOrdering::Greater,
    })
}

pub fn add_decimal(a: &Decimal, b: &Decimal) -> Result<Decimal> {
    let dec_a = a.value.parse::<D256>()?;
    let dec_b = b.value.parse::<D256>()?;
    let res = (dec_a + dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(Decimal {
        value: res.to_string(),
    })
}

pub fn sub_decimal(a: &Decimal, b: &Decimal) -> Result<Decimal> {
    let dec_a = a.value.parse::<D256>()?;
    let dec_b = b.value.parse::<D256>()?;
    let res = (dec_a - dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(Decimal {
        value: res.to_string(),
    })
}

pub fn mul_decimal(a: &Decimal, b: &Decimal) -> Result<Decimal> {
    let dec_a = a.value.parse::<D256>()?;
    let dec_b = b.value.parse::<D256>()?;
    let res = (dec_a * dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(Decimal {
        value: res.to_string(),
    })
}

pub fn div_decimal(a: &Decimal, b: &Decimal) -> Result<Decimal> {
    let dec_a = a.value.parse::<D256>()?;
    let dec_b = b.value.parse::<D256>()?;
    if dec_b.is_zero() {
        return Err(Error::DivByZero("decimal divide by zero".to_string()).into());
    }
    let res = (dec_a / dec_b).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(Decimal {
        value: res.to_string(),
    })
}

pub fn log10(a: &Decimal) -> Result<Decimal> {
    let dec_a = a.value.parse::<D256>()?;
    let res = (dec_a.log10()).with_ctx(CTX).quantize(MIN_DECIMAL);
    if res.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(Decimal {
        value: res.to_string(),
    })
}
