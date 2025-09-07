use std::cmp::Ordering;

use anyhow::Result;
use fastnum::{
    D256, dec256,
    decimal::{Context, SignalsTraps},
};
use num::BigInt;

use super::{Decimal, Error, Integer, NumericOrdering};

const MIN_DECIMAL: D256 = dec256!(0.000_000_000_000_000_001);
const CTX: Context = Context::default().with_signal_traps(SignalsTraps::empty());

pub fn eq_integer(a: &Integer, b: &Integer) -> Result<bool> {
    let big_a = a.value.parse::<BigInt>()?;
    let big_b = b.value.parse::<BigInt>()?;
    Ok(big_a == big_b)
}

pub fn cmp_integer(a: &Integer, b: &Integer) -> Result<NumericOrdering> {
    let big_a = a.value.parse::<BigInt>()?;
    let big_b = b.value.parse::<BigInt>()?;
    Ok(match big_a.cmp(&big_b) {
        Ordering::Less => NumericOrdering::Less,
        Ordering::Equal => NumericOrdering::Equal,
        Ordering::Greater => NumericOrdering::Greater,
    })
}

pub fn add_integer(a: &Integer, b: &Integer) -> Result<Integer> {
    let big_a = a.value.parse::<BigInt>()?;
    let big_b = b.value.parse::<BigInt>()?;
    Ok(Integer {
        value: (big_a + big_b).to_string(),
    })
}

pub fn sub_integer(a: &Integer, b: &Integer) -> Result<Integer> {
    let big_a = a.value.parse::<BigInt>()?;
    let big_b = b.value.parse::<BigInt>()?;
    Ok(Integer {
        value: (big_a - big_b).to_string(),
    })
}

pub fn mul_integer(a: &Integer, b: &Integer) -> Result<Integer> {
    let big_a = a.value.parse::<BigInt>()?;
    let big_b = b.value.parse::<BigInt>()?;
    Ok(Integer {
        value: (big_a * big_b).to_string(),
    })
}

pub fn div_integer(a: &Integer, b: &Integer) -> Result<Integer> {
    let big_a = a.value.parse::<BigInt>()?;
    let big_b = b.value.parse::<BigInt>()?;
    if big_b == BigInt::ZERO {
        return Err(Error::DivByZero("integer divide by zero".to_string()).into());
    }
    Ok(Integer {
        value: (big_a / big_b).to_string(),
    })
}

pub fn integer_to_decimal(i: &Integer) -> Result<Decimal> {
    let dec_ = i.value.parse::<D256>()?;
    let dec = dec_.with_ctx(CTX).quantize(MIN_DECIMAL);
    if dec.is_op_invalid() {
        return Err(Error::Overflow("invalid decimal number".to_string()).into());
    }
    Ok(Decimal {
        value: dec.to_string(),
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
