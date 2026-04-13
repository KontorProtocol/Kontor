use core::cmp::Ordering;
use std::sync::LazyLock;

use anyhow::Result;
use fastnum::{
    D256, U256,
    bint::UInt,
    dec256,
    decimal::{self, Context, SignalsTraps},
};
use num::{BigInt, bigint::Sign};

use super::{Decimal, Error, Integer, NumericOrdering, NumericSign};

const DECIMAL_18_DECS: D256 = dec256!(1_000_000_000_000_000_000);
const MIN_DECIMAL: D256 = dec256!(0.000_000_000_000_000_001);
const MAX_UINT64: D256 = dec256!(18446744073709551615);
static MAX_INT: LazyLock<BigInt> = LazyLock::new(|| {
    "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457"
        .parse::<BigInt>()
        .unwrap()
});

const CTX: Context = Context::default().with_signal_traps(SignalsTraps::empty());

impl TryFrom<BigInt> for Integer {
    type Error = Error;

    fn try_from(big: BigInt) -> Result<Self, Error> {
        let (sign_, digits) = big.to_u64_digits();
        if digits.len() > 4 {
            return Err(Error::Overflow("oversized integer".to_string()));
        }
        let sign = if sign_ == Sign::Minus {
            NumericSign::Minus
        } else {
            NumericSign::Plus
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
        // Each value is masked to 64 bits, so to_u64() is infallible
        let r0 = dig.bitand(filter).to_u64().expect("masked to 64 bits");
        dig >>= 64;
        let r1 = dig.bitand(filter).to_u64().expect("masked to 64 bits");
        dig >>= 64;
        let r2 = dig.bitand(filter).to_u64().expect("masked to 64 bits");
        dig >>= 64;
        let r3 = dig.bitand(filter).to_u64().expect("masked to 64 bits");

        let sign = if dec.sign() == decimal::Sign::Minus {
            NumericSign::Minus
        } else {
            NumericSign::Plus
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

        if d.sign == NumericSign::Minus {
            dec = -dec
        };

        dec / DECIMAL_18_DECS
    }
}

pub fn u64_to_integer(i: u64) -> Integer {
    Integer {
        r0: i,
        r1: 0,
        r2: 0,
        r3: 0,
        sign: NumericSign::Plus,
    }
}

pub fn s64_to_integer(i: i64) -> Integer {
    let sign = if i < 0 {
        NumericSign::Minus
    } else {
        NumericSign::Plus
    };
    Integer {
        r0: i.unsigned_abs(),
        r1: 0,
        r2: 0,
        r3: 0,
        sign,
    }
}

pub fn string_to_integer(s: &str) -> Result<Integer, Error> {
    let max_int = MAX_INT.clone();
    let i = match s.parse::<BigInt>() {
        Ok(i) => i,
        Err(e) => {
            return Err(Error::Syntax(e.to_string()));
        }
    };
    if i > max_int || i < -max_int {
        return Err(Error::Overflow("result overflows Integer".to_string()));
    }
    i.try_into()
}

pub fn integer_to_string(i: Integer) -> String {
    let big_i: BigInt = i.into();
    big_i.to_string()
}

pub fn eq_integer(a: Integer, b: Integer) -> bool {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    big_a == big_b
}

pub fn cmp_integer(a: Integer, b: Integer) -> NumericOrdering {
    let big_a: BigInt = a.into();
    let big_b: BigInt = b.into();
    match big_a.cmp(&big_b) {
        Ordering::Less => NumericOrdering::Less,
        Ordering::Equal => NumericOrdering::Equal,
        Ordering::Greater => NumericOrdering::Greater,
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
        Err(e) => {
            return Err(Error::Syntax(e.to_string()));
        }
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

pub fn cmp_decimal(a: Decimal, b: Decimal) -> NumericOrdering {
    let dec_a: D256 = a.into();
    let dec_b: D256 = b.into();
    match dec_a.cmp(&dec_b) {
        Ordering::Less => NumericOrdering::Less,
        Ordering::Equal => NumericOrdering::Equal,
        Ordering::Greater => NumericOrdering::Greater,
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
