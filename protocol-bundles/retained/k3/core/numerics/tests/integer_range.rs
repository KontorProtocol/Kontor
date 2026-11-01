use numerics::{
    Decimal, Error, Integer, Sign, add_integer, decimal_to_integer, div_integer,
    integer_to_decimal, integer_to_string, mul_integer, string_to_decimal, string_to_integer,
    sub_integer, u64_to_integer,
};

const MAX: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const TOO_LARGE: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639936";

#[test]
fn decimal_to_integer_truncates_signed_coefficients_toward_zero() {
    for (input, expected) in [
        ("0", "0"),
        ("0.999999999999999999", "0"),
        ("-0.999999999999999999", "0"),
        ("1.999999999999999999", "1"),
        ("-1.999999999999999999", "-1"),
    ] {
        assert_eq!(
            decimal_to_integer(string_to_decimal(input).unwrap()).unwrap(),
            string_to_integer(expected).unwrap(),
        );
    }
    for sign in [Sign::Plus, Sign::Minus] {
        let value = Decimal {
            r0: u64::MAX,
            r1: u64::MAX,
            r2: u64::MAX,
            r3: u64::MAX,
            sign,
        };
        let prefix = if sign == Sign::Minus { "-" } else { "" };
        assert_eq!(
            integer_to_string(decimal_to_integer(value).unwrap()),
            format!("{prefix}115792089237316195423570985008687907853269984665640564039457"),
        );
    }
}

#[test]
fn signed_integer_operations_share_the_full_wire_range() {
    let one = u64_to_integer(1);
    for negative in [false, true] {
        let prefix = if negative { "-" } else { "" };
        let max = string_to_integer(&format!("{prefix}{MAX}")).unwrap();
        let signed_one = Integer {
            sign: max.sign,
            ..one
        };
        assert_eq!(integer_to_string(max), format!("{prefix}{MAX}"));
        assert!(matches!(
            string_to_integer(&format!("{prefix}{TOO_LARGE}")),
            Err(Error::Overflow(_))
        ));
        assert!(matches!(
            add_integer(max, signed_one),
            Err(Error::Overflow(_))
        ));
        assert!(matches!(
            mul_integer(max, u64_to_integer(2)),
            Err(Error::Overflow(_))
        ));
        let below = sub_integer(max, signed_one).unwrap();
        assert_eq!(add_integer(below, signed_one).unwrap(), max);
        assert_eq!(mul_integer(max, one).unwrap(), max);
        assert_eq!(div_integer(max, one).unwrap(), max);
        assert_eq!(sub_integer(max, max).unwrap(), Integer::default());
    }
    let max = string_to_integer(MAX).unwrap();
    let negative_max = Integer {
        sign: Sign::Minus,
        ..max
    };
    assert!(matches!(
        sub_integer(max, negative_max),
        Err(Error::Overflow(_))
    ));
    assert!(matches!(
        sub_integer(negative_max, max),
        Err(Error::Overflow(_))
    ));
}

#[test]
fn only_whole_integer_to_decimal_conversion_reserves_fractional_digits() {
    let limit =
        string_to_integer("115792089237316195423570985008687907853269984665640564039457").unwrap();
    for sign in [Sign::Plus, Sign::Minus] {
        let value = Integer { sign, ..limit };
        let signed_one = Integer {
            sign,
            ..u64_to_integer(1)
        };
        let decimal = integer_to_decimal(value).unwrap();
        assert_eq!(decimal_to_integer(decimal).unwrap(), value);
        assert!(matches!(
            integer_to_decimal(add_integer(value, signed_one).unwrap()),
            Err(Error::Overflow(_))
        ));
        assert!(matches!(
            integer_to_decimal(Integer {
                sign,
                ..string_to_integer(MAX).unwrap()
            }),
            Err(Error::Overflow(_))
        ));
    }
}
