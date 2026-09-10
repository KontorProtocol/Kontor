use built_in_types::numbers_types::{Decimal, Integer, Sign};

#[test]
fn direct_integer_constructors_preserve_signed_boundaries() {
    for value in [i64::MIN, -1, 0, 1, i64::MAX] {
        assert_eq!(Integer::from(value), Integer::from(value.to_string()));
    }
    assert_eq!(Integer::from(u64::MAX), Integer::from(u64::MAX.to_string()));
}

#[test]
fn raw_units_are_exact_and_distinct_from_whole_integer_conversion() {
    const SCALE: Integer = Integer::from_u128(10u128.pow(18));
    const ONE: Decimal = Decimal::from_raw_units(SCALE);
    assert_eq!(ONE, Decimal::from("1"));
    assert_eq!(
        Integer::from_u128(u128::MAX),
        Integer::from(u128::MAX.to_string())
    );
    for text in [
        "0",
        "0.000000000000000001",
        "-0.000000000000000001",
        "-1.25",
        "1e54",
    ] {
        let value = Decimal::from(text);
        assert_eq!(Decimal::from_raw_units(value.to_raw_units()), value);
    }
    assert_eq!(
        Decimal::from("-1.25").to_raw_units(),
        Integer::from("-1250000000000000000")
    );
    assert_eq!(Decimal::try_from(Integer::from(1)).unwrap(), ONE);
    assert_eq!(
        Decimal::from_raw_units(Integer::from(1)),
        Decimal::from("0.000000000000000001")
    );
    for sign in [Sign::Plus, Sign::Minus] {
        let max = Integer {
            r0: u64::MAX,
            r1: u64::MAX,
            r2: u64::MAX,
            r3: u64::MAX,
            sign,
        };
        assert_eq!(Decimal::from_raw_units(max).to_raw_units(), max);
        assert!(Decimal::try_from(max).is_err());
    }
}
