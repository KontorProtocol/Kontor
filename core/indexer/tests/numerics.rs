use std::panic::catch_unwind;

use testlib::*;

#[tokio::test]
async fn test_numerics() -> Result<()> {
    assert!(Integer::from(123) == 123.into());
    assert!(Integer::from(123) == 123.into());
    assert!(
        Integer::from("57843975908437589027340573245") == "57843975908437589027340573245".into()
    );

    assert_eq!(Integer::from(123) + 123.into(), 246.into());

    assert_eq!(Integer::from(123) - 21.into(), 102.into());

    assert_eq!(Integer::from(5) * 6.into(), 30.into());

    assert_eq!(Integer::from(5) / 2.into(), 2.into());

    assert_eq!(Integer::from(-5) / 2.into(), (-2).into());
    assert_eq!(
        Integer::from("-1000000000000000000000000000") / (-2).into(),
        ("500000000000000000000000000").into()
    );

    assert_eq!(
        Decimal::from(Integer::from(123)) / (10).into(),
        "12.3".into()
    );

    Ok(())
}

#[tokio::test]
async fn test_runtime_decimal_operations() -> Result<()> {
    assert!(Decimal::from(123.0) == "123".into());
    assert!(
        Decimal::from("57843975908.437589027340573245") == "57843975908.437589027340573245".into()
    );

    assert_eq!(Decimal::from(123.0) + "123.0".into(), "246.0".into());

    assert_eq!(Decimal::from(123.0) - 21.0.into(), 102.0.into());

    assert_eq!(Decimal::from(-123.0) * 0.5.into(), (-61.5).into());

    assert!(
        catch_unwind(|| Decimal::from("1000000000000000000000000000000000000")
            * "1000000000000000000000000000000000000".into())
        .is_err()
    );

    assert_eq!(Decimal::from(-123.0) / 2.0.into(), (-61.5).into());

    assert!(catch_unwind(|| Decimal::from(10.0) / 0.0.into()).is_err());

    assert_eq!(
        Decimal::from("-1000000000000000000000000000") / (-2).into(),
        ("500000000000000000000000000").into()
    );

    assert_eq!(
        Decimal::from("-100000000000000000000000000000000000000000000.000001") / (-2).into(),
        ("50000000000000000000000000000000000000000000.0000005").into()
    );

    Ok(())
}

#[tokio::test]
async fn test_decimal_to_integer_conversions() -> Result<()> {
    use indexer::runtime::numerics;

    // Test floor function with positive numbers
    assert_eq!(
        numerics::decimal_to_integer_floor(Decimal::from("10.7"))?,
        10.into()
    );
    assert_eq!(
        numerics::decimal_to_integer_floor(Decimal::from("10.3"))?,
        10.into()
    );
    assert_eq!(
        numerics::decimal_to_integer_floor(Decimal::from("10.0"))?,
        10.into()
    );

    // Test floor function with negative numbers
    assert_eq!(
        numerics::decimal_to_integer_floor(Decimal::from("-10.3"))?,
        (-11).into()
    );
    assert_eq!(
        numerics::decimal_to_integer_floor(Decimal::from("-10.7"))?,
        (-11).into()
    );
    assert_eq!(
        numerics::decimal_to_integer_floor(Decimal::from("-10.0"))?,
        (-10).into()
    );

    // Test ceil function with positive numbers
    assert_eq!(
        numerics::decimal_to_integer_ceil(Decimal::from("10.7"))?,
        11.into()
    );
    assert_eq!(
        numerics::decimal_to_integer_ceil(Decimal::from("10.3"))?,
        11.into()
    );
    assert_eq!(
        numerics::decimal_to_integer_ceil(Decimal::from("10.0"))?,
        10.into()
    );

    // Test ceil function with negative numbers
    assert_eq!(
        numerics::decimal_to_integer_ceil(Decimal::from("-10.3"))?,
        (-10).into()
    );
    assert_eq!(
        numerics::decimal_to_integer_ceil(Decimal::from("-10.7"))?,
        (-10).into()
    );
    assert_eq!(
        numerics::decimal_to_integer_ceil(Decimal::from("-10.0"))?,
        (-10).into()
    );

    // Test edge cases with very small decimals
    assert_eq!(
        numerics::decimal_to_integer_floor(Decimal::from("0.999999999"))?,
        0.into()
    );
    assert_eq!(
        numerics::decimal_to_integer_ceil(Decimal::from("0.000000001"))?,
        1.into()
    );
    assert_eq!(
        numerics::decimal_to_integer_floor(Decimal::from("-0.000000001"))?,
        (-1).into()
    );
    assert_eq!(
        numerics::decimal_to_integer_ceil(Decimal::from("-0.999999999"))?,
        0.into()
    );

    Ok(())
}
