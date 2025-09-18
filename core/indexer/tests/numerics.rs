use std::panic::catch_unwind;

use testlib::*;

#[tokio::test]
async fn test_numerics() -> Result<()> {
    assert!(int_eq(&int(123), &int(123)));
    assert!(int_eq(&int_from_str("57843975908437589027340573245"), 
                    &int_from_str("57843975908437589027340573245")));

    assert!(int_eq(&int_add(int(123), int(123)), &int(246)));

    assert!(int_eq(&int_sub(int(123), int(21)), &int(102)));

    assert!(int_eq(&int_mul(int(5), int(6)), &int(30)));

    assert!(int_eq(&int_div(int(5), int(2)), &int(2)));

    assert!(int_eq(&int_div(int_from_i64(-5), int(2)), &int_from_i64(-2)));
    assert!(int_eq(
        &int_div(int_from_str("-1000000000000000000000000000"), int_from_i64(-2)),
        &int_from_str("500000000000000000000000000")
    ));

    assert!(decimal_eq(
        &decimal_div(decimal_from_int(int(123)), decimal_from_int(int(10))),
        &decimal_from_str("12.3")
    ));

    Ok(())
}

#[tokio::test]
async fn test_runtime_decimal_operations() -> Result<()> {
    assert!(decimal_eq(&decimal_from_f64(123.0), &decimal_from_str("123")));
    assert!(decimal_eq(
        &decimal_from_str("57843975908.437589027340573245"),
        &decimal_from_str("57843975908.437589027340573245")
    ));

    assert!(decimal_eq(
        &decimal_add(decimal_from_f64(123.0), decimal_from_str("123.0")),
        &decimal_from_str("246.0")
    ));

    assert!(decimal_eq(
        &decimal_sub(decimal_from_f64(123.0), decimal_from_f64(21.0)),
        &decimal_from_f64(102.0)
    ));

    assert!(decimal_eq(
        &decimal_mul(decimal_from_f64(-123.0), decimal_from_f64(0.5)),
        &decimal_from_f64(-61.5)
    ));

    assert!(
        catch_unwind(|| decimal_mul(
            decimal_from_str("1000000000000000000000000000000000000"),
            decimal_from_str("1000000000000000000000000000000000000")
        ))
        .is_err()
    );

    assert!(decimal_eq(
        &decimal_div(decimal_from_f64(-123.0), decimal_from_f64(2.0)),
        &decimal_from_f64(-61.5)
    ));

    assert!(catch_unwind(|| decimal_div(decimal_from_f64(10.0), decimal_from_f64(0.0))).is_err());

    assert!(decimal_eq(
        &decimal_div(
            decimal_from_str("-1000000000000000000000000000"),
            decimal_from_int(int_from_i64(-2))
        ),
        &decimal_from_str("500000000000000000000000000")
    ));

    assert!(decimal_eq(
        &decimal_div(
            decimal_from_str("-100000000000000000000000000000000000000000000.000001"),
            decimal_from_int(int_from_i64(-2))
        ),
        &decimal_from_str("50000000000000000000000000000000000000000000.0000005")
    ));

    Ok(())
}

#[tokio::test]
async fn test_decimal_to_integer_conversions() -> Result<()> {
    use indexer::runtime::numerics;

    // Test floor function with positive numbers
    assert!(int_eq(
        &numerics::decimal_to_integer_floor(decimal_from_str("10.7"))?,
        &int(10)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_floor(decimal_from_str("10.3"))?,
        &int(10)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_floor(decimal_from_str("10.0"))?,
        &int(10)
    ));

    // Test floor function with negative numbers
    assert!(int_eq(
        &numerics::decimal_to_integer_floor(decimal_from_str("-10.3"))?,
        &int_from_i64(-11)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_floor(decimal_from_str("-10.7"))?,
        &int_from_i64(-11)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_floor(decimal_from_str("-10.0"))?,
        &int_from_i64(-10)
    ));

    // Test ceil function with positive numbers
    assert!(int_eq(
        &numerics::decimal_to_integer_ceil(decimal_from_str("10.7"))?,
        &int(11)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_ceil(decimal_from_str("10.3"))?,
        &int(11)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_ceil(decimal_from_str("10.0"))?,
        &int(10)
    ));

    // Test ceil function with negative numbers
    assert!(int_eq(
        &numerics::decimal_to_integer_ceil(decimal_from_str("-10.3"))?,
        &int_from_i64(-10)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_ceil(decimal_from_str("-10.7"))?,
        &int_from_i64(-10)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_ceil(decimal_from_str("-10.0"))?,
        &int_from_i64(-10)
    ));

    // Test edge cases with very small decimals
    assert!(int_eq(
        &numerics::decimal_to_integer_floor(decimal_from_str("0.999999999"))?,
        &int(0)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_ceil(decimal_from_str("0.000000001"))?,
        &int(1)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_floor(decimal_from_str("-0.000000001"))?,
        &int_from_i64(-1)
    ));
    assert!(int_eq(
        &numerics::decimal_to_integer_ceil(decimal_from_str("-0.999999999"))?,
        &int(0)
    ));

    Ok(())
}
