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

    Ok(())
}
