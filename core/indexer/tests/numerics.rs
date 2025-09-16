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
        Decimal::from(Integer::from(123)) / (10).into(),
        "12.3".into()
    );

    assert_eq!(
        numbers::decimal_to_integer(Decimal::from("1.999")),
        Integer::from("1")
    );
    assert_eq!(
        numbers::decimal_to_integer(Decimal::from("-1.999")),
        Integer::from("-1")
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
    assert_eq!(
        Decimal::from(123.0).add(123.0.into()).unwrap(),
        246.0.into()
    );

    assert_eq!(Decimal::from(123.0) - 21.0.into(), 102.0.into());
    assert_eq!(Decimal::from(123.0).sub(21.0.into()).unwrap(), 102.0.into());

    assert_eq!(Decimal::from(-123.0) * 0.5.into(), (-61.5).into());
    assert_eq!(
        Decimal::from(-123.0).mul(0.5.into()).unwrap(),
        (-61.5).into()
    );

    assert!(
        catch_unwind(|| Decimal::from("1000000000000000000000000000000000000")
            * "1000000000000000000000000000000000000".into())
        .is_err()
    );

    assert_eq!(Decimal::from(-123.0) / 2.0.into(), (-61.5).into());
    assert_eq!(
        Decimal::from(-123.0).div(2.0.into()).unwrap(),
        (-61.5).into()
    );

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
async fn test_numerics_limits() -> Result<()> {
    let max_int = "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457";
    let min_int =
        "-115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457";
    let oversized_int =
        "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_458";
    let oversized_dec =
        "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457.585";

    assert_eq!(
        Decimal::from(Integer::from(max_int)),
        Decimal::from(max_int)
    );
    assert_eq!(
        Decimal::from(Integer::from(min_int)),
        Decimal::from(min_int)
    );

    assert!(catch_unwind(|| Integer::from(oversized_int)).is_err());
    assert!(catch_unwind(|| Decimal::from(oversized_dec)).is_err());

    assert!(numbers::add_integer(Integer::from(max_int), Integer::from(1)).is_err());
    assert_eq!(
        numbers::add_integer(Integer::from(max_int), Integer::from(-1)).unwrap(),
        Integer::from(
            "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_456"
        ),
    );

    assert!(numbers::sub_integer(Integer::from(max_int), Integer::from(-1)).is_err());
    assert_eq!(
        numbers::sub_integer(Integer::from(max_int), Integer::from(1)).unwrap(),
        Integer::from(
            "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_456"
        ),
    );

    assert!(numbers::mul_integer(Integer::from(max_int), Integer::from(2)).is_err());
    assert_eq!(
        numbers::mul_integer(Integer::from(max_int), Integer::from(1)).unwrap(),
        Integer::from(max_int)
    );

    Ok(())
}
