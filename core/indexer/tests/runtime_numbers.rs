use indexer::runtime::wit::kontor::built_in::numbers::Host;
use testlib::*;

#[tokio::test]
async fn test_runtime_integer_operations() -> Result<()> {
    let runtime_ = Runtime::new(RuntimeConfig::default()).await?;
    let mut rt = runtime_.runtime;

    assert!(Host::eq_integer(&mut rt, 123.into(), 123.into()).await?);
    assert!(
        Host::eq_integer(
            &mut rt,
            "57843975908437589027340573245".into(),
            "57843975908437589027340573245".into()
        )
        .await?
    );

    assert_eq!(
        Host::add_integer(&mut rt, 123.into(), 123.into()).await?,
        246.into()
    );

    assert_eq!(
        Host::sub_integer(&mut rt, 123.into(), 21.into()).await?,
        102.into()
    );

    Ok(())
}

#[tokio::test]
async fn test_runtime_decimal_operations() -> Result<()> {
    let runtime_ = Runtime::new(RuntimeConfig::default()).await?;
    let mut rt = runtime_.runtime;

    assert!(Host::eq_decimal(&mut rt, 123.0.into(), "123".into()).await?);
    assert!(
        Host::eq_decimal(
            &mut rt,
            "57843975908.437589027340573245".into(),
            "57843975908.437589027340573245".into()
        )
        .await?
    );

    assert_eq!(
        Host::add_decimal(&mut rt, 123.0.into(), "123.0".into()).await?,
        "246.0".into()
    );

    assert_eq!(
        Host::sub_decimal(&mut rt, 123.0.into(), 21.0.into()).await?,
        102.0.into()
    );

    assert_eq!(
        Host::mul_decimal(&mut rt, (-123.0).into(), 0.5.into()).await?,
        (-61.5).into()
    );

    assert!(
        Host::mul_decimal(
            &mut rt,
            "1000000000000000000000000000000000000".into(),
            "1000000000000000000000000000000000000".into()
        )
        .await
        .is_err() // overflow
    );

    Ok(())
}
