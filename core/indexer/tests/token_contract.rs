use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
);

#[tokio::test]
async fn test_token_contract() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;

    let minter = "test_minter";
    let holder = "test_holder";
    token::mint(&runtime, minter, 900.into()).await?;
    token::mint(&runtime, minter, 100.into()).await?;

    let result = token::balance(&runtime, minter).await?;
    assert_eq!(result, Some(1000.into()));

    let result = token::transfer(&runtime, holder, minter, 123.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    token::transfer(&runtime, minter, holder, 40.into()).await??;
    token::transfer(&runtime, minter, holder, 2.into()).await??;

    let result = token::balance(&runtime, holder).await?;
    assert_eq!(result, Some(42.into()));

    let result = token::balance(&runtime, minter).await?;
    assert_eq!(result, Some(958.into()));

    let result = token::balance(&runtime, "foo").await?;
    assert_eq!(result, None);

    let result = token::balance_log10(&runtime, minter).await?;
    assert_eq!(result, Some("2.981_365_509_078_544_415".into()));

    Ok(())
}

#[tokio::test]
async fn test_token_contract_large_numbers() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;

    let minter = "test_minter";
    let holder = "test_holder";
    token::mint(
        &runtime,
        minter,
        "100_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000".into(),
    )
    .await?;
    token::mint(&runtime, minter, 100.into()).await?;

    let result = token::balance(&runtime, minter).await?;
    assert_eq!(
        result,
        Some(
            "100_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_100"
                .into()
        )
    );

    token::transfer(
        &runtime,
        minter,
        holder,
        "1_000_000_000_000_000_000_000_000_000_000".into(),
    )
    .await??;

    let result = token::balance(&runtime, holder).await?;
    assert_eq!(
        result,
        Some("1_000_000_000_000_000_000_000_000_000_000".into())
    );

    let result = token::balance(&runtime, minter).await?;
    assert_eq!(
        result,
        Some(
            "99_999_999_999_999_999_999_999_999_999_000_000_000_000_000_000_000_000_000_100".into()
        )
    );

    let result = token::balance_log10(&runtime, minter).await?;
    assert_eq!(result, Some("59.000_000_000_000_000_000".into()));

    let result = token::balance_log10(&runtime, holder).await?;
    assert_eq!(result, Some("30.000_000_000_000_000_000".into()));

    Ok(())
}
