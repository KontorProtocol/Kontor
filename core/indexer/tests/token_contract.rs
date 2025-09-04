use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
    test = true,
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

    Ok(())
}
