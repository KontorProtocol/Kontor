use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
    test = true,
);

#[testlib::test]
async fn test_token_contract() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;

    let minter = "test_minter";
    let holder = "test_holder";
    token::mint(&runtime, minter, 900).await;
    token::mint(&runtime, minter, 100).await;

    let result = token::balance(&runtime, minter).await;
    assert_eq!(result, Some(1000));

    let result = token::transfer(&runtime, holder, minter, 123).await;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    token::transfer(&runtime, minter, holder, 40).await?;
    token::transfer(&runtime, minter, holder, 2).await?;

    let result = token::balance(&runtime, holder).await;
    assert_eq!(result, Some(42));

    let result = token::balance(&runtime, minter).await;
    assert_eq!(result, Some(958));

    let result = token::balance(&runtime, "foo").await;
    assert_eq!(result, None);

    Ok(())
}
