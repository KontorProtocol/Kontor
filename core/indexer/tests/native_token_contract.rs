use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../contracts/native-token/wit",
);

async fn run_test_native_token_contract(runtime: &mut Runtime) -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;

    token::mint(runtime, &minter, 900.into()).await?;
    token::mint(runtime, &minter, 100.into()).await?;

    let result = token::balance(runtime, &minter).await?;
    // extra 10 comes from automatic issuance at identity creation
    assert_eq!(result, Some(1010.into()));

    let result = token::transfer(runtime, &holder, &minter, 123.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    token::transfer(runtime, &minter, &holder, 50.into()).await??;
    token::transfer(runtime, &minter, &holder, 2.into()).await??;

    let result = token::balance(runtime, &holder).await?;
    assert_eq!(result, Some(62.into()));

    let result = token::balance(runtime, &minter).await?;
    assert_eq!(result, Some(958.into()));

    let result = token::balance(runtime, "foo").await?;
    assert_eq!(result, None);

    let result = token::balance_log10(runtime, &minter).await??;
    assert_eq!(result, Some("2.981_365_509_078_544_415".into()));

    Ok(())
}

#[runtime(contracts_dir = "../../contracts")]
async fn test_native_token_contract() -> Result<()> {
    run_test_native_token_contract(runtime).await
}

#[runtime(contracts_dir = "../../contracts", mode = "regtest")]
async fn test_native_token_contract_regtest() -> Result<()> {
    run_test_native_token_contract(runtime).await
}
