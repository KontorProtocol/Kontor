use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../../native-contracts/token/wit",
);

async fn run_test_native_token_contract(runtime: &mut Runtime) -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;

    token::mint(runtime, &minter, 900.into()).await??;
    token::mint(runtime, &minter, 100.into()).await??;

    let result = token::balance(runtime, &minter).await?;
    // extra 10 comes from automatic issuance at identity creation
    let minter_tokens_spent_as_gas = Decimal::from("0.000000238");
    assert_eq!(
        result.map(|d| d.to_string()),
        Some(Decimal::from(1010) - minter_tokens_spent_as_gas).map(|d| d.to_string())
    );

    let result = token::transfer(runtime, &holder, &minter, 123.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    token::transfer(runtime, &minter, &holder, 50.into()).await??;
    token::transfer(runtime, &minter, &holder, 2.into()).await??;

    let result = token::balance(runtime, &holder).await?;
    let holder_tokens_spent_as_gas = Decimal::from("0.000000072");
    assert_eq!(
        result.map(|d| d.to_string()),
        Some(Decimal::from(62) - holder_tokens_spent_as_gas).map(|d| d.to_string())
    );

    let result = token::balance(runtime, &minter).await?;
    let minter_tokens_spent_as_gas = Decimal::from("0.000000498");
    assert_eq!(
        result.map(|d| d.to_string()),
        Some(Decimal::from(958) - minter_tokens_spent_as_gas).map(|d| d.to_string())
    );

    let result = token::balance(runtime, "foo").await?;
    assert_eq!(result, None);

    let balances = token::balances(runtime).await?;
    assert_eq!(balances.len(), 2);
    let total = balances.iter().fold(Decimal::from(0), |acc, x| acc + x.amt);
    assert_eq!(total, token::total_supply(runtime).await?);

    Ok(())
}

#[testlib::test(contracts_dir = "../../../test-contracts")]
async fn test_native_token_contract() -> Result<()> {
    run_test_native_token_contract(runtime).await
}

#[testlib::test(contracts_dir = "../../../test-contracts", mode = "regtest")]
async fn test_native_token_contract_regtest() -> Result<()> {
    run_test_native_token_contract(runtime).await
}
