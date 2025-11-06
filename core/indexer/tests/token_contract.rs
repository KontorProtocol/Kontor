use testlib::*;

interface!(name = "token", path = "../test-contracts/token/wit");

async fn run_test_token_contract(runtime: &mut Runtime) -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;
    let token = runtime.publish(&minter, "token").await?;

    token::mint(runtime, &token, &minter, 900.into()).await?;
    token::mint(runtime, &token, &minter, 100.into()).await?;

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(result, Some(1000.into()));

    let result = token::transfer(runtime, &token, &holder, &minter, 123.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    token::transfer(runtime, &token, &minter, &holder, 40.into()).await??;
    token::transfer(runtime, &token, &minter, &holder, 2.into()).await??;

    let result = token::balance(runtime, &token, &holder).await?;
    assert_eq!(result, Some(42.into()));

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(result, Some(958.into()));

    let result = token::balance(runtime, &token, "foo").await?;
    assert_eq!(result, None);

    let result = token::balance_log10(runtime, &token, &minter).await??;
    assert_eq!(result, Some("2.981_365_509_078_544_415".into()));

    Ok(())
}

#[runtime(contracts_dir = "../../test-contracts")]
async fn test_token_contract() -> Result<()> {
    run_test_token_contract(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_token_contract_regtest() -> Result<()> {
    run_test_token_contract(runtime).await
}

async fn run_test_token_contract_large_numbers(runtime: &mut Runtime) -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;
    let token = runtime.publish(&minter, "token").await?;

    token::mint(
        runtime,
        &token,
        &minter,
        "100_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000".into(),
    )
    .await?;

    token::mint_checked(runtime, &token, &minter, 100.into()).await??;

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(
        result,
        Some(
            "100_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_100"
                .into()
        )
    );

    let max_int = "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457";
    assert!(
        token::mint_checked(runtime, &token, &minter, max_int.into())
            .await?
            .is_err()
    );

    token::transfer(
        runtime,
        &token,
        &minter,
        &holder,
        "1_000_000_000_000_000_000_000_000_000_000".into(),
    )
    .await??;

    let result = token::balance(runtime, &token, &holder).await?;
    assert_eq!(
        result,
        Some("1_000_000_000_000_000_000_000_000_000_000".into())
    );

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(
        result,
        Some(
            "99_999_999_999_999_999_999_999_999_999_000_000_000_000_000_000_000_000_000_100".into()
        )
    );

    let result = token::balance_log10(runtime, &token, &minter).await??;
    assert_eq!(result, Some("59.000_000_000_000_000_000".into()));

    let result = token::balance_log10(runtime, &token, &holder).await??;
    assert_eq!(result, Some("30.000_000_000_000_000_000".into()));

    Ok(())
}

#[runtime(contracts_dir = "../../test-contracts")]
async fn test_token_contract_large_numbers() -> Result<()> {
    run_test_token_contract_large_numbers(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_token_contract_large_numbers_regtest() -> Result<()> {
    run_test_token_contract_large_numbers(runtime).await
}
