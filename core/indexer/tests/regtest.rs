use testlib::*;

interface!(name = "token", path = "../contracts/token/wit",);

#[runtime(contracts_dir = "../../contracts", mode = "regtest")]
async fn test_regtests() -> Result<()> {
    logging::setup();

    let minter = runtime.identity().await?;
    let _holder = runtime.identity().await?;

    let token = runtime.publish(&minter, "token").await?;

    token::mint(runtime, &token, &minter, 900.into()).await?;
    token::mint(runtime, &token, &minter, 100.into()).await?;

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(result, Some(1000.into()));

    Ok(())
}
