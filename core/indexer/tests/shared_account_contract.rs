use testlib::*;

interface!(name = "token", path = "../contracts/token/wit",);

interface!(
    name = "shared-account",
    path = "../contracts/shared-account/wit",
);

async fn run_test_shared_account_contract(runtime: &mut Runtime) -> Result<()> {
    let alice = runtime.identity().await?;
    let bob = runtime.identity().await?;
    let claire = runtime.identity().await?;
    let dara = runtime.identity().await?;

    let token = runtime.publish(&alice, "token").await?;
    let shared_account = runtime.publish(&alice, "shared-account").await?;

    token::mint(runtime, &token, &alice, 100.into()).await?;

    let account_id = shared_account::open(
        runtime,
        &shared_account,
        &alice,
        token.clone(),
        50.into(),
        vec![&bob, &dara],
    )
    .await??;

    let result = shared_account::balance(runtime, &shared_account, &account_id).await?;
    assert_eq!(result, Some(50.into()));

    shared_account::deposit(
        runtime,
        &shared_account,
        &alice,
        token.clone(),
        &account_id,
        25.into(),
    )
    .await??;

    let result = shared_account::balance(runtime, &shared_account, &account_id).await?;
    assert_eq!(result, Some(75.into()));

    shared_account::withdraw(
        runtime,
        &shared_account,
        &bob,
        token.clone(),
        &account_id,
        25.into(),
    )
    .await??;

    let result = shared_account::balance(runtime, &shared_account, &account_id).await?;
    assert_eq!(result, Some(50.into()));

    shared_account::withdraw(
        runtime,
        &shared_account,
        &alice,
        token.clone(),
        &account_id,
        50.into(),
    )
    .await??;

    let result = shared_account::balance(runtime, &shared_account, &account_id).await?;
    assert_eq!(result, Some(0.into()));

    let result = shared_account::withdraw(
        runtime,
        &shared_account,
        &bob,
        token.clone(),
        &account_id,
        1.into(),
    )
    .await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient balance".to_string()))
    );

    let result = shared_account::withdraw(
        runtime,
        &shared_account,
        &claire,
        token.clone(),
        &account_id,
        1.into(),
    )
    .await?;
    assert_eq!(result, Err(Error::Message("unauthorized".to_string())));

    let result =
        shared_account::token_balance(runtime, &shared_account, token.clone(), &alice).await?;
    assert_eq!(result, Some(75.into()));

    let result = token::balance(runtime, &token, &bob).await?;
    assert_eq!(result, Some(25.into()));

    let result = shared_account::tenants(runtime, &shared_account, &account_id)
        .await?
        .unwrap();
    assert_eq!(result.iter().len(), 3);
    assert!(result.contains(&alice.to_string()));
    assert!(result.contains(&dara.to_string()));
    assert!(result.contains(&bob.to_string()));

    Ok(())
}

#[runtime(contracts_dir = "../../contracts")]
async fn test_shared_account_contract() -> Result<()> {
    run_test_shared_account_contract(runtime).await
}

#[runtime(contracts_dir = "../../contracts", mode = "regtest")]
async fn test_shared_account_contract_regtest() -> Result<()> {
    run_test_shared_account_contract(runtime).await
}
