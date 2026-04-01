use testlib::*;

interface!(name = "token", path = "../../test-contracts/test-token/wit",);

interface!(
    name = "shared_account",
    path = "../../test-contracts/shared-account/wit",
);

#[testlib::test(contracts_dir = "../../test-contracts", shared)]
async fn test_shared_account_contract() -> Result<()> {
    let alice = runtime.identity().await?;
    let bob = runtime.identity().await?;
    let claire = runtime.identity().await?;
    let dara = runtime.identity().await?;

    let addrs = runtime
        .publish_many(&alice, &["test-token", "shared-account"])
        .await?;
    let token = addrs[0].clone();
    let shared_account = addrs[1].clone();

    token::mint(runtime, &token, &alice, 100.into()).await??;

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

    // Two independent error cases — batch them
    let mut submit = runtime.submit();
    let h_insufficient = submit.push(
        &bob,
        shared_account::withdraw_call(&shared_account, token.clone(), &account_id, 1.into()),
    );
    let h_unauthorized = submit.push(
        &claire,
        shared_account::withdraw_call(&shared_account, token.clone(), &account_id, 1.into()),
    );
    let results = submit.execute().await?;
    assert_eq!(
        results.get(&h_insufficient),
        Err(Error::Message("insufficient balance".to_string()))
    );
    assert_eq!(
        results.get(&h_unauthorized),
        Err(Error::Message("unauthorized".to_string()))
    );

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
