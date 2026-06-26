use testlib::*;

interface!(name = "token", path = "../../test-contracts/test-token/wit");

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_token_contract() -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;
    let token = runtime.publish(&minter, "test-token").await?;

    // Batch two mints (independent, same signer)
    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token, 900u64.try_into().unwrap()));
    ops.push(token::mint_call(&token, 100u64.try_into().unwrap()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(result, Some(1000u64.try_into().unwrap()));

    // Transfer with insufficient funds (expected error, keep separate)
    let result = token::transfer(
        runtime,
        &token,
        &holder,
        &minter,
        123u64.try_into().unwrap(),
    )
    .await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    // Batch two transfers (independent, same signer)
    let mut ops = Ops::new(&minter);
    ops.push(token::transfer_call(
        &token,
        &holder,
        40u64.try_into().unwrap(),
    ));
    ops.push(token::transfer_call(
        &token,
        &holder,
        2u64.try_into().unwrap(),
    ));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    let result = token::balance(runtime, &token, &holder).await?;
    assert_eq!(result, Some(42u64.try_into().unwrap()));

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(result, Some(958u64.try_into().unwrap()));

    // A well-formed but unknown holder has no balance.
    let result = token::balance(runtime, &token, HolderRef::XOnlyPubkey("foo".to_string())).await?;
    assert_eq!(result, None);

    let balances = token::balances(runtime, &token).await?;
    assert!(balances.len() >= 2);
    let total = balances
        .iter()
        .fold(0u64.try_into().unwrap(), |acc: Decimal, x| {
            acc.add(x.amt).unwrap()
        });
    assert_eq!(total, token::total_supply(runtime, &token).await?);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_token_contract_large_numbers() -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;
    let token = runtime.publish(&minter, "test-token").await?;

    // test-token is decimal (fastnum::D256); exercise large-but-valid amounts. (The
    // old integer test minted near 2^256 — not representable as a decimal.)
    let big: Decimal = "1_000_000_000_000_000_000_000_000_000_000".into(); // 1e30
    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token, big));
    ops.push(token::mint_call(&token, 100u64.try_into().unwrap()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(
        result,
        Some("1_000_000_000_000_000_000_000_000_000_100".into()) // 1e30 + 100
    );

    token::transfer(runtime, &token, &minter, &holder, big).await??;

    let result = token::balance(runtime, &token, &holder).await?;
    assert_eq!(result, Some(big));

    Ok(())
}
