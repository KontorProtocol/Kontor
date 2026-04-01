use testlib::*;

interface!(name = "token", path = "../../test-contracts/test-token/wit");

#[testlib::test(contracts_dir = "../../test-contracts", shared)]
async fn test_token_contract() -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;
    let token = runtime.publish(&minter, "test-token").await?;

    // Batch two mints (independent, same signer)
    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(&token, 900.into()));
    ops.push(token::mint_call(&token, 100.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(result, Some(1000.into()));

    // Transfer with insufficient funds (expected error, keep separate)
    let result = token::transfer(runtime, &token, &holder, &minter, 123.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    // Batch two transfers (independent, same signer)
    let mut ops = Ops::new(&minter);
    ops.push(token::transfer_call(&token, &holder, 40.into()));
    ops.push(token::transfer_call(&token, &holder, 2.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    let result = token::balance(runtime, &token, &holder).await?;
    assert_eq!(result, Some(42.into()));

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(result, Some(958.into()));

    let result = token::balance(runtime, &token, "foo").await?;
    assert_eq!(result, None);

    let balances = token::balances(runtime, &token).await?;
    assert!(balances.len() >= 2);
    let total = balances
        .iter()
        .fold(Integer::from(0), |acc, x| acc + x.value);
    assert_eq!(total, token::total_supply(runtime, &token).await?);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", shared)]
async fn test_token_contract_large_numbers() -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;
    let token = runtime.publish(&minter, "test-token").await?;

    // Batch two mints (independent, same signer)
    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(
        &token,
        "100_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000".into(),
    ));
    ops.push(token::mint_call(&token, 100.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    let result = token::balance(runtime, &token, &minter).await?;
    assert_eq!(
        result,
        Some(
            "100_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_100"
                .into()
        )
    );

    // Overflow mint (expected error, keep separate)
    let max_int = "115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457";
    assert!(
        token::mint(runtime, &token, &minter, max_int.into())
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

    Ok(())
}
