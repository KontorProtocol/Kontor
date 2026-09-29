use testlib::*;

interface!(name = "token", path = "../../test-contracts/test-token/wit");

interface!(
    name = "decimal_token",
    path = "../../test-contracts/decimal-token/wit"
);

#[testlib::test(contracts_dir = "../../test-contracts")]
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

    let mut balances = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = token::balances(runtime, &token, after.as_deref(), 100).await??;
        balances.extend(page.items);
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    assert!(balances.len() >= 2);
    let total = balances
        .iter()
        .fold(Integer::from(0), |acc, x| acc + x.value);
    assert_eq!(total, token::total_supply(runtime, &token).await?);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
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
    let max_int = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
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

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_token_balance_pages_include_zero_and_skip_burner() -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;
    let token = runtime.publish(&minter, "test-token").await?;
    let empty = token::balances(runtime, &token, None, 1).await??;
    assert!(empty.items.is_empty() && empty.next.is_none());
    token::mint(runtime, &token, &minter, 10.into()).await??;
    token::transfer(runtime, &token, &minter, &holder, 10.into()).await??;
    token::burn(runtime, &token, &holder, 1.into()).await??;
    let first = token::balances(runtime, &token, None, 1).await??;
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.next.as_ref(), Some(&first.items[0].key));
    let last = token::balances(runtime, &token, first.next.as_deref(), 1).await??;
    assert_eq!(last.items.len(), 1);
    assert!(last.next.is_none());
    assert_ne!(first.items[0].key, last.items[0].key);
    let mut amounts = [first.items[0].value, last.items[0].value];
    amounts.sort();
    assert_eq!(amounts, [Integer::from(0), Integer::from(9)]);
    assert!(
        token::balances(runtime, &token, Some("invalid"), 1)
            .await?
            .is_err()
    );
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_decimal_token_balance_pages() -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;
    let token = runtime.publish(&minter, "decimal-token").await?;
    let empty = decimal_token::balances(runtime, &token, None, 1).await??;
    assert!(empty.items.is_empty() && empty.next.is_none());
    decimal_token::mint(runtime, &token, &minter, Decimal::from("10.5")).await??;
    decimal_token::transfer(runtime, &token, &minter, &holder, Decimal::from("10.5")).await??;
    decimal_token::burn(runtime, &token, &holder, Decimal::from("1")).await??;
    let first = decimal_token::balances(runtime, &token, None, 1).await??;
    assert_eq!(first.items.len(), 1);
    assert!(first.next.is_some());
    let last = decimal_token::balances(runtime, &token, first.next.as_deref(), 1).await??;
    assert_eq!(last.items.len(), 1);
    assert!(last.next.is_none());
    assert_ne!(first.items[0].acc, last.items[0].acc);
    let mut amounts = [first.items[0].amt, last.items[0].amt];
    amounts.sort();
    assert_eq!(amounts, [Decimal::from("0"), Decimal::from("9.5")]);
    assert!(
        decimal_token::balances(runtime, &token, Some("invalid"), 1)
            .await?
            .is_err()
    );
    Ok(())
}
