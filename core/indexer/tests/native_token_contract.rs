use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/token/wit",
);

#[testlib::test(contracts_dir = "../../test-contracts", shared)]
async fn test_native_token_contract() -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;

    // Batch two mints (independent, same signer)
    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(900.into()));
    ops.push(token::mint_call(100.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    let result = token::balance(runtime, &minter).await?;
    let minter_tokens_spent_as_gas = Decimal::from("0.000000238");
    assert_eq!(
        result.map(|d| d.to_string()),
        Some(Decimal::from(1010) - minter_tokens_spent_as_gas).map(|d| d.to_string())
    );

    // Transfer with insufficient funds (expected error, keep separate)
    let result = token::transfer(runtime, &holder, &minter, 123.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    // Batch two transfers (independent, same signer)
    let mut ops = Ops::new(&minter);
    ops.push(token::transfer_call(&holder, 50.into()));
    ops.push(token::transfer_call(&holder, 2.into()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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
    assert!(balances.len() >= 2);
    let total = balances.iter().fold(Decimal::from(0), |acc, x| acc + x.amt);
    assert_eq!(total, token::total_supply(runtime).await?);

    Ok(())
}
