use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/token/wit",
);

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_native_token_contract() -> Result<()> {
    let minter = runtime.identity().await?;
    let holder = runtime.identity().await?;

    // Batch two mints (independent, same signer)
    let mut ops = Ops::new(&minter);
    ops.push(token::mint_call(900u64.try_into().unwrap()));
    ops.push(token::mint_call(100u64.try_into().unwrap()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    let result = token::balance(runtime, &minter).await?.unwrap();
    // 10 from issuance + 1000 minted, minus small gas cost
    assert!(result > 1009u64.try_into().unwrap());
    assert!(result <= 1010u64.try_into().unwrap());

    // Transfer with insufficient funds (expected error, keep separate)
    let result = token::transfer(runtime, &holder, &minter, 123u64.try_into().unwrap()).await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient funds".to_string()))
    );

    // Batch two transfers (independent, same signer)
    let mut ops = Ops::new(&minter);
    ops.push(token::transfer_call(&holder, 50u64.try_into().unwrap()));
    ops.push(token::transfer_call(&holder, 2u64.try_into().unwrap()));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    let result = token::balance(runtime, &holder).await?.unwrap();
    // 10 from issuance + 52 from transfers, minus small gas cost
    assert!(result > 61u64.try_into().unwrap());
    assert!(result <= 62u64.try_into().unwrap());

    let result = token::balance(runtime, &minter).await?.unwrap();
    // 1010 - 52 transferred, minus small gas cost
    assert!(result > 957u64.try_into().unwrap());
    assert!(result <= 958u64.try_into().unwrap());

    let result = token::balance(runtime, "foo").await?;
    assert_eq!(result, None);

    let balances = token::balances(runtime).await?;
    assert!(balances.len() >= 2);
    // Total supply vs sum-of-balances check: only valid in local mode where
    // no concurrent modules modify native token state between the two queries.
    if runtime.reg_tester().is_none() {
        let total: Decimal = balances
            .iter()
            .fold(0u64.try_into().unwrap(), |acc, x| acc + x.amt);
        assert_eq!(total, token::total_supply(runtime).await?);
    }

    Ok(())
}
