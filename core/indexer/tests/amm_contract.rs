use testlib::*;

import!(
    name = "token_a",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
);


import!(
    name = "token_b",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
);

import!(
    name = "amm",
    height = 0,
    tx_index = 0,
    path = "../contracts/amm/wit",
);

interface!(name = "token-dyn", path = "../contracts/token/wit");

#[tokio::test]
async fn test_token_contract() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;

    let token_a = ContractAddress {
        name: "token_a".to_string(),
        height: 0,
        tx_index: 0,
    };

    let token_b = ContractAddress {
        name: "token_b".to_string(),
        height: 0,
        tx_index: 0,
    };

    let admin = "test_admin";
    let minter = "test_minter";
    let holder = "test_holder";
    token_a::mint(&runtime, minter, 1000.into()).await?;
    token_b::mint(&runtime, minter, 1000.into()).await?;

    amm::create(&runtime, admin, token_a.clone(), token_b.clone()).await?;

    let custody = amm::custody_address(&runtime).await?;

    token_a::transfer(&runtime, minter, &custody, 100.into()).await??;
    token_b::transfer(&runtime, minter, &custody, 500.into()).await??;

    let bal_a = amm::token_balance(&runtime, token_a.clone()).await?;
    assert_eq!(bal_a, Some(100.into()));
    let bal_b = amm::token_balance(&runtime, token_b.clone()).await?;
    assert_eq!(bal_b, Some(500.into()));
    let k = bal_a.unwrap() * bal_b.unwrap();

    let result = amm::quote_swap(&runtime, token_a.clone(), 10.into()).await?;
    assert_eq!(result, Some(45.into()));

    let result = amm::swap(&runtime, minter, token_a.clone(), 10.into()).await?;
    assert_eq!(result, Ok(45.into()));

    let bal_a = amm::token_balance(&runtime, token_a.clone()).await?;
    let bal_b = amm::token_balance(&runtime, token_b.clone()).await?;
//    assert_eq!(bal_a.unwrap() * bal_b.unwrap(), k);

    let result = amm::quote_swap(&runtime, token_b.clone(), 100.into()).await?;
    assert_eq!(result, Some(19.into()));
    let result = amm::swap(&runtime, minter, token_b.clone(), 100.into()).await?;
    assert_eq!(result, Ok(19.into()));

    let bal_a = amm::token_balance(&runtime, token_a.clone()).await?;
    let bal_b = amm::token_balance(&runtime, token_b.clone()).await?;
    assert_eq!(bal_a.unwrap() * bal_b.unwrap(), k);

    Ok(())
}
