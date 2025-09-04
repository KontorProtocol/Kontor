use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
    test = true,
);

import!(
    name = "shared-account",
    height = 0,
    tx_index = 0,
    path = "../contracts/shared-account/wit",
    test = true,
);

interface!(
    name = "token-dyn",
    path = "../contracts/token/wit",
    test = true
);

#[tokio::test]
async fn test_shared_account_contract() -> Result<()> {
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    let alice = "alice";
    let bob = "bob";
    let claire = "claire";
    let dara = "dara";

    token::mint(&runtime, alice, 100).await?;

    let account_id = shared_account::open(&runtime, alice, 50, vec![bob, dara]).await??;

    let result = shared_account::balance(&runtime, &account_id).await?;
    assert_eq!(result, Some(50));

    shared_account::deposit(&runtime, alice, &account_id, 25).await??;

    let result = shared_account::balance(&runtime, &account_id).await?;
    assert_eq!(result, Some(75));

    shared_account::withdraw(&runtime, bob, &account_id, 25).await??;

    let result = shared_account::balance(&runtime, &account_id).await?;
    assert_eq!(result, Some(50));

    shared_account::withdraw(&runtime, alice, &account_id, 50).await??;

    let result = shared_account::balance(&runtime, &account_id).await?;
    assert_eq!(result, Some(0));

    let result = shared_account::withdraw(&runtime, bob, &account_id, 1).await?;
    assert_eq!(
        result,
        Err(Error::Message("insufficient balance".to_string()))
    );

    let result = shared_account::withdraw(&runtime, claire, &account_id, 1).await?;
    assert_eq!(result, Err(Error::Message("unauthorized".to_string())));

    let token_address = ContractAddress {
        name: "token".to_string(),
        height: 0,
        tx_index: 0,
    };
    let result = shared_account::token_balance(&runtime, token_address.clone(), alice).await?;
    assert_eq!(result, Some(75));

    let result = token_dyn::balance(&runtime, &token_address, bob).await?;
    assert_eq!(result, Some(25));

    let result = shared_account::tenants(&runtime, &account_id).await?;
    assert_eq!(
        result,
        Some(vec![alice.to_string(), bob.to_string(), dara.to_string()])
    );

    Ok(())
}
