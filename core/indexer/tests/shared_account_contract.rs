use indexer::logging;
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

#[tokio::test]
async fn test_shared_account_contract() -> Result<()> {
    logging::setup();
    let runtime = Runtime::new(RuntimeConfig::default()).await?;
    let alice = "alice";
    let bob = "bob";
    let claire = "claire";

    token::mint(&runtime, alice, 100).await?;

    let account_id = shared_account::open(&runtime, alice, 50, vec![bob]).await??;

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

    Ok(())
}
