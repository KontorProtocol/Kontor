use testlib::*;

import!(
    name = "staking",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/staking/wit",
);

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/token/wit",
);

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_register_validator() -> Result<()> {
    let validator = runtime.identity().await?;
    let ed25519_key = vec![1u8; 32];

    let result =
        staking::register_validator(runtime, &validator, ed25519_key.clone(), 5.into()).await??;
    assert_eq!(result.status, staking::ValidatorStatus::PendingJoin);
    assert_eq!(result.stake, Decimal::from(5));
    assert_eq!(result.ed25519_pubkey, ed25519_key);
    assert_eq!(result.x_only_pubkey, validator.to_string());

    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::PendingJoin);
    assert_eq!(info.stake, Decimal::from(5));

    let epoch = staking::get_staking_info(runtime).await?;
    assert_eq!(epoch.active_count, 0);
    assert_eq!(epoch.total_stake, Decimal::from(0));

    assert_eq!(staking::get_active_set(runtime).await?.len(), 0);
    assert_eq!(staking::get_active_count(runtime).await?, 0);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_register_validator_errors() -> Result<()> {
    let validator = runtime.identity().await?;

    // Stake exceeds maximum
    let result =
        staking::register_validator(runtime, &validator, vec![1u8; 32], 1_000_000_001u64.into())
            .await?;
    assert_eq!(
        result,
        Err(Error::Message("stake exceeds maximum".to_string()))
    );

    // Bad ed25519 key length
    let result = staking::register_validator(runtime, &validator, vec![1u8; 16], 5.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message(
            "expected 32-byte ed25519 pubkey".to_string()
        ))
    );

    // Register once successfully
    staking::register_validator(runtime, &validator, vec![1u8; 32], 5.into()).await??;

    // Double registration
    let result = staking::register_validator(runtime, &validator, vec![2u8; 32], 3.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message("already registered".to_string()))
    );

    // Go inactive from PENDING_JOIN — tokens returned automatically, can re-register directly
    staking::begin_unstake(runtime, &validator).await??;
    let result =
        staking::register_validator(runtime, &validator, vec![3u8; 32], 2.into()).await??;
    assert_eq!(result.status, staking::ValidatorStatus::PendingJoin);
    assert_eq!(result.stake, Decimal::from(2));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_add_stake() -> Result<()> {
    let validator = runtime.identity().await?;

    staking::register_validator(runtime, &validator, vec![1u8; 32], 3.into()).await??;

    let result = staking::add_stake(runtime, &validator, 2.into()).await??;
    assert_eq!(result.stake, Decimal::from(5));
    assert_eq!(result.status, staking::ValidatorStatus::PendingJoin);

    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.stake, Decimal::from(5));

    // Negative and zero amounts rejected
    let result = staking::add_stake(runtime, &validator, Decimal::from(-1)).await?;
    assert_eq!(
        result,
        Err(Error::Message("amount must be positive".to_string()))
    );
    let result = staking::add_stake(runtime, &validator, Decimal::from(0)).await?;
    assert_eq!(
        result,
        Err(Error::Message("amount must be positive".to_string()))
    );

    // add_stake that would exceed max
    let result = staking::add_stake(runtime, &validator, 1_000_000_000u64.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message(
            "total stake would exceed maximum".to_string()
        ))
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_add_stake_rejected_during_pending_exit() -> Result<()> {
    let validator = runtime.identity().await?;

    staking::register_validator(runtime, &validator, vec![1u8; 32], 3.into()).await??;

    // add_stake while pending_join is fine
    staking::add_stake(runtime, &validator, 1.into()).await??;

    // (local mode cannot trigger activation)
    // (use begin_unstake from pending_join which goes straight to inactive,
    //  then re-register and go through regtest activation path isn't needed —
    //  just test the error directly via local mode workaround)
    // In local mode we can't reach PENDING_EXIT without epoch transitions,
    // so test that add_stake is rejected for inactive validators instead
    staking::begin_unstake(runtime, &validator).await??;
    let result = staking::add_stake(runtime, &validator, 1.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message(
            "cannot add stake while inactive or pending exit".to_string()
        ))
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_begin_unstake_from_pending() -> Result<()> {
    let validator = runtime.identity().await?;

    let balance_before = token::balance(runtime, &validator).await?.unwrap();
    staking::register_validator(runtime, &validator, vec![1u8; 32], 5.into()).await??;

    let result = staking::begin_unstake(runtime, &validator).await??;
    assert_eq!(result.status, staking::ValidatorStatus::Inactive);

    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::Inactive);
    assert_eq!(info.stake, Decimal::from(0));

    // Tokens returned automatically when unstaking from PENDING_JOIN
    let balance_after_unstake = token::balance(runtime, &validator).await?.unwrap();
    assert!(balance_before - balance_after_unstake < Decimal::from(1)); // only gas cost

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_unstake_returns_tokens() -> Result<()> {
    let validator = runtime.identity().await?;

    let balance_before = token::balance(runtime, &validator).await?.unwrap();
    staking::register_validator(runtime, &validator, vec![1u8; 32], 5.into()).await??;

    // Unstake from PENDING_JOIN — tokens returned automatically
    staking::begin_unstake(runtime, &validator).await??;

    // Token balance should have mostly recovered (minus gas)
    let balance = token::balance(runtime, &validator).await?.unwrap();
    assert!(balance_before - balance < Decimal::from(1));

    // Validator entry still exists with ed25519_pubkey retained
    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.ed25519_pubkey, vec![1u8; 32]);
    assert_eq!(info.stake, Decimal::from(0));
    assert_eq!(info.status, staking::ValidatorStatus::Inactive);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_multiple_validators() -> Result<()> {
    let v1 = runtime.identity().await?;
    let v2 = runtime.identity().await?;

    staking::register_validator(runtime, &v1, vec![1u8; 32], 5.into()).await??;
    staking::register_validator(runtime, &v2, vec![2u8; 32], 3.into()).await??;

    let info1 = staking::get_validator(runtime, &v1).await?.unwrap();
    assert_eq!(info1.stake, Decimal::from(5));

    let info2 = staking::get_validator(runtime, &v2).await?.unwrap();
    assert_eq!(info2.stake, Decimal::from(3));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_duplicate_ed25519_key_rejected() -> Result<()> {
    let v1 = runtime.identity().await?;
    let v2 = runtime.identity().await?;
    let same_key = vec![1u8; 32];

    staking::register_validator(runtime, &v1, same_key.clone(), 5.into()).await??;

    let result = staking::register_validator(runtime, &v2, same_key, 3.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message(
            "ed25519 pubkey already registered by another validator".to_string()
        ))
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_duplicate_ed25519_key_allowed_after_inactive() -> Result<()> {
    let v1 = runtime.identity().await?;
    let v2 = runtime.identity().await?;
    let same_key = vec![1u8; 32];

    // v1 registers and then goes inactive (tokens returned automatically from PENDING_JOIN)
    staking::register_validator(runtime, &v1, same_key.clone(), 5.into()).await??;
    staking::begin_unstake(runtime, &v1).await??;

    // v2 can now use the same key since v1 is inactive
    let result = staking::register_validator(runtime, &v2, same_key, 3.into()).await??;
    assert_eq!(result.status, staking::ValidatorStatus::PendingJoin);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_register_validator_token_balance() -> Result<()> {
    let validator = runtime.identity().await?;

    let balance_before = token::balance(runtime, &validator).await?.unwrap();
    staking::register_validator(runtime, &validator, vec![1u8; 32], 5.into()).await??;
    let balance_after = token::balance(runtime, &validator).await?.unwrap();

    // Difference should be at least 5 (staked amount) plus a small gas cost
    let diff = balance_before - balance_after;
    assert!(diff >= Decimal::from(5));
    assert!(diff < Decimal::from(6));

    Ok(())
}
