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

    let epoch = staking::get_epoch_info(runtime).await?;
    assert_eq!(epoch.active_count, 0);
    assert_eq!(epoch.epoch, 0);

    assert_eq!(staking::get_active_set(runtime).await?.len(), 0);
    assert_eq!(staking::get_active_count(runtime).await?, 0);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_register_validator_errors() -> Result<()> {
    let validator = runtime.identity().await?;

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

    // Go inactive, try re-register without withdrawing
    staking::begin_unstake(runtime, &validator).await??;
    let result = staking::register_validator(runtime, &validator, vec![3u8; 32], 2.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message(
            "withdraw existing stake before re-registering".to_string()
        ))
    );

    // Withdraw, then re-register succeeds
    staking::withdraw_stake(runtime, &validator).await??;
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

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_add_stake_rejected_during_pending_exit() -> Result<()> {
    let validator = runtime.identity().await?;

    staking::register_validator(runtime, &validator, vec![1u8; 32], 3.into()).await??;

    // add_stake while pending_join is fine
    staking::add_stake(runtime, &validator, 1.into()).await??;

    // Simulate activation + begin unstake to get to pending_exit
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

    staking::register_validator(runtime, &validator, vec![1u8; 32], 5.into()).await??;

    let result = staking::begin_unstake(runtime, &validator).await??;
    assert_eq!(result.status, staking::ValidatorStatus::Inactive);

    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::Inactive);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_withdraw_stake() -> Result<()> {
    let validator = runtime.identity().await?;

    staking::register_validator(runtime, &validator, vec![1u8; 32], 5.into()).await??;

    // Can't withdraw while pending
    let result = staking::withdraw_stake(runtime, &validator).await?;
    assert!(result.is_err());

    // Go to inactive
    staking::begin_unstake(runtime, &validator).await??;

    // Now can withdraw
    let result = staking::withdraw_stake(runtime, &validator).await??;
    assert_eq!(result.status, staking::ValidatorStatus::Inactive);
    assert_eq!(result.stake, Decimal::from(0));

    // Token balance should have mostly recovered (minus gas)
    let balance = token::balance(runtime, &validator).await?.unwrap();
    assert!(balance > Decimal::from(9));

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

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_register_and_activate_regtest() -> Result<()> {
    let validator = runtime.identity().await?;
    let ed25519_key = vec![1u8; 32];

    staking::register_validator(runtime, &validator, ed25519_key.clone(), 5.into()).await??;

    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::PendingJoin);

    // Mine blocks past epoch boundary (epoch_length = 10)
    for _ in 0..12 {
        runtime.issuance(&validator).await?;
    }

    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::Active);

    let active_set = staking::get_active_set(runtime).await?;
    assert_eq!(active_set.len(), 1);
    assert_eq!(active_set[0].x_only_pubkey, validator.to_string());

    let epoch = staking::get_epoch_info(runtime).await?;
    assert!(epoch.epoch >= 1);
    assert_eq!(epoch.active_count, 1);
    assert_eq!(epoch.total_stake, Decimal::from(5));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_add_stake_rejected_during_pending_exit_regtest() -> Result<()> {
    let validator = runtime.identity().await?;

    staking::register_validator(runtime, &validator, vec![1u8; 32], 5.into()).await??;

    // Activate
    for _ in 0..12 {
        runtime.issuance(&validator).await?;
    }
    assert_eq!(
        staking::get_validator(runtime, &validator)
            .await?
            .unwrap()
            .status,
        staking::ValidatorStatus::Active
    );

    // Begin unstake → pending_exit
    staking::begin_unstake(runtime, &validator).await??;
    assert_eq!(
        staking::get_validator(runtime, &validator)
            .await?
            .unwrap()
            .status,
        staking::ValidatorStatus::PendingExit
    );

    // add_stake should be rejected
    let result = staking::add_stake(runtime, &validator, 3.into()).await?;
    assert_eq!(
        result,
        Err(Error::Message(
            "cannot add stake while inactive or pending exit".to_string()
        ))
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_full_lifecycle_regtest() -> Result<()> {
    let validator = runtime.identity().await?;
    let ed25519_key = vec![1u8; 32];

    // Register
    staking::register_validator(runtime, &validator, ed25519_key.clone(), 5.into()).await??;

    // Mine to activation
    for _ in 0..12 {
        runtime.issuance(&validator).await?;
    }
    assert_eq!(
        staking::get_validator(runtime, &validator)
            .await?
            .unwrap()
            .status,
        staking::ValidatorStatus::Active
    );

    // Begin unstake
    staking::begin_unstake(runtime, &validator).await??;
    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::PendingExit);

    // Mine to next epoch
    for _ in 0..12 {
        runtime.issuance(&validator).await?;
    }
    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::Inactive);

    // Withdraw
    let result = staking::withdraw_stake(runtime, &validator).await??;
    assert_eq!(result.stake, Decimal::from(0));

    // Tokens returned (minus gas)
    let balance = token::balance(runtime, &validator).await?.unwrap();
    assert!(balance > Decimal::from(9));

    Ok(())
}
