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

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_register_validator() -> Result<()> {
    let validator = runtime.identity().await?;
    let ed25519_key = vec![1u8; 32];

    let result = staking::register_validator(
        runtime,
        &validator,
        ed25519_key.clone(),
        5u64.try_into().unwrap(),
    )
    .await??;
    assert_eq!(result.status, staking::ValidatorStatus::PendingJoin);
    assert_eq!(result.stake, 5u64.try_into().unwrap());
    assert_eq!(result.ed25519_pubkey, ed25519_key);
    assert_eq!(result.x_only_pubkey, validator.to_string());

    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::PendingJoin);
    assert_eq!(info.stake, 5u64.try_into().unwrap());

    let epoch = staking::get_staking_info(runtime).await?;
    assert_eq!(epoch.active_count, 0);
    assert_eq!(epoch.total_stake, 0u64.try_into().unwrap());

    assert_eq!(staking::get_active_set(runtime).await?.len(), 0);
    assert_eq!(staking::get_active_count(runtime).await?, 0);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_register_validator_errors() -> Result<()> {
    let validator = runtime.identity().await?;

    // Stake exceeds maximum
    let result = staking::register_validator(
        runtime,
        &validator,
        vec![1u8; 32],
        1_000_000_001u64.try_into().unwrap(),
    )
    .await?;
    assert_eq!(
        result,
        Err(Error::Message("stake exceeds maximum".to_string()))
    );

    // Bad ed25519 key length
    let result =
        staking::register_validator(runtime, &validator, vec![1u8; 16], 5u64.try_into().unwrap())
            .await?;
    assert_eq!(
        result,
        Err(Error::Message(
            "expected 32-byte ed25519 pubkey".to_string()
        ))
    );

    // Register once successfully
    staking::register_validator(runtime, &validator, vec![1u8; 32], 5u64.try_into().unwrap())
        .await??;

    // Double registration
    let result =
        staking::register_validator(runtime, &validator, vec![2u8; 32], 3u64.try_into().unwrap())
            .await?;
    assert_eq!(
        result,
        Err(Error::Message("already registered".to_string()))
    );

    // Cancel participation, then reuse the existing bond with an additional deposit.
    staking::leave_validation(runtime, &validator).await??;
    let result =
        staking::register_validator(runtime, &validator, vec![3u8; 32], 2u64.try_into().unwrap())
            .await??;
    assert_eq!(result.status, staking::ValidatorStatus::PendingJoin);
    assert_eq!(result.stake, 7u64.try_into().unwrap());

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_add_stake() -> Result<()> {
    let validator = runtime.identity().await?;

    staking::register_validator(runtime, &validator, vec![1u8; 32], 3u64.try_into().unwrap())
        .await??;

    let result = staking::add_stake(runtime, &validator, 2u64.try_into().unwrap()).await??;
    assert_eq!(result.stake, 5u64.try_into().unwrap());
    assert_eq!(result.withdrawal_height, None);

    let info = staking::get_validator(runtime, &validator).await?.unwrap();
    assert_eq!(info.stake, 5u64.try_into().unwrap());

    // Negative and zero amounts rejected
    let result = staking::add_stake(runtime, &validator, Decimal::try_from(-1i64).unwrap()).await?;
    assert_eq!(
        result,
        Err(Error::Message("amount must be positive".to_string()))
    );
    let result = staking::add_stake(runtime, &validator, 0u64.try_into().unwrap()).await?;
    assert_eq!(
        result,
        Err(Error::Message("amount must be positive".to_string()))
    );

    // add_stake that would exceed max
    let result =
        staking::add_stake(runtime, &validator, 1_000_000_000u64.try_into().unwrap()).await?;
    assert_eq!(
        result,
        Err(Error::Message(
            "total stake would exceed maximum".to_string()
        ))
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_add_stake_rejected_after_withdrawal_request() -> Result<()> {
    let signer = runtime.identity().await?;
    staking::add_stake(runtime, &signer, 3u64.try_into().unwrap()).await??;
    staking::begin_unstake(runtime, &signer).await??;
    assert_eq!(
        staking::add_stake(runtime, &signer, 1u64.try_into().unwrap()).await?,
        Err(Error::Message("withdrawal already requested".into()))
    );
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_cancel_validator_join_keeps_bond() -> Result<()> {
    let signer = runtime.identity().await?;
    staking::register_validator(runtime, &signer, vec![1; 32], 5u64.try_into().unwrap()).await??;
    assert!(staking::begin_unstake(runtime, &signer).await?.is_err());
    let canceled = staking::leave_validation(runtime, &signer).await??;
    assert_eq!(canceled.status, staking::ValidatorStatus::Inactive);
    assert_eq!(canceled.stake, 5u64.try_into().unwrap());
    let bond = staking::get_stake(runtime, &signer).await?.unwrap();
    assert_eq!(bond.stake, canceled.stake);
    assert_eq!(bond.withdrawal_height, None);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_storage_only_bond_needs_no_consensus_key() -> Result<()> {
    let signer = runtime.identity().await?;
    let bond = staking::add_stake(runtime, &signer, 5u64.try_into().unwrap()).await??;
    assert_eq!(bond.stake, 5u64.try_into().unwrap());
    assert!(staking::get_validator(runtime, &signer).await?.is_none());
    assert!(staking::get_active_set(runtime).await?.is_empty());
    let withdrawal = staking::begin_unstake(runtime, &signer).await??;
    assert!(withdrawal.withdrawal_height.is_some());
    assert!(staking::withdraw_stake(runtime, &signer).await?.is_err());
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_multiple_validators() -> Result<()> {
    let v1 = runtime.identity().await?;
    let v2 = runtime.identity().await?;

    staking::register_validator(runtime, &v1, vec![1u8; 32], 5u64.try_into().unwrap()).await??;
    staking::register_validator(runtime, &v2, vec![2u8; 32], 3u64.try_into().unwrap()).await??;

    let info1 = staking::get_validator(runtime, &v1).await?.unwrap();
    assert_eq!(info1.stake, 5u64.try_into().unwrap());

    let info2 = staking::get_validator(runtime, &v2).await?.unwrap();
    assert_eq!(info2.stake, 3u64.try_into().unwrap());

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_duplicate_ed25519_key_rejected() -> Result<()> {
    let v1 = runtime.identity().await?;
    let v2 = runtime.identity().await?;
    let same_key = vec![1u8; 32];

    staking::register_validator(runtime, &v1, same_key.clone(), 5u64.try_into().unwrap()).await??;

    let result =
        staking::register_validator(runtime, &v2, same_key, 3u64.try_into().unwrap()).await?;
    assert_eq!(
        result,
        Err(Error::Message(
            "ed25519 pubkey already registered by another validator".to_string()
        ))
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_duplicate_ed25519_key_allowed_after_inactive() -> Result<()> {
    let v1 = runtime.identity().await?;
    let v2 = runtime.identity().await?;
    let same_key = vec![1u8; 32];

    // v1 cancels consensus participation while retaining its bond.
    staking::register_validator(runtime, &v1, same_key.clone(), 5u64.try_into().unwrap()).await??;
    staking::leave_validation(runtime, &v1).await??;

    // v2 can now use the same key since v1 is inactive
    let result =
        staking::register_validator(runtime, &v2, same_key, 3u64.try_into().unwrap()).await??;
    assert_eq!(result.status, staking::ValidatorStatus::PendingJoin);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_register_validator_token_balance() -> Result<()> {
    let validator = runtime.identity().await?;

    let balance_before = token::balance(runtime, &validator).await?.unwrap();
    staking::register_validator(runtime, &validator, vec![1u8; 32], 5u64.try_into().unwrap())
        .await??;
    let balance_after = token::balance(runtime, &validator).await?.unwrap();

    // Difference should be at least 5 (staked amount) plus a small gas cost
    let diff = balance_before - balance_after;
    assert!(diff >= 5u64.try_into().unwrap());
    assert!(diff < 6u64.try_into().unwrap());

    Ok(())
}
