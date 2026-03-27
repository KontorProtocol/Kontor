use blst::min_sig::AggregateSignature;
use indexer::bls::KONTOR_BLS_DST;
use indexer::runtime::to_wave_expr;
use indexer_types::{AggregateInfo, ContractAddress as IndexerContractAddress, Inst, Insts};
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

    let signer_id = validator.id().unwrap();

    let result =
        staking::register_validator(runtime, &validator, ed25519_key.clone(), 5.into()).await??;
    assert_eq!(result.status, staking::ValidatorStatus::PendingJoin);
    assert_eq!(result.stake, Decimal::from(5));
    assert_eq!(result.ed25519_pubkey, ed25519_key);
    assert_eq!(result.signer_id, signer_id);

    let info = staking::get_validator(runtime, signer_id).await?.unwrap();
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
    let signer_id = validator.id().unwrap();

    staking::register_validator(runtime, &validator, vec![1u8; 32], 3.into()).await??;

    let result = staking::add_stake(runtime, &validator, 2.into()).await??;
    assert_eq!(result.stake, Decimal::from(5));
    assert_eq!(result.status, staking::ValidatorStatus::PendingJoin);

    let info = staking::get_validator(runtime, signer_id).await?.unwrap();
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
    let signer_id = validator.id().unwrap();

    staking::register_validator(runtime, &validator, vec![1u8; 32], 5.into()).await??;

    let result = staking::begin_unstake(runtime, &validator).await??;
    assert_eq!(result.status, staking::ValidatorStatus::Inactive);

    let info = staking::get_validator(runtime, signer_id).await?.unwrap();
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

    let info1 = staking::get_validator(runtime, v1.id().unwrap())
        .await?
        .unwrap();
    assert_eq!(info1.stake, Decimal::from(5));

    let info2 = staking::get_validator(runtime, v2.id().unwrap())
        .await?
        .unwrap();
    assert_eq!(info2.stake, Decimal::from(3));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_register_and_activate_regtest() -> Result<()> {
    let validator = runtime.identity().await?;
    let signer_id = validator.id().unwrap();
    let ed25519_key = vec![1u8; 32];

    staking::register_validator(runtime, &validator, ed25519_key.clone(), 5.into()).await??;

    let info = staking::get_validator(runtime, signer_id).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::PendingJoin);

    for _ in 0..12 {
        runtime.issuance(&validator).await?;
    }

    let info = staking::get_validator(runtime, signer_id).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::Active);

    let active_set = staking::get_active_set(runtime).await?;
    assert_eq!(active_set.len(), 1);
    assert_eq!(active_set[0].signer_id, signer_id);

    let epoch = staking::get_epoch_info(runtime).await?;
    assert!(epoch.epoch >= 1);
    assert_eq!(epoch.active_count, 1);
    assert_eq!(epoch.total_stake, Decimal::from(5));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_add_stake_rejected_during_pending_exit_regtest() -> Result<()> {
    let validator = runtime.identity().await?;
    let signer_id = validator.id().unwrap();

    staking::register_validator(runtime, &validator, vec![1u8; 32], 5.into()).await??;

    for _ in 0..12 {
        runtime.issuance(&validator).await?;
    }
    assert_eq!(
        staking::get_validator(runtime, signer_id)
            .await?
            .unwrap()
            .status,
        staking::ValidatorStatus::Active
    );

    staking::begin_unstake(runtime, &validator).await??;
    assert_eq!(
        staking::get_validator(runtime, signer_id)
            .await?
            .unwrap()
            .status,
        staking::ValidatorStatus::PendingExit
    );
    assert_eq!(staking::get_active_set(runtime).await?.len(), 1);
    assert_eq!(staking::get_active_count(runtime).await?, 1);

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
    let signer_id = validator.id().unwrap();
    let ed25519_key = vec![1u8; 32];

    staking::register_validator(runtime, &validator, ed25519_key.clone(), 5.into()).await??;

    for _ in 0..12 {
        runtime.issuance(&validator).await?;
    }
    assert_eq!(
        staking::get_validator(runtime, signer_id)
            .await?
            .unwrap()
            .status,
        staking::ValidatorStatus::Active
    );

    staking::begin_unstake(runtime, &validator).await??;
    let info = staking::get_validator(runtime, signer_id).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::PendingExit);

    for _ in 0..12 {
        runtime.issuance(&validator).await?;
    }
    let info = staking::get_validator(runtime, signer_id).await?.unwrap();
    assert_eq!(info.status, staking::ValidatorStatus::Inactive);

    // Withdraw
    let result = staking::withdraw_stake(runtime, &validator).await??;
    assert_eq!(result.stake, Decimal::from(0));

    // Tokens returned (minus gas)
    let balance = token::balance(runtime, &validator).await?.unwrap();
    assert!(balance > Decimal::from(9));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_direct_and_aggregate_calls_share_signer_id_identity() -> Result<()> {
    let mut validator = reg_tester.identity().await?;
    let mut publisher = reg_tester.identity().await?;

    reg_tester
        .instruction(&mut validator, Inst::Issuance)
        .await?;

    let signer_id = reg_tester
        .kontor_client()
        .await
        .registry_entry(&validator.x_only_public_key().to_string())
        .await?
        .signer_id;

    let staking_contract = IndexerContractAddress {
        name: "staking".to_string(),
        height: 0,
        tx_index: 0,
    };

    let register_expr = format!(
        "register-validator({}, {})",
        to_wave_expr(vec![1u8; 32]),
        to_wave_expr(Decimal::from(5))
    );
    reg_tester
        .instruction(
            &mut validator,
            Inst::Call {
                gas_limit: 50_000,
                contract: staking_contract.clone(),
                nonce: None,
                expr: register_expr,
            },
        )
        .await?;

    let info = staking::get_validator(runtime, signer_id).await?.unwrap();
    assert_eq!(info.signer_id, signer_id);
    assert_eq!(info.stake, Decimal::from(5));
    assert_eq!(info.status, staking::ValidatorStatus::PendingJoin);

    let add_stake_inst = Inst::Call {
        gas_limit: 50_000,
        contract: staking_contract,
        nonce: Some(0),
        expr: format!("add-stake({})", to_wave_expr(Decimal::from(2))),
    };
    let msg = add_stake_inst.aggregate_signing_message(signer_id)?;
    let signer_sk = blst::min_sig::SecretKey::from_bytes(&validator.bls_secret_key)
        .map_err(|e| anyhow::anyhow!("invalid validator BLS secret key: {e:?}"))?;
    let sig = signer_sk.sign(&msg, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig], true)
        .map_err(|e| anyhow::anyhow!("aggregate signature failed: {e:?}"))?;

    reg_tester
        .insts_instruction(
            &mut publisher,
            Insts {
                ops: vec![add_stake_inst],
                aggregate: Some(AggregateInfo {
                    signer_ids: vec![signer_id],
                    signature: aggregate.to_signature().to_bytes().to_vec(),
                }),
            },
        )
        .await?;

    let updated = staking::get_validator(runtime, signer_id).await?.unwrap();
    assert_eq!(updated.signer_id, signer_id);
    assert_eq!(updated.stake, Decimal::from(7));
    assert_eq!(updated.status, staking::ValidatorStatus::PendingJoin);

    Ok(())
}
