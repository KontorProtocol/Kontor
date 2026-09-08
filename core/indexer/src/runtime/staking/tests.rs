use anyhow::Result;
use indexer_types::BlockRow;

use super::api::{self, ActiveValidatorInfo, ValidatorStatus};
use super::reward_tests::escrow;
use crate::consensus::signing::PrivateKey;
use crate::database::queries::{get_checkpoint_by_height, insert_block};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::filestorage::api as filestorage;
use crate::runtime::numerics::{add_decimal, sub_decimal};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Error, GenesisValidator, Runtime};
use crate::test_utils::{
    make_descriptor, new_mock_block_hash, test_runtime, test_runtime_with_genesis, valid_seed_field,
};

const LIMIT: u64 = u64::MAX / 3;

fn assert_capacity_error<T>(result: Result<T, Error>) {
    let Err(Error::Message(message)) = result else {
        panic!("expected stake capacity error");
    };
    assert_eq!(message, "total stake exceeds voting power limit");
}

fn core() -> Signer {
    Signer::Core(Box::new(Signer::Nobody))
}

fn validator(holder: String, seed: u8, stake: Decimal) -> ActiveValidatorInfo {
    ActiveValidatorInfo {
        x_only_pubkey: holder,
        ed25519_pubkey: PrivateKey::from([seed; 32])
            .public_key()
            .as_bytes()
            .to_vec(),
        stake,
    }
}

async fn funded_signer(runtime: &mut Runtime) -> Result<Signer> {
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    token::issue_to(
        runtime,
        &core(),
        HolderRef::from(&signer),
        Decimal::from("1000"),
    )
    .await??;
    Ok(signer)
}

async fn advance(runtime: &mut Runtime, height: u64) -> Result<()> {
    insert_block(
        &runtime.get_storage_conn(),
        BlockRow::builder()
            .height(height)
            .hash(new_mock_block_hash(height as u32))
            .relevant(true)
            .build(),
    )
    .await?;
    runtime.set_context(height, None, None, None).await;
    api::process_pending_validators(runtime, &core(), height).await??;
    Ok(())
}

#[tokio::test]
async fn storage_only_withdrawal_preserves_escrow_and_rolls_back() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let signer = funded_signer(&mut runtime).await?;
    let amount = Decimal::from("100");
    api::add_stake(&mut runtime, &signer, amount).await??;
    assert!(api::get_validator(&mut runtime, &signer).await?.is_none());
    assert!(api::get_active_set(&mut runtime).await?.is_empty());
    assert!(!api::has_reward_recipients(&mut runtime).await?);
    assert_eq!(escrow(&mut runtime).await?, amount);
    let withdrawal = api::begin_unstake(&mut runtime, &signer).await??;
    let height = withdrawal.withdrawal_height.unwrap();
    assert_eq!(height, 2029);
    assert!(
        api::add_stake(&mut runtime, &signer, Decimal::from("1"))
            .await?
            .is_err()
    );
    assert!(
        api::register_validator(&mut runtime, &signer, vec![2; 32], Decimal::default())
            .await?
            .is_err()
    );
    assert!(api::begin_unstake(&mut runtime, &signer).await?.is_err());
    advance(&mut runtime, height - 1).await?;
    assert_eq!(
        api::withdraw_stake(&mut runtime, &signer)
            .await?
            .unwrap_err(),
        Error::Message("withdrawal delay has not elapsed".into())
    );
    let balance = token::balance(&mut runtime, HolderRef::from(&signer)).await?;
    for replay in 0..2 {
        advance(&mut runtime, height).await?;
        let supply = token::total_supply(&mut runtime).await?;
        let withdrawn = api::withdraw_stake(&mut runtime, &signer).await??;
        assert_eq!(withdrawn.withdrawal_height, None);
        assert_eq!(withdrawn.stake, Decimal::default());
        assert_eq!(escrow(&mut runtime).await?, Decimal::default());
        // User calls burn execution fees even through the direct runtime API.
        let fee = sub_decimal(supply, token::total_supply(&mut runtime).await?)?;
        assert!(fee >= Decimal::default() && fee < Decimal::from("1"));
        assert_eq!(
            token::balance(&mut runtime, HolderRef::from(&signer)).await?,
            Some(sub_decimal(add_decimal(balance.unwrap(), amount)?, fee)?)
        );
        assert!(api::withdraw_stake(&mut runtime, &signer).await?.is_err());
        if replay == 0 {
            runtime.storage.rollback_with_footprint(height - 1).await?;
            runtime.set_context(height - 1, None, None, None).await;
            let restored = api::get_stake(&mut runtime, &signer).await?.unwrap();
            assert_eq!(restored.withdrawal_height, Some(height));
            assert_eq!(restored.stake, amount);
            assert_eq!(escrow(&mut runtime).await?, amount);
            assert_eq!(
                token::balance(&mut runtime, HolderRef::from(&signer)).await?,
                balance
            );
        }
    }
    assert!(api::get_validator(&mut runtime, &signer).await?.is_none());
    api::add_stake(&mut runtime, &signer, amount).await??;
    Ok(())
}

#[tokio::test]
async fn withdrawal_checks_storage_after_maturity_including_expired_challenges() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let alice = funded_signer(&mut runtime).await?;
    let bob = funded_signer(&mut runtime).await?;
    let carol = funded_signer(&mut runtime).await?;
    let amount = Decimal::from("100");
    for signer in [&alice, &bob, &carol] {
        api::add_stake(&mut runtime, signer, amount).await??;
    }
    let agreement = filestorage::create_agreement(
        &mut runtime,
        &alice,
        make_descriptor("withdrawal".into(), vec![1; 32], 16, 100, "file.txt".into()),
    )
    .await??
    .agreement_id;
    let prover = filestorage::join_agreement(&mut runtime, &alice, &agreement)
        .await??
        .node_id;
    for signer in [&bob, &carol] {
        filestorage::join_agreement(&mut runtime, signer, &agreement).await??;
    }
    let challenge = filestorage::create_challenge_for_agreement(
        &mut runtime,
        &alice,
        &agreement,
        prover,
        1,
        valid_seed_field(1).bytes.to_vec(),
    )
    .await??;
    let exit = api::begin_unstake(&mut runtime, &alice).await??;
    api::begin_unstake(&mut runtime, &bob).await??;
    advance(&mut runtime, exit.withdrawal_height.unwrap()).await?;
    for signer in [&alice, &bob] {
        assert_eq!(
            api::withdraw_stake(&mut runtime, signer)
                .await?
                .unwrap_err(),
            Error::Message("unresolved storage obligations".into())
        );
        filestorage::leave_agreement(&mut runtime, signer, &agreement).await??;
    }
    api::withdraw_stake(&mut runtime, &bob).await??;
    assert!(api::withdraw_stake(&mut runtime, &alice).await?.is_err());
    assert_eq!(
        filestorage::expire_challenges(&mut runtime, &core(), challenge.deadline_height).await?,
        1
    );
    assert_eq!(
        api::withdraw_stake(&mut runtime, &alice)
            .await?
            .unwrap_err(),
        Error::Message("unresolved storage obligations".into())
    );
    assert_eq!(
        api::get_stake(&mut runtime, &alice).await?.unwrap().stake,
        amount
    );
    Ok(())
}

#[tokio::test]
async fn storage_bond_survives_entering_and_leaving_validation() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let signer = funded_signer(&mut runtime).await?;
    api::add_stake(&mut runtime, &signer, Decimal::from("100")).await??;
    let agreement = filestorage::create_agreement(
        &mut runtime,
        &signer,
        make_descriptor(
            "independent".into(),
            vec![1; 32],
            16,
            100,
            "file.txt".into(),
        ),
    )
    .await??
    .agreement_id;
    let node = filestorage::join_agreement(&mut runtime, &signer, &agreement)
        .await??
        .node_id;
    assert!(api::get_validator(&mut runtime, &signer).await?.is_none());
    assert!(
        api::register_validator(&mut runtime, &signer, vec![1; 32], Decimal::from("-1"))
            .await?
            .is_err()
    );
    let joined =
        api::register_validator(&mut runtime, &signer, vec![1; 32], Decimal::default()).await??;
    assert_eq!(joined.stake, Decimal::from("100"));
    assert_eq!(escrow(&mut runtime).await?, joined.stake);
    assert!(api::begin_unstake(&mut runtime, &signer).await?.is_err());
    advance(&mut runtime, joined.activation_height).await?;
    assert_eq!(api::get_active_count(&mut runtime).await?, 1);
    assert!(api::begin_unstake(&mut runtime, &signer).await?.is_err());
    let exit = api::leave_validation(&mut runtime, &signer).await??;
    filestorage::leave_agreement(&mut runtime, &signer, &agreement).await??;
    filestorage::join_agreement(&mut runtime, &signer, &agreement).await??;
    api::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
    assert_eq!(
        api::get_staking_info(&mut runtime).await?.total_stake,
        Decimal::from("101")
    );
    assert!(api::begin_unstake(&mut runtime, &signer).await?.is_err());
    advance(&mut runtime, exit.deactivation_height).await?;
    assert_eq!(api::get_active_count(&mut runtime).await?, 0);
    assert_eq!(
        api::get_staking_info(&mut runtime).await?.total_stake,
        Decimal::default()
    );
    assert!(filestorage::is_node_in_agreement(&mut runtime, &agreement, node).await?);
    runtime
        .storage
        .rollback_with_footprint(joined.activation_height)
        .await?;
    runtime
        .set_context(joined.activation_height, None, None, None)
        .await;
    assert_eq!(
        api::get_validator(&mut runtime, &signer)
            .await?
            .unwrap()
            .status,
        ValidatorStatus::PendingExit
    );
    assert_eq!(
        api::get_staking_info(&mut runtime).await?.total_stake,
        Decimal::from("101")
    );
    assert!(filestorage::is_node_in_agreement(&mut runtime, &agreement, node).await?);
    advance(&mut runtime, exit.deactivation_height).await?;
    let bond = api::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
    filestorage::leave_agreement(&mut runtime, &signer, &agreement).await??;
    filestorage::join_agreement(&mut runtime, &signer, &agreement).await??;
    assert_eq!(bond.withdrawal_height, None);
    assert_eq!(bond.stake, Decimal::from("102"));
    api::register_validator(&mut runtime, &signer, vec![2; 32], Decimal::default()).await??;
    let canceled = api::leave_validation(&mut runtime, &signer).await??;
    assert_eq!(canceled.status, ValidatorStatus::Inactive);
    assert_eq!(canceled.stake, bond.stake);
    assert_eq!(escrow(&mut runtime).await?, bond.stake);
    assert!(filestorage::has_storage_obligations(&mut runtime, node).await?);
    Ok(())
}

#[tokio::test]
async fn storage_bonds_do_not_reserve_consensus_capacity() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let signer = funded_signer(&mut runtime).await?;
    api::set_genesis_set(
        &mut runtime,
        &core(),
        vec![validator("10000".into(), 1, Decimal::try_from(LIMIT)?)],
    )
    .await?;
    api::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
    assert_capacity_error(
        api::register_validator(&mut runtime, &signer, vec![2; 32], Decimal::default()).await?,
    );
    assert!(api::get_validator(&mut runtime, &signer).await?.is_none());
    assert_eq!(
        api::get_stake(&mut runtime, &signer).await?.unwrap().stake,
        Decimal::from("1")
    );
    Ok(())
}

#[tokio::test]
async fn genesis_rejects_unsafe_stake_without_minting() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let supply = token::total_supply(&mut runtime).await?;
    for stakes in [
        vec![Decimal::try_from(LIMIT)?, Decimal::from("1")],
        vec![Decimal::from("18446744073709551616")],
        vec![Decimal::from("-1")],
        vec![Decimal::from("0")],
        vec![Decimal::from("0.999999999999999999")],
    ] {
        let validators = stakes
            .into_iter()
            .enumerate()
            .map(|(i, stake)| validator((100 + i).to_string(), i as u8 + 1, stake))
            .collect();
        assert!(
            api::set_genesis_set(&mut runtime, &core(), validators)
                .await
                .is_err()
        );
        assert_eq!(token::total_supply(&mut runtime).await?, supply);
        assert!(api::get_active_set(&mut runtime).await?.is_empty());
        assert_eq!(
            api::get_staking_info(&mut runtime).await?.total_stake,
            Decimal::from("0")
        );
    }
    let validators = vec![
        validator("100".to_string(), 1, Decimal::try_from(LIMIT - 1)?),
        validator("101".to_string(), 2, Decimal::from("1")),
    ];
    api::set_genesis_set(&mut runtime, &core(), validators).await?;
    assert_eq!(
        api::get_staking_info(&mut runtime).await?.total_stake,
        Decimal::try_from(LIMIT)?
    );
    assert_eq!(
        token::total_supply(&mut runtime).await?,
        add_decimal(supply, Decimal::try_from(LIMIT)?)?
    );
    Ok(())
}

#[tokio::test]
async fn genesis_is_not_reissued_after_the_last_validator_exits() -> Result<()> {
    let pubkey = random_x_only_pubkey();
    let validators = [GenesisValidator {
        x_only_pubkey: pubkey,
        ed25519_pubkey: PrivateKey::from([1; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }];
    let (mut runtime, _dir, _name) = test_runtime_with_genesis(&validators).await?;
    runtime.set_context(1, None, None, None).await;
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&validators[0].x_only_pubkey)
            .await?,
    );
    token::issue_to(
        &mut runtime,
        &core(),
        HolderRef::from(&signer),
        Decimal::from("1000"),
    )
    .await??;
    api::leave_validation(&mut runtime, &signer).await??;
    advance(&mut runtime, 13).await?;
    assert!(api::get_active_set(&mut runtime).await?.is_empty());
    let supply = token::total_supply(&mut runtime).await?;
    let balance = token::balance(&mut runtime, HolderRef::from(&signer)).await?;
    let genesis_checkpoint = get_checkpoint_by_height(&runtime.get_storage_conn(), 0)
        .await?
        .unwrap();
    // Startup republishes native contracts at height zero, even on an existing database.
    runtime.publish_native_contracts(&validators).await?;
    assert_eq!(
        get_checkpoint_by_height(&runtime.get_storage_conn(), 0).await?,
        Some(genesis_checkpoint)
    );
    assert!(api::get_active_set(&mut runtime).await?.is_empty());
    assert_eq!(
        api::get_staking_info(&mut runtime).await?.total_stake,
        Decimal::default()
    );
    assert_eq!(token::total_supply(&mut runtime).await?, supply);
    assert_eq!(
        token::balance(&mut runtime, HolderRef::from(&signer)).await?,
        balance
    );
    Ok(())
}

#[tokio::test]
async fn pending_joins_and_exits_reserve_aggregate_capacity() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let alice = funded_signer(&mut runtime).await?;
    let bob = funded_signer(&mut runtime).await?;
    let carol = funded_signer(&mut runtime).await?;
    api::set_genesis_set(
        &mut runtime,
        &core(),
        vec![
            validator("10000".to_string(), 1, Decimal::try_from(LIMIT - 11)?),
            validator(alice.to_string(), 2, Decimal::from("1")),
        ],
    )
    .await?;
    api::register_validator(&mut runtime, &bob, vec![3; 32], Decimal::from("6")).await??;
    assert_capacity_error(
        api::register_validator(&mut runtime, &carol, vec![4; 32], Decimal::from("5")).await?,
    );
    assert!(api::get_validator(&mut runtime, &carol).await?.is_none());
    api::register_validator(&mut runtime, &carol, vec![4; 32], Decimal::from("4")).await??;
    for signer in [&alice, &bob] {
        assert_capacity_error(api::add_stake(&mut runtime, signer, Decimal::from("0.1")).await?);
    }
    assert_eq!(
        api::get_validator(&mut runtime, &alice)
            .await?
            .unwrap()
            .stake,
        Decimal::from("1")
    );
    assert_eq!(
        api::get_validator(&mut runtime, &bob).await?.unwrap().stake,
        Decimal::from("6")
    );
    api::leave_validation(&mut runtime, &carol).await??;
    api::add_stake(&mut runtime, &alice, Decimal::from("2")).await??;
    api::add_stake(&mut runtime, &bob, Decimal::from("2")).await??;
    advance(&mut runtime, 13).await?;
    assert_eq!(
        api::get_staking_info(&mut runtime).await?.total_stake,
        Decimal::try_from(LIMIT)?
    );
    assert_eq!(
        api::get_validator(&mut runtime, &bob)
            .await?
            .unwrap()
            .status,
        ValidatorStatus::Active
    );
    api::leave_validation(&mut runtime, &bob).await??;
    assert_capacity_error(api::add_stake(&mut runtime, &alice, Decimal::from("1")).await?);
    advance(&mut runtime, 25).await?;
    api::add_stake(&mut runtime, &alice, Decimal::from("1")).await??;
    assert_eq!(
        api::get_staking_info(&mut runtime).await?.total_stake,
        sub_decimal(Decimal::try_from(LIMIT)?, Decimal::from("7"))?
    );
    Ok(())
}
