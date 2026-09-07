use anyhow::Result;
use indexer_types::BlockRow;

use super::api::{self, ActiveValidatorInfo, ValidatorInfo, ValidatorStatus};
use crate::consensus::signing::PrivateKey;
use crate::database::queries::{get_checkpoint_by_height, insert_block};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::numerics::{add_decimal, sub_decimal};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Error, GenesisValidator, Runtime};
use crate::test_utils::{new_mock_block_hash, test_runtime, test_runtime_with_genesis};

const LIMIT: u64 = u64::MAX / 3;

fn assert_capacity_error(result: Result<ValidatorInfo, Error>) {
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
async fn genesis_rejects_unsafe_stake_without_minting() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let supply = token::total_supply(&mut runtime).await?;
    for stakes in [
        vec![Decimal::try_from(LIMIT)?, Decimal::from("1")],
        vec![Decimal::from("18446744073709551616")],
        vec![Decimal::from("-1")],
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
    api::begin_unstake(&mut runtime, &signer).await??;
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
    api::begin_unstake(&mut runtime, &carol).await??;
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
    api::begin_unstake(&mut runtime, &bob).await??;
    assert_capacity_error(api::add_stake(&mut runtime, &alice, Decimal::from("1")).await?);
    advance(&mut runtime, 25).await?;
    api::add_stake(&mut runtime, &alice, Decimal::from("1")).await??;
    assert_eq!(
        api::get_staking_info(&mut runtime).await?.total_stake,
        sub_decimal(Decimal::try_from(LIMIT)?, Decimal::from("7"))?
    );
    Ok(())
}
