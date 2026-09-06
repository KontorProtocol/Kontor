use crate::reg_tester::random_x_only_pubkey;
use anyhow::Result;
use indexer_types::BlockRow;

use super::address;
use super::api::{self, ActiveValidatorInfo};
use crate::database::queries::{
    get_contract_id_from_address, get_contract_signer_id, insert_block,
};
use crate::runtime::numerics::{add_decimal, div_decimal, mul_decimal, sub_decimal};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Runtime};
use crate::test_utils::{new_mock_block_hash, test_runtime};

fn core() -> Signer {
    Signer::Core(Box::new(Signer::Nobody))
}

async fn seed(runtime: &mut Runtime, stakes: &[&str]) -> Result<()> {
    let validators = stakes
        .iter()
        .enumerate()
        .map(|(i, stake)| ActiveValidatorInfo {
            x_only_pubkey: (100 + i).to_string(),
            ed25519_pubkey: vec![i as u8 + 1; 32],
            stake: Decimal::from(*stake),
        })
        .collect();
    api::set_genesis_set(runtime, &core(), validators).await?;
    Ok(())
}

async fn balance(runtime: &mut Runtime, holder: HolderRef) -> Result<Decimal> {
    Ok(token::balance(runtime, holder).await?.unwrap_or_default())
}

async fn escrow(runtime: &mut Runtime) -> Result<Decimal> {
    let conn = runtime.get_storage_conn();
    let id = get_contract_id_from_address(&conn, &address())
        .await?
        .unwrap();
    let signer_id = get_contract_signer_id(&conn, id).await?.unwrap();
    balance(runtime, HolderRef::SignerId(signer_id)).await
}

async fn settle(runtime: &mut Runtime) -> Result<Decimal> {
    let eligible = api::has_reward_recipients(runtime).await?;
    let emission = token::mint_emission(runtime, &core(), eligible).await??;
    Ok(api::distribute_ordering_reward(runtime, &core(), emission.ordering_minted).await??)
}

#[tokio::test]
async fn ordering_rewards_conserve_supply_and_replay_atomically() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    seed(&mut runtime, &["6000000000", "4000000000"]).await?;
    let supply = token::total_supply(&mut runtime).await?;
    let before = escrow(&mut runtime).await?;
    let core_before = balance(&mut runtime, HolderRef::Core).await?;
    let expected = div_decimal(
        div_decimal(
            div_decimal(
                mul_decimal(supply, Decimal::from("5"))?,
                Decimal::from("100"),
            )?,
            Decimal::from("52560"),
        )?,
        Decimal::from("10"),
    )?;
    runtime.storage.savepoint().await?;
    let paid = settle(&mut runtime).await?;
    assert_eq!(paid, expected);
    let stakes = api::get_active_set(&mut runtime).await?;
    assert_eq!(
        stakes[0].stake,
        add_decimal(
            Decimal::from("6000000000"),
            div_decimal(mul_decimal(paid, Decimal::from("6"))?, Decimal::from("10"))?
        )?
    );
    assert_eq!(
        api::get_staking_info(&mut runtime).await?.total_stake,
        add_decimal(before, paid)?
    );
    assert_eq!(escrow(&mut runtime).await?, add_decimal(before, paid)?);
    assert_eq!(
        token::total_supply(&mut runtime).await?,
        add_decimal(supply, paid)?
    );
    assert_eq!(
        balance(&mut runtime, HolderRef::OrderingPool).await?,
        Decimal::default()
    );
    assert_eq!(
        balance(&mut runtime, HolderRef::StoragePool).await?,
        Decimal::default()
    );
    assert_eq!(balance(&mut runtime, HolderRef::Core).await?, core_before);
    assert!(
        token::mint_emission(&mut runtime, &core(), true)
            .await?
            .is_err()
    );
    assert!(
        api::distribute_ordering_reward(&mut runtime, &core(), paid)
            .await?
            .is_err()
    );
    runtime.storage.rollback().await?;
    assert_eq!(token::total_supply(&mut runtime).await?, supply);
    assert_eq!(escrow(&mut runtime).await?, before);
    assert_eq!(token::last_emission_height(&mut runtime).await?, None);
    assert_eq!(api::last_reward_height(&mut runtime).await?, None);
    assert_eq!(settle(&mut runtime).await?, paid);
    assert_eq!(api::get_active_set(&mut runtime).await?, stakes);
    Ok(())
}

#[tokio::test]
async fn ordering_reward_failures_do_not_leave_credits() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    seed(&mut runtime, &["2", "1", "1"]).await?;
    let before = api::get_active_set(&mut runtime).await?;
    assert!(
        api::distribute_ordering_reward(&mut runtime, &core(), Decimal::from("1"))
            .await?
            .is_err()
    );
    assert_eq!(api::get_active_set(&mut runtime).await?, before);
    assert_eq!(api::last_reward_height(&mut runtime).await?, None);
    token::issue_to(
        &mut runtime,
        &core(),
        HolderRef::OrderingPool,
        Decimal::from("0.000000000000000001"),
    )
    .await??;
    let paid = api::distribute_ordering_reward(
        &mut runtime,
        &core(),
        Decimal::from("0.000000000000000001"),
    )
    .await??;
    let after = api::get_active_set(&mut runtime).await?;
    let mut credited = Decimal::default();
    for (a, b) in after.iter().zip(&before) {
        assert!(a.stake >= b.stake);
        credited = add_decimal(credited, sub_decimal(a.stake, b.stake)?)?;
    }
    assert_eq!(credited, paid);
    assert_eq!(
        escrow(&mut runtime).await?,
        add_decimal(Decimal::from("4"), paid)?
    );
    Ok(())
}

#[tokio::test]
async fn empty_rewards_and_pool_authority() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let supply = token::total_supply(&mut runtime).await?;
    assert_eq!(settle(&mut runtime).await?, Decimal::default());
    assert_eq!(token::last_emission_height(&mut runtime).await?, Some(1));
    assert_eq!(api::last_reward_height(&mut runtime).await?, Some(1));
    assert_eq!(token::total_supply(&mut runtime).await?, supply);
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    token::issue_to(
        &mut runtime,
        &core(),
        HolderRef::from(&signer),
        Decimal::from("1000"),
    )
    .await??;
    assert!(
        token::mint_emission(&mut runtime, &signer, true)
            .await
            .is_err()
    );
    assert!(
        api::distribute_ordering_reward(&mut runtime, &signer, Decimal::from("1"))
            .await
            .is_err()
    );
    assert!(
        token::transfer_ordering_reward(
            &mut runtime,
            &signer,
            HolderRef::from(&signer),
            Decimal::from("1")
        )
        .await
        .is_err()
    );
    for pool in [HolderRef::OrderingPool, HolderRef::StoragePool] {
        token::issue_to(&mut runtime, &core(), pool, Decimal::from("2")).await??;
    }
    let payer = Signer::Core(Box::new(signer));
    token::hold(&mut runtime, &payer, Decimal::from("10")).await??;
    token::release(&mut runtime, &payer, Decimal::from("1")).await??;
    assert_eq!(
        balance(&mut runtime, HolderRef::OrderingPool).await?,
        Decimal::from("2")
    );
    assert_eq!(
        balance(&mut runtime, HolderRef::StoragePool).await?,
        Decimal::from("2")
    );
    for pool in [HolderRef::OrderingPool, HolderRef::StoragePool] {
        assert_eq!(pool.to_string().parse::<HolderRef>().unwrap(), pool);
        assert_eq!(token::floor(&mut runtime, pool).await?, Decimal::default());
    }
    Ok(())
}

#[tokio::test]
async fn rewards_respect_pending_exit_eligibility_and_capacity() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    api::set_genesis_set(
        &mut runtime,
        &core(),
        vec![ActiveValidatorInfo {
            x_only_pubkey: signer.to_string(),
            stake: Decimal::from("10"),
            ed25519_pubkey: vec![1; 32],
        }],
    )
    .await?;
    token::issue_to(
        &mut runtime,
        &core(),
        HolderRef::from(&signer),
        Decimal::from("1000"),
    )
    .await??;
    api::begin_unstake(&mut runtime, &signer).await??;
    assert!(!api::has_reward_recipients(&mut runtime).await?);
    assert_eq!(api::get_active_set(&mut runtime).await?.len(), 1);
    assert_eq!(settle(&mut runtime).await?, Decimal::default());
    let (mut runtime, _dir2, _name2) = test_runtime().await?;
    seed(&mut runtime, &["6148914691236517205"]).await?;
    runtime.storage.savepoint().await?;
    let supply = token::total_supply(&mut runtime).await?;
    assert!(settle(&mut runtime).await.is_err());
    runtime.storage.rollback().await?;
    assert_eq!(token::total_supply(&mut runtime).await?, supply);
    assert_eq!(token::last_emission_height(&mut runtime).await?, None);
    assert_eq!(escrow(&mut runtime).await?, supply);
    Ok(())
}

#[tokio::test]
async fn joins_earn_after_activation_and_exits_stop_immediately() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let alice = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    let bob = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    let carol = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    api::set_genesis_set(
        &mut runtime,
        &core(),
        vec![
            ActiveValidatorInfo {
                x_only_pubkey: alice.to_string(),
                stake: Decimal::from("60"),
                ed25519_pubkey: vec![1; 32],
            },
            ActiveValidatorInfo {
                x_only_pubkey: bob.to_string(),
                stake: Decimal::from("40"),
                ed25519_pubkey: vec![2; 32],
            },
        ],
    )
    .await?;
    token::issue_to(
        &mut runtime,
        &core(),
        HolderRef::from(&carol),
        Decimal::from("1000"),
    )
    .await??;
    api::register_validator(&mut runtime, &carol, vec![3; 32], Decimal::from("10")).await??;
    token::issue_to(
        &mut runtime,
        &core(),
        HolderRef::from(&bob),
        Decimal::from("1000"),
    )
    .await??;
    api::begin_unstake(&mut runtime, &bob).await??;
    token::issue_to(
        &mut runtime,
        &core(),
        HolderRef::OrderingPool,
        Decimal::from("29"),
    )
    .await??;
    api::distribute_ordering_reward(&mut runtime, &core(), Decimal::from("10")).await??;
    assert_eq!(
        api::get_validator(&mut runtime, &alice)
            .await?
            .unwrap()
            .stake,
        Decimal::from("70")
    );
    assert_eq!(
        api::get_validator(&mut runtime, &bob).await?.unwrap().stake,
        Decimal::from("40")
    );
    assert_eq!(
        api::get_validator(&mut runtime, &carol)
            .await?
            .unwrap()
            .stake,
        Decimal::from("10")
    );
    for height in [13, 14] {
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
        let amount = if height == 13 { "10" } else { "9" };
        api::distribute_ordering_reward(&mut runtime, &core(), Decimal::from(amount)).await??;
        api::process_pending_validators(&mut runtime, &core(), height).await??;
    }
    assert_eq!(
        api::get_validator(&mut runtime, &alice)
            .await?
            .unwrap()
            .stake,
        Decimal::from("88")
    );
    assert_eq!(
        api::get_validator(&mut runtime, &carol)
            .await?
            .unwrap()
            .stake,
        Decimal::from("11")
    );
    assert_eq!(
        api::get_staking_info(&mut runtime).await?.total_stake,
        Decimal::from("99")
    );
    Ok(())
}
