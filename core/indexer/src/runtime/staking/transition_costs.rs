use std::{collections::BTreeMap, ops::AsyncFnOnce, time::Instant};

use anyhow::Result;
use indexer_types::BlockRow;
use serde_json::json;

use super::api;
use crate::database::queries::insert_block;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::costs::snapshot;
use crate::runtime::fuel::FuelGauge;
use crate::runtime::numerics::{add_decimal, sub_decimal};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Runtime};
use crate::test_utils::{new_mock_block_hash, test_runtime};

async fn at_height(runtime: &mut Runtime, height: u64) -> Result<()> {
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
    Ok(())
}

async fn measured<T>(
    runtime: &mut Runtime,
    operation: &str,
    population: usize,
    call: impl AsyncFnOnce(&mut Runtime) -> Result<T>,
) -> Result<T> {
    let gauge = FuelGauge::new();
    runtime.gauge = Some(gauge.clone());
    let started = Instant::now();
    let result = call(runtime).await?;
    let elapsed = started.elapsed();
    runtime.gauge = None;
    let operations: BTreeMap<_, _> = gauge
        .per_type_stats()
        .await
        .into_iter()
        .map(|(kind, stats)| (format!("{kind:?}"), stats.count))
        .collect();
    println!(
        "TRANSITION_COST {}",
        json!({
            "operation": operation,
            "population": population,
            "elapsed_us": elapsed.as_micros(),
            "host_fuel": gauge.total_host_fuel().await,
            "host_operations": operations,
        })
    );
    Ok(result)
}

#[tokio::test]
#[ignore = "manual validator transition scan and index maintenance measurements"]
async fn validator_transition_costs() -> Result<()> {
    let core = Signer::Core(Box::new(Signer::Nobody));
    for population in [0, 4, 32, 128] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        runtime.set_context(1, None, None, None).await;
        let mut signers = Vec::new();
        for _ in 0..population {
            let signer = Signer::Id(
                runtime
                    .get_or_create_identity(&random_x_only_pubkey())
                    .await?,
            );
            token::issue_to(
                &mut runtime,
                &core,
                HolderRef::from(&signer),
                Decimal::from("1000"),
            )
            .await??;
            signers.push(signer);
        }
        measured(&mut runtime, "register", population, async |rt| {
            for (i, signer) in signers.iter().enumerate() {
                api::register_validator(rt, signer, vec![i as u8 + 1; 32], Decimal::from("100"))
                    .await??;
            }
            Ok(())
        })
        .await?;
        for height in 2..=12 {
            at_height(&mut runtime, height).await?;
            measured(&mut runtime, "join_wait", population, async |rt| {
                let change = api::process_pending_validators(rt, &core, height).await??;
                assert_eq!((change.activated, change.deactivated), (0, 0));
                Ok(())
            })
            .await?;
        }
        snapshot(&runtime, "pending_join", population).await?;
        at_height(&mut runtime, 13).await?;
        measured(&mut runtime, "activate", population, async |rt| {
            let change = api::process_pending_validators(rt, &core, 13).await??;
            assert_eq!(change.activated as usize, population);
            Ok(())
        })
        .await?;
        snapshot(&runtime, "active", population).await?;
        let emission = token::mint_emission(&mut runtime, &core, population > 0).await??;
        measured(&mut runtime, "reward", population, async |rt| {
            Ok(api::distribute_ordering_reward(rt, &core, emission.ordering_minted).await??)
        })
        .await?;
        measured(&mut runtime, "request_exit", population, async |rt| {
            for signer in &signers {
                api::leave_validation(rt, signer).await??;
            }
            Ok(())
        })
        .await?;
        for height in 14..=24 {
            at_height(&mut runtime, height).await?;
            measured(&mut runtime, "exit_wait", population, async |rt| {
                let change = api::process_pending_validators(rt, &core, height).await??;
                assert_eq!((change.activated, change.deactivated), (0, 0));
                Ok(())
            })
            .await?;
        }
        snapshot(&runtime, "pending_exit", population).await?;
        at_height(&mut runtime, 25).await?;
        measured(&mut runtime, "deactivate", population, async |rt| {
            let change = api::process_pending_validators(rt, &core, 25).await??;
            assert_eq!(change.deactivated as usize, population);
            Ok(())
        })
        .await?;
        snapshot(&runtime, "inactive", population).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "manual storage-only bond index costs"]
async fn storage_only_index_costs() -> Result<()> {
    let core = Signer::Core(Box::new(Signer::Nobody));
    for population in [4, 32, 128] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        runtime.set_context(1, None, None, None).await;
        let mut signers = Vec::new();
        for _ in 0..population {
            let signer = Signer::Id(
                runtime
                    .get_or_create_identity(&random_x_only_pubkey())
                    .await?,
            );
            token::issue_to(
                &mut runtime,
                &core,
                HolderRef::from(&signer),
                Decimal::from("1000"),
            )
            .await??;
            signers.push(signer);
        }
        measured(&mut runtime, "storage_bond", population, async |rt| {
            for signer in &signers {
                api::add_stake(rt, signer, Decimal::from("100")).await??;
            }
            Ok(())
        })
        .await?;
        snapshot(&runtime, "storage_bond", population).await?;
        at_height(&mut runtime, 2).await?;
        measured(&mut runtime, "storage_topup", population, async |rt| {
            for signer in &signers {
                api::add_stake(rt, signer, Decimal::from("1")).await??;
            }
            Ok(())
        })
        .await?;
        snapshot(&runtime, "storage_topup", population).await?;
    }
    Ok(())
}

async fn user_balances(runtime: &mut Runtime, signers: &[Signer]) -> Result<(Decimal, Decimal)> {
    let mut balance = Decimal::default();
    let mut collateral = Decimal::default();
    for signer in signers {
        balance = add_decimal(
            balance,
            token::balance(runtime, HolderRef::from(signer))
                .await?
                .unwrap(),
        )?;
        collateral = add_decimal(
            collateral,
            token::floor(runtime, HolderRef::from(signer)).await?,
        )?;
    }
    Ok((balance, collateral))
}

#[tokio::test]
#[ignore = "manual user collateral and actual burned-fee comparison"]
async fn storage_user_costs() -> Result<()> {
    let core = Signer::Core(Box::new(Signer::Nobody));
    for population in [1, 128] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        runtime.set_context(1, None, None, None).await;
        let mut signers = Vec::new();
        for _ in 0..population {
            let signer = Signer::Id(
                runtime
                    .get_or_create_identity(&random_x_only_pubkey())
                    .await?,
            );
            token::issue_to(
                &mut runtime,
                &core,
                HolderRef::from(&signer),
                Decimal::from("1000"),
            )
            .await??;
            signers.push(signer);
        }
        for (operation, amount, height) in [("bond", 100, 1), ("topup", 1, 2)] {
            if height > 1 {
                at_height(&mut runtime, height).await?;
            }
            let (before, floor_before) = user_balances(&mut runtime, &signers).await?;
            let burned_before = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            for signer in &signers {
                api::add_stake(
                    &mut runtime,
                    signer,
                    Decimal::from(amount.to_string().as_str()),
                )
                .await??;
            }
            let (after, floor_after) = user_balances(&mut runtime, &signers).await?;
            let burned_after = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            let principal = Decimal::from((population * amount).to_string().as_str());
            let fees = sub_decimal(sub_decimal(before, after)?, principal)?;
            assert_eq!(fees, sub_decimal(burned_after, burned_before)?);
            assert!(fees > Decimal::default());
            for signer in &signers {
                let stake = api::get_stake(&mut runtime, signer).await?.unwrap().stake;
                assert_eq!(
                    stake,
                    Decimal::from(if height == 1 { "100" } else { "101" })
                );
            }
            println!(
                "USER_COST {}",
                json!({
                    "operation": operation, "population": population,
                    "fee_tokens": fees.to_string(), "collateral_before": floor_before.to_string(),
                    "collateral_after": floor_after.to_string(),
                })
            );
        }
    }
    Ok(())
}
