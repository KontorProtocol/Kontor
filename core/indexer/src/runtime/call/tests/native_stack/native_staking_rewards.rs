use std::process;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, ensure};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use libsql::Connection;
use serde_json::{Value as JsonValue, json};

use super::sweep::persistent_digest;
use crate::database::queries::{get_contract_id_from_address, get_contract_signer_id};
use crate::runtime::invocation::{InvocationBudget, ResourceProbePhase, ResourceTeardownRecorder};
use crate::runtime::numerics::{add_decimal, div_decimal, mul_decimal, sub_decimal};
use crate::runtime::resource_diagnostics;
use crate::runtime::staking::address as staking_address;
use crate::runtime::staking::api::{self as staking_api, ActiveValidatorInfo};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Runtime};
use crate::test_utils::test_runtime_with_engine;

const CASE_ID: &str = "native_staking_rewards";
const POPULATIONS: [usize; 4] = [0, 4, 32, 128];
const INITIAL_STAKE: &str = "1000";

async fn receipt_count(conn: &Connection) -> Result<u64> {
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    Ok(rows.next().await?.unwrap().get(0)?)
}

async fn balance(runtime: &mut Runtime, holder: HolderRef) -> Result<Decimal> {
    Ok(token::balance(runtime, holder).await?.unwrap_or_default())
}

async fn staking_escrow(runtime: &mut Runtime) -> Result<Decimal> {
    let conn = runtime.get_storage_conn();
    let id = get_contract_id_from_address(&conn, &staking_address())
        .await?
        .unwrap();
    let signer_id = get_contract_signer_id(&conn, id).await?.unwrap();
    balance(runtime, HolderRef::SignerId(signer_id)).await
}

fn validators(population: usize) -> Result<Vec<ActiveValidatorInfo>> {
    let secp = Secp256k1::new();
    (0..population)
        .map(|index| {
            let mut scalar = [0_u8; 32];
            scalar[31] = (index + 1) as u8;
            let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&scalar)?);
            let (key, _) = XOnlyPublicKey::from_keypair(&keypair);
            Ok(ActiveValidatorInfo {
                x_only_pubkey: key.to_string(),
                ed25519_pubkey: vec![(index + 1) as u8; 32],
                stake: Decimal::from(INITIAL_STAKE),
            })
        })
        .collect()
}

fn expected_emission(supply: Decimal, eligible: bool) -> Result<Decimal> {
    if !eligible {
        return Ok(Decimal::default());
    }
    let total = div_decimal(
        div_decimal(
            mul_decimal(supply, Decimal::from("5"))?,
            Decimal::from("100"),
        )?,
        Decimal::from("52560"),
    )?;
    Ok(div_decimal(total, Decimal::from("10"))?)
}

fn expected_stakes(before: &[ActiveValidatorInfo], amount: Decimal) -> Result<Vec<Decimal>> {
    let mut credited = Decimal::default();
    let total = Decimal::from(INITIAL_STAKE);
    let total = mul_decimal(total, Decimal::try_from(before.len() as u64)?)?;
    let mut result = Vec::with_capacity(before.len());
    for (index, validator) in before.iter().enumerate() {
        let remaining = sub_decimal(amount, credited)?;
        let share = if index + 1 == before.len() {
            remaining
        } else {
            div_decimal(mul_decimal(amount, validator.stake)?, total)?.min(remaining)
        };
        result.push(add_decimal(validator.stake, share)?);
        credited = add_decimal(credited, share)?;
    }
    ensure!(
        credited == amount,
        "staking reward distribution lost its remainder"
    );
    Ok(result)
}

pub(super) async fn run(configuration: &str, process_role: &str) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown staking reward configuration or role"
    );
    let engine = if configuration == "reduced" {
        Runtime::new_resource_diagnostic_engine()?
    } else {
        Runtime::new_engine()?
    };
    let core = Signer::Core(Box::new(Signer::Nobody));
    let mut outcomes = Vec::with_capacity(POPULATIONS.len() * 2);
    for population in POPULATIONS {
        resource_diagnostics::record("fixture_preparation_entry");
        let (mut runtime, _dir, _name) = test_runtime_with_engine(engine.clone()).await?;
        runtime.set_context(1, None, None, None).await;
        let seeded = validators(population)?;
        staking_api::set_genesis_set(&mut runtime, &core, seeded.clone()).await?;
        let active_before = staking_api::get_active_set(&mut runtime).await?;
        ensure!(
            active_before.len() == population
                && active_before
                    .iter()
                    .all(|validator| validator.stake == Decimal::from(INITIAL_STAKE)),
            "staking reward genesis set changed"
        );
        let mut expected_order = seeded.clone();
        expected_order.sort_by(|a, b| a.x_only_pubkey.cmp(&b.x_only_pubkey));
        ensure!(
            active_before
                .iter()
                .zip(&expected_order)
                .all(|(a, b)| a.x_only_pubkey == b.x_only_pubkey
                    && a.ed25519_pubkey == b.ed25519_pubkey
                    && a.stake == b.stake),
            "staking reward active holders changed order or metadata"
        );
        let eligible = staking_api::has_reward_recipients(&mut runtime).await?;
        ensure!(eligible == (population > 0), "reward eligibility changed");
        let supply_pre_mint = token::total_supply(&mut runtime).await?;
        let minted = token::mint_emission(&mut runtime, &core, eligible).await??;
        let expected_amount = expected_emission(supply_pre_mint, eligible)?;
        ensure!(
            minted.ordering_minted == expected_amount,
            "reward emission differs from the independently ordered supply calculation"
        );
        runtime.set_context(1, None, None, None).await;
        let conn = runtime.get_storage_conn();
        let baseline_digest = persistent_digest(&conn).await?;
        let baseline_receipts = receipt_count(&conn).await?;
        let supply_before = token::total_supply(&mut runtime).await?;
        let escrow_before = staking_escrow(&mut runtime).await?;
        let pool_before = balance(&mut runtime, HolderRef::OrderingPool).await?;
        let total_stake_before = staking_api::get_staking_info(&mut runtime)
            .await?
            .total_stake;
        ensure!(
            pool_before == expected_amount
                && staking_api::last_reward_height(&mut runtime)
                    .await?
                    .is_none(),
            "staking reward prestate changed"
        );
        resource_diagnostics::record("fixture_preparation_exit");
        let sample = format!("population_{population}");
        for repeat_index in 0..2 {
            ensure!(persistent_digest(&conn).await? == baseline_digest);
            runtime.storage.savepoint().await?;
            let outer_savepoint = runtime.storage.savepoint_stack.peek().await;
            let recorder = (process_role == "target_observed")
                .then(|| Arc::new(ResourceTeardownRecorder::default()));
            let budget = Arc::new(match recorder.as_ref() {
                Some(recorder) => InvocationBudget::with_teardown_recorder(recorder.clone()),
                None => InvocationBudget::default(),
            });
            runtime.invocation_budget = Some(budget.clone());
            runtime.resource_probe_phase =
                Some(ResourceProbePhase::Target(Arc::new(
                    vec![staking_address()],
                )));
            let resources_before = runtime.table.lock().await.iter_mut().count();
            let receipts_before = receipt_count(&conn).await?;
            resource_diagnostics::record("finite_stack_attempt_start");
            let started = Instant::now();
            let previous = runtime.start_usage();
            let paid =
                staking_api::distribute_ordering_reward(&mut runtime, &core, expected_amount)
                    .await??;
            let usage = runtime.finish_usage(previous)?;
            let teardown_events = recorder.as_ref().map(|recorder| recorder.events());
            let live_invocations = budget.live();
            runtime.invocation_budget = None;
            runtime.resource_probe_phase = None;
            let resources_after = runtime.table.lock().await.iter_mut().count();
            let stack_empty = runtime.stack.is_empty().await;
            let savepoint_restored =
                runtime.storage.savepoint_stack.peek().await == outer_savepoint;
            let active_after = staking_api::get_active_set(&mut runtime).await?;
            let expected_after = expected_stakes(&active_before, expected_amount)?;
            let mut credited = Decimal::default();
            let mut accounts = Vec::with_capacity(population);
            for ((before, after), expected) in
                active_before.iter().zip(&active_after).zip(&expected_after)
            {
                ensure!(
                    before.x_only_pubkey == after.x_only_pubkey
                        && before.ed25519_pubkey == after.ed25519_pubkey
                        && after.stake == *expected,
                    "staking reward changed account metadata or rounded share"
                );
                credited = add_decimal(credited, sub_decimal(after.stake, before.stake)?)?;
                accounts.push(json!({
                    "holder": after.x_only_pubkey,
                    "ed25519_pubkey": hex::encode(&after.ed25519_pubkey),
                    "stake_before": before.stake.to_string(),
                    "stake_after": after.stake.to_string(),
                }));
            }
            let supply_after = token::total_supply(&mut runtime).await?;
            let escrow_after = staking_escrow(&mut runtime).await?;
            let pool_after = balance(&mut runtime, HolderRef::OrderingPool).await?;
            let total_stake_after = staking_api::get_staking_info(&mut runtime)
                .await?
                .total_stake;
            let last_reward_height = staking_api::last_reward_height(&mut runtime).await?;
            let receipts_after = receipt_count(&conn).await?;
            let state_after_sha256 = persistent_digest(&conn).await?;
            ensure!(
                paid == expected_amount
                    && credited == expected_amount
                    && supply_after == supply_before
                    && sub_decimal(escrow_after, escrow_before)? == expected_amount
                    && sub_decimal(pool_before, pool_after)? == expected_amount
                    && sub_decimal(total_stake_after, total_stake_before)? == expected_amount
                    && last_reward_height == Some(1)
                    && receipts_after == receipts_before + if population == 0 { 1 } else { 2 }
                    && usage.user_fuel == 0
                    && usage.deposit_fuel == 0
                    && usage.system_fuel > 0
                    && resources_after == resources_before
                    && stack_empty
                    && savepoint_restored
                    && live_invocations == 0,
                "staking reward settlement or Store cleanup changed"
            );
            runtime.storage.rollback().await?;
            runtime.set_context(1, None, None, None).await;
            let state_restored_sha256 = persistent_digest(&conn).await?;
            let receipts_restored = receipt_count(&conn).await?;
            ensure!(
                state_restored_sha256 == baseline_digest
                    && receipts_restored == baseline_receipts
                    && runtime.storage.savepoint_stack.is_empty().await,
                "staking reward repeat did not restore full baseline state"
            );
            let observation = json!({
                "sample_key": sample,
                "outcome": "ok",
                "population": population,
                "eligible": eligible,
                "amount": expected_amount.to_string(),
                "paid": paid.to_string(),
                "credited": credited.to_string(),
                "accounts": accounts,
                "supply_pre_mint": supply_pre_mint.to_string(),
                "supply_before": supply_before.to_string(),
                "supply_after": supply_after.to_string(),
                "escrow_before": escrow_before.to_string(),
                "escrow_after": escrow_after.to_string(),
                "pool_before": pool_before.to_string(),
                "pool_after": pool_after.to_string(),
                "total_stake_before": total_stake_before.to_string(),
                "total_stake_after": total_stake_after.to_string(),
                "last_reward_height": last_reward_height,
                "system_fuel": usage.system_fuel,
                "user_fuel": usage.user_fuel,
                "deposit_fuel": usage.deposit_fuel,
                "state_before_sha256": baseline_digest,
                "state_after_sha256": state_after_sha256,
                "state_restored_sha256": state_restored_sha256,
                "receipts_before": receipts_before,
                "receipts_after": receipts_after,
                "receipts_restored": receipts_restored,
                "resources_before": resources_before,
                "resources_after": resources_after,
                "stack_empty": stack_empty,
                "savepoint_restored": savepoint_restored,
                "savepoint_empty": true,
                "live_invocations": live_invocations,
                "teardown_probe_on": recorder.is_some(),
                "teardown_events": teardown_events,
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": runtime.engine.get_max_wasm_stack(),
                "async_stack_size": runtime.engine.get_async_stack_size(),
            });
            println!(
                "FINITE_STACK_ATTEMPT:{}",
                json!({
                    "case_id": CASE_ID,
                    "configuration": configuration,
                    "process_role": process_role,
                    "sample_key": sample,
                    "repeat_index": repeat_index,
                    "pid": process::id(),
                    "observation": observation,
                })
            );
            println!(
                "KONTOR_STACK_TIMING:{}",
                json!({
                    "case_id": CASE_ID,
                    "sample_key": sample,
                    "repeat_index": repeat_index,
                    "elapsed_ms": started.elapsed().as_millis(),
                })
            );
            resource_diagnostics::record("finite_stack_attempt_end");
            outcomes.push("ok");
        }
    }
    let summary = json!({
        "case_id": CASE_ID,
        "configuration": configuration,
        "process_role": process_role,
        "sample_count": outcomes.len(),
        "outcomes": outcomes,
        "complete": true,
    });
    println!("FINITE_STACK_SUMMARY:{summary}");
    Ok(summary)
}
