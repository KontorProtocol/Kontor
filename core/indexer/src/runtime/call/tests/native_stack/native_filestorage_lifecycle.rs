use std::process;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, ensure};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use libsql::{Connection, params};
use serde_json::{Value as JsonValue, json};

use super::sweep::persistent_digest;
use crate::runtime::filestorage::address as filestorage_address;
use crate::runtime::filestorage::api as storage_api;
use crate::runtime::filestorage::settlement_tests::{StorageFixture, at_height};
use crate::runtime::invocation::{InvocationBudget, ResourceProbePhase, ResourceTeardownRecorder};
use crate::runtime::numerics::{add_decimal, mul_decimal, sub_decimal};
use crate::runtime::resource_diagnostics;
use crate::runtime::staking::api as staking_api;
use crate::runtime::token::api as token_api;
use crate::runtime::wit::Signer;
use crate::runtime::{Decimal, Runtime};
use crate::test_utils::test_runtime_with_engine;

const CASE_ID: &str = "native_filestorage_lifecycle";
const SAMPLES: [&str; 3] = ["expiry", "penalty", "cleanup"];
const DUE_HEIGHT: u64 = 2016;
const WORK_LIMIT: u64 = 32;

fn host_keys() -> Result<Vec<String>> {
    let secp = Secp256k1::new();
    (1..=3)
        .map(|index| {
            let mut scalar = [0_u8; 32];
            scalar[31] = index;
            let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&scalar)?);
            let (key, _) = XOnlyPublicKey::from_keypair(&keypair);
            Ok(key.to_string())
        })
        .collect()
}

async fn receipt_count(conn: &Connection) -> Result<u64> {
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    Ok(rows.next().await?.unwrap().get(0)?)
}

async fn latest_receipt_id(conn: &Connection) -> Result<u64> {
    let mut rows = conn
        .query("SELECT COALESCE(MAX(id), 0) FROM contract_results", ())
        .await?;
    Ok(rows.next().await?.unwrap().get(0)?)
}

async fn new_receipts(conn: &Connection, previous_id: u64) -> Result<Vec<JsonValue>> {
    let mut rows = conn
        .query(
            "SELECT c.name, r.func, r.status, r.gas, r.size, r.value, \
             r.signer_id, r.payer_signer_id, r.height, r.tx_id, \
             r.input_index, r.op_index, r.result_index \
             FROM contract_results r JOIN contracts c ON c.id = r.contract_id \
             WHERE r.id > ? ORDER BY r.id",
            params![previous_id],
        )
        .await?;
    let mut receipts = Vec::new();
    while let Some(row) = rows.next().await? {
        let contract: String = row.get(0)?;
        let function: String = row.get(1)?;
        let status: String = row.get(2)?;
        let gas: u64 = row.get(3)?;
        let size: u64 = row.get(4)?;
        let value: Option<String> = row.get(5)?;
        let signer_id: u64 = row.get(6)?;
        let payer_signer_id: Option<u64> = row.get(7)?;
        let height: u64 = row.get(8)?;
        let tx_id: Option<u64> = row.get(9)?;
        let input_index: Option<u64> = row.get(10)?;
        let op_index: Option<u64> = row.get(11)?;
        let result_index: u64 = row.get(12)?;
        ensure!(
            status == "Ok"
                && gas > 0
                && value
                    .as_ref()
                    .is_some_and(|value| !value.is_empty() && value.len() as u64 == size)
                && height == DUE_HEIGHT
                && tx_id.is_none()
                && input_index.is_none()
                && op_index.is_none()
                && result_index == receipts.len() as u64,
            "filestorage receipt content or order changed"
        );
        receipts.push(json!({
            "contract": contract, "function": function, "status": status,
            "gas": gas, "size": size, "value": value,
            "signer_id": signer_id, "payer_signer_id": payer_signer_id,
            "height": height, "tx_id": tx_id,
            "input_index": input_index, "op_index": op_index,
            "result_index": result_index,
        }));
    }
    ensure!(!receipts.is_empty(), "filestorage call produced no receipt");
    Ok(receipts)
}

async fn challenge_statuses(runtime: &mut Runtime, ids: &[String]) -> Result<Vec<String>> {
    let mut statuses = Vec::with_capacity(ids.len());
    for id in ids {
        let challenge = storage_api::get_challenge(runtime, id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("filestorage challenge disappeared"))?;
        statuses.push(format!("{:?}", challenge.status));
    }
    Ok(statuses)
}

async fn active_agreements(runtime: &mut Runtime, fixture: &StorageFixture) -> Result<Vec<String>> {
    let node_id = fixture.hosts[0].0;
    let mut active = Vec::new();
    for agreement in &fixture.agreements {
        if storage_api::is_node_in_agreement(runtime, agreement, node_id).await? {
            active.push(agreement.clone());
        }
    }
    Ok(active)
}

pub(super) async fn run(configuration: &str, process_role: &str) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown filestorage configuration or role"
    );
    let engine = if configuration == "reduced" {
        Runtime::new_resource_diagnostic_engine()?
    } else {
        Runtime::new_engine()?
    };
    let core = Signer::Core(Box::new(Signer::Nobody));
    let keys = host_keys()?;
    let mut outcomes = Vec::with_capacity(SAMPLES.len() * 2);
    for sample in SAMPLES {
        resource_diagnostics::record("fixture_preparation_entry");
        let (mut runtime, _dir, _name) = test_runtime_with_engine(engine.clone()).await?;
        let file_count = if sample == "cleanup" { 40 } else { 32 };
        let fixture = StorageFixture::new(&mut runtime, file_count, &keys).await?;
        let mut collateral = Decimal::default();
        for requirement in &fixture.requirements {
            collateral = add_decimal(collateral, *requirement)?;
        }
        let first_bond = if sample == "cleanup" {
            collateral
        } else {
            Decimal::from("9000")
        };
        fixture.join(&mut runtime, first_bond).await?;
        let challenge_count = if sample == "cleanup" { 3 } else { 32 };
        let mut challenge_ids = Vec::with_capacity(challenge_count);
        for file in 0..challenge_count {
            challenge_ids.push(fixture.challenge(&mut runtime, file, 0).await?);
        }
        at_height(&mut runtime, DUE_HEIGHT).await?;
        if sample == "penalty" || sample == "cleanup" {
            ensure!(
                storage_api::expire_challenges(&mut runtime, &core, DUE_HEIGHT).await?
                    == challenge_count as u64,
                "filestorage setup expiry count changed"
            );
        }
        if sample == "cleanup" {
            ensure!(
                storage_api::settle_expired_challenges(&mut runtime, &core).await??
                    == 3 + WORK_LIMIT,
                "filestorage cleanup setup budget changed"
            );
            ensure!(
                storage_api::is_bond_cleanup_pending(&mut runtime, fixture.hosts[0].0).await?
                    && active_agreements(&mut runtime, &fixture).await?.len() == 8,
                "filestorage bounded cleanup setup changed"
            );
        }
        runtime.set_context(DUE_HEIGHT, None, None, None).await;
        let conn = runtime.get_storage_conn();
        let baseline_digest = persistent_digest(&conn).await?;
        let baseline_receipts = receipt_count(&conn).await?;
        let node_id = fixture.hosts[0].0;
        let stake_before = staking_api::get_stake(&mut runtime, &node_id.to_string())
            .await?
            .ok_or_else(|| anyhow::anyhow!("filestorage first host stake missing"))?
            .stake;
        let supply_before = token_api::total_supply(&mut runtime).await?;
        let reservation_before = storage_api::get_node_reservation(&mut runtime, node_id).await?;
        let pending_before = storage_api::is_bond_cleanup_pending(&mut runtime, node_id).await?;
        let obligations_before =
            storage_api::has_storage_obligations(&mut runtime, node_id).await?;
        let active_agreements_before = active_agreements(&mut runtime, &fixture).await?;
        let memberships_before = active_agreements_before.len() as u64;
        let statuses_before = challenge_statuses(&mut runtime, &challenge_ids).await?;
        let penalty_total = if sample == "penalty" {
            let mut total = Decimal::default();
            for requirement in &fixture.requirements {
                total = add_decimal(total, mul_decimal(*requirement, Decimal::from("30"))?)?;
            }
            ensure!(
                stake_before > total,
                "filestorage penalty fixture would exhaust the bond"
            );
            total
        } else {
            Decimal::default()
        };
        ensure!(
            memberships_before
                == if sample == "cleanup" {
                    8
                } else {
                    file_count as u64
                }
                && pending_before == (sample == "cleanup")
                && statuses_before.iter().all(|status| {
                    status.as_str()
                        == if sample == "expiry" {
                            "Active"
                        } else if sample == "penalty" {
                            "Expired"
                        } else {
                            "Settled"
                        }
                }),
            "filestorage fixture prestate changed"
        );
        resource_diagnostics::record("fixture_preparation_exit");
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
            runtime.resource_probe_phase = Some(ResourceProbePhase::Target(Arc::new(vec![
                filestorage_address(),
            ])));
            let resources_before = runtime.table.lock().await.iter_mut().count();
            let receipts_before = receipt_count(&conn).await?;
            let receipt_before_id = latest_receipt_id(&conn).await?;
            resource_diagnostics::record("finite_stack_attempt_start");
            resource_diagnostics::record("operation_entry");
            let started = Instant::now();
            let previous = runtime.start_usage();
            let processed = if sample == "expiry" {
                storage_api::expire_challenges(&mut runtime, &core, DUE_HEIGHT).await?
            } else {
                storage_api::settle_expired_challenges(&mut runtime, &core).await??
            };
            let usage = runtime.finish_usage(previous)?;
            resource_diagnostics::record("operation_exit");
            let teardown_events = recorder.as_ref().map(|recorder| recorder.events());
            let live_invocations = budget.live();
            runtime.invocation_budget = None;
            runtime.resource_probe_phase = None;
            let resources_after = runtime.table.lock().await.iter_mut().count();
            let stack_empty = runtime.stack.is_empty().await;
            let savepoint_restored =
                runtime.storage.savepoint_stack.peek().await == outer_savepoint;
            resource_diagnostics::record("postcall_observation_entry");
            let stake_after = staking_api::get_stake(&mut runtime, &node_id.to_string())
                .await?
                .ok_or_else(|| anyhow::anyhow!("filestorage first host stake missing"))?
                .stake;
            let supply_after = token_api::total_supply(&mut runtime).await?;
            let reservation_after =
                storage_api::get_node_reservation(&mut runtime, node_id).await?;
            let pending_after = storage_api::is_bond_cleanup_pending(&mut runtime, node_id).await?;
            let obligations_after =
                storage_api::has_storage_obligations(&mut runtime, node_id).await?;
            let active_agreements_after = active_agreements(&mut runtime, &fixture).await?;
            let memberships_after = active_agreements_after.len() as u64;
            let statuses_after = challenge_statuses(&mut runtime, &challenge_ids).await?;
            let receipts_after = receipt_count(&conn).await?;
            let measured_receipts = new_receipts(&conn, receipt_before_id).await?;
            let state_after_sha256 = persistent_digest(&conn).await?;
            resource_diagnostics::record("postcall_observation_exit");
            let expected_processed = if sample == "cleanup" { 9 } else { WORK_LIMIT };
            let expected_stake = if sample == "penalty" {
                sub_decimal(stake_before, penalty_total)?
            } else {
                stake_before
            };
            let expected_supply = if sample == "penalty" {
                sub_decimal(supply_before, penalty_total)?
            } else {
                supply_before
            };
            ensure!(
                processed == expected_processed
                    && stake_after == expected_stake
                    && supply_after == expected_supply
                    && reservation_after
                        == if sample == "cleanup" {
                            Decimal::default()
                        } else {
                            reservation_before
                        }
                    && !pending_after
                    && obligations_after == (sample != "cleanup" && obligations_before)
                    && memberships_after
                        == if sample == "cleanup" {
                            0
                        } else {
                            memberships_before
                        }
                    && statuses_after.iter().all(|status| {
                        status.as_str()
                            == if sample == "expiry" {
                                "Expired"
                            } else {
                                "Settled"
                            }
                    })
                    && receipts_after == receipts_before + measured_receipts.len() as u64
                    && usage.user_fuel == 0
                    && usage.deposit_fuel == 0
                    && usage.system_fuel > 0
                    && resources_after == resources_before
                    && stack_empty
                    && savepoint_restored
                    && live_invocations == 0,
                "filestorage lifecycle semantics or Store cleanup changed"
            );
            runtime.storage.rollback().await?;
            runtime.set_context(DUE_HEIGHT, None, None, None).await;
            let state_restored_sha256 = persistent_digest(&conn).await?;
            let receipts_restored = receipt_count(&conn).await?;
            ensure!(
                state_restored_sha256 == baseline_digest
                    && receipts_restored == baseline_receipts
                    && runtime.storage.savepoint_stack.is_empty().await,
                "filestorage lifecycle repeat did not restore baseline state"
            );
            let mut observation = json!({
                "sample_key": sample, "outcome": "ok", "processed": processed,
                "challenge_count": challenge_count, "file_count": file_count,
                "challenge_ids": &challenge_ids,
                "agreements": &fixture.agreements,
                "requirements": fixture.requirements.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "active_agreements_before": &active_agreements_before,
                "active_agreements_after": &active_agreements_after,
                "statuses_before": &statuses_before, "statuses_after": &statuses_after,
                "stake_before": stake_before.to_string(), "stake_after": stake_after.to_string(),
                "supply_before": supply_before.to_string(), "supply_after": supply_after.to_string(),
                "penalty_total": penalty_total.to_string(),
                "reservation_before": reservation_before.to_string(),
                "reservation_after": reservation_after.to_string(),
                "pending_before": pending_before, "pending_after": pending_after,
                "obligations_before": obligations_before, "obligations_after": obligations_after,
                "memberships_before": memberships_before, "memberships_after": memberships_after,
            });
            let diagnostics = json!({
                "system_fuel": usage.system_fuel, "user_fuel": usage.user_fuel,
                "deposit_fuel": usage.deposit_fuel,
                "state_before_sha256": baseline_digest,
                "state_after_sha256": state_after_sha256,
                "state_restored_sha256": state_restored_sha256,
                "receipts_before": receipts_before, "receipts_after": receipts_after,
                "measured_receipts": measured_receipts, "receipts_restored": receipts_restored,
                "resources_before": resources_before, "resources_after": resources_after,
                "stack_empty": stack_empty, "savepoint_restored": savepoint_restored,
                "savepoint_empty": true, "live_invocations": live_invocations,
                "teardown_probe_on": recorder.is_some(), "teardown_events": teardown_events,
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": runtime.engine.get_max_wasm_stack(),
                "async_stack_size": runtime.engine.get_async_stack_size(),
            });
            observation
                .as_object_mut()
                .unwrap()
                .extend(diagnostics.as_object().unwrap().clone());
            println!(
                "FINITE_STACK_ATTEMPT:{}",
                json!({
                    "case_id": CASE_ID, "configuration": configuration,
                    "process_role": process_role, "sample_key": sample,
                    "repeat_index": repeat_index, "pid": process::id(),
                    "observation": observation,
                })
            );
            println!(
                "KONTOR_STACK_TIMING:{}",
                json!({
                    "case_id": CASE_ID, "sample_key": sample,
                    "repeat_index": repeat_index, "elapsed_ms": started.elapsed().as_millis(),
                })
            );
            resource_diagnostics::record("finite_stack_attempt_end");
            outcomes.push("ok");
        }
    }
    let summary = json!({
        "case_id": CASE_ID, "configuration": configuration,
        "process_role": process_role, "sample_count": outcomes.len(),
        "outcomes": outcomes, "complete": true,
    });
    println!("FINITE_STACK_SUMMARY:{summary}");
    Ok(summary)
}
