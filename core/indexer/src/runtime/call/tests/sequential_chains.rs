use std::env;
use std::future::{Future, poll_fn};
use std::process;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use anyhow::{Result, bail};
use indexer_types::Payment;
use libsql::params;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio::sync::Notify;
use tokio::time::timeout;
use wasmtime::Trap;

use super::native_stack::{assert_receipt_stream_initial_state, memory, persistent_digest};
use super::{balance, funded, funded_with_pubkey};
use crate::database::queries::live_deposit_gas_sum;
use crate::runtime::invocation::{
    InvocationBudget, InvocationCapacityExhausted, InvocationLimitReached, MAX_LIVE_INVOCATIONS,
    ResourceProbePhase, ResourceTeardownRecorder,
};
use crate::runtime::numerics::sub_decimal;
use crate::runtime::pricing::Pricing;
use crate::runtime::resource_diagnostics;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, Linkers, MAX_UNTRUSTED_GAS_LIMIT, Runtime,
    TransactionContext, native_provenance, to_wave_expr,
};
use crate::test_utils::{test_runtime, test_runtime_with_engine};

const CHILD: &str = "runtime::call::tests::sequential_chains::chain_probe_child";
const RESOURCE_CHAIN_SIGNER_X_ONLY_PUBKEY: &str =
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[tokio::test]
async fn deep_sequential_chains_survive_in_separate_processes() -> Result<()> {
    for mode in ["paid", "view", "core"] {
        for stores in [33_u32, 63, 64, 65] {
            let depth = stores - 1;
            // An abort must fail this parent test instead of taking down the suite.
            let output = timeout(
                Duration::from_secs(120),
                Command::new(env::current_exe()?)
                    .args(["--exact", CHILD, "--ignored", "--nocapture"])
                    .env("KONTOR_CHAIN_MODE", mode)
                    .env("KONTOR_CHAIN_DEPTH", depth.to_string())
                    .kill_on_drop(true)
                    .output(),
            )
            .await??;
            assert!(
                output.status.success(),
                "{mode} stores={stores}: {}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("CHAIN_PROBE_COMPLETE"), "{stdout}");
            print!("{stdout}");
            println!("CHAIN_CELL_COMPLETE mode={mode} stores={stores}");
        }
    }
    Ok(())
}

async fn publish_chain(
    runtime: &mut Runtime,
    signer: &Signer,
    depth: u32,
) -> Result<Vec<ContractAddress>> {
    let mut chain: Vec<ContractAddress> = Vec::new();
    for index in 0..=depth {
        runtime
            .set_context(
                1,
                Some(TransactionContext::builder().tx_index(index).build()),
                None,
                None,
            )
            .await;
        let (name, bytes) = if index == 0 {
            (
                "deep-errors",
                include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br")
                    .as_slice(),
            )
        } else {
            (
                "deep-proxy",
                include_bytes!("../../../../../../test-contracts/binaries/proxy.wasm.br")
                    .as_slice(),
            )
        };
        runtime
            .publish(
                signer,
                Payment {
                    signer_id: signer.signer_id().unwrap(),
                    gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
                },
                name,
                bytes,
                &native_provenance()?,
            )
            .await?;
        let address = ContractAddress {
            name: name.into(),
            height: 1,
            tx_index: index,
        };
        if let Some(child) = chain.last() {
            runtime
                .execute_api(
                    Some(signer),
                    &address,
                    &format!("set-contract-address({})", to_wave_expr(child.clone())),
                )
                .await?;
        }
        chain.push(address);
    }
    runtime.set_context(1, None, None, None).await;
    Ok(chain)
}

#[tokio::test]
async fn physical_capacity_failure_in_a_paid_nested_call_rolls_back_payment() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = publish_chain(&mut runtime, &actor, 1).await?;
    let root = chain.last().unwrap();
    let conn = runtime.get_storage_conn();
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    let receipts_before: u64 = rows.next().await?.unwrap().get(0)?;
    let balance_before = balance(&mut runtime, HolderRef::from(&actor)).await?;
    let burner_before = balance(&mut runtime, HolderRef::Burner).await?;
    let floor_before = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
    let supply_before = token::total_supply(&mut runtime).await?;
    let resources_before = runtime.table.lock().await.iter_mut().count();

    let budget = Arc::new(InvocationBudget::default());
    runtime.invocation_budget = Some(budget.clone());
    let stores = (0..MAX_LIVE_INVOCATIONS - 1)
        .map(|_| runtime.make_store(1_000_000))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(budget.live(), MAX_LIVE_INVOCATIONS - 1);
    let result = runtime
        .execute(
            Some(&actor),
            Some(Payment {
                signer_id: actor.signer_id().unwrap(),
                gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
            }),
            root,
            "chain-probe(false)",
        )
        .await;
    assert!(
        matches!(result, Err(ExecutionError::NonDeterministic(ref error))
        if error.chain().any(|cause| cause.is::<InvocationCapacityExhausted>()))
    );
    assert_eq!(budget.live(), MAX_LIVE_INVOCATIONS - 1);
    assert!(runtime.stack.is_empty().await);
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    assert_eq!(
        runtime.table.lock().await.iter_mut().count(),
        resources_before
    );
    assert_eq!(
        balance(&mut runtime, HolderRef::from(&actor)).await?,
        balance_before
    );
    assert_eq!(
        balance(&mut runtime, HolderRef::Burner).await?,
        burner_before
    );
    assert_eq!(
        token::floor(&mut runtime, HolderRef::from(&actor)).await?,
        floor_before
    );
    assert_eq!(token::total_supply(&mut runtime).await?, supply_before);
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    let receipts_after: u64 = rows.next().await?.unwrap().get(0)?;
    assert_eq!(receipts_after, receipts_before);

    drop(stores);
    assert_eq!(budget.live(), 0);
    assert_eq!(
        runtime
            .execute(None, None, &chain[0], "storage-state()")
            .await?,
        "[0, 0, 0, 0]"
    );
    assert_eq!(budget.live(), 0);
    Ok(())
}

#[tokio::test]
async fn nested_depth_rejection_preserves_the_typed_limit_marker() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = publish_chain(&mut runtime, &actor, 1).await?;
    let root_id = runtime
        .storage
        .contract_id(chain.last().unwrap())
        .await?
        .unwrap();
    let conn = runtime.get_storage_conn();
    conn.execute("DELETE FROM contract_results", ()).await?;
    let floor_before = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
    runtime.invocation_depth = MAX_LIVE_INVOCATIONS - 1;
    let result = runtime
        .execute(
            Some(&actor),
            Some(Payment {
                signer_id: actor.signer_id().unwrap(),
                gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
            }),
            chain.last().unwrap(),
            "chain-probe(false)",
        )
        .await;
    assert!(
        matches!(result, Err(ExecutionError::Deterministic(ref error))
        if error.chain().any(|cause| cause.downcast_ref::<InvocationLimitReached>().is_some())
            && error.chain().all(|cause| cause.downcast_ref::<Trap>().is_none()))
    );
    runtime.invocation_depth = 0;
    let mut rows = conn
        .query(
            "SELECT contract_id, status FROM contract_results ORDER BY id",
            (),
        )
        .await?;
    let receipt = rows.next().await?.expect("one root receipt");
    assert_eq!(receipt.get::<u64>(0)?, root_id);
    assert_eq!(receipt.get::<String>(1)?, "Other");
    assert!(rows.next().await?.is_none());
    assert_eq!(
        runtime
            .execute(None, None, &chain[0], "storage-state()")
            .await?,
        "[0, 0, 0, 0]"
    );
    assert_eq!(
        token::floor(&mut runtime, HolderRef::from(&actor)).await?,
        floor_before
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "invoked by the parent test to contain native process aborts"]
async fn chain_probe_child() -> Result<()> {
    let mode = env::var("KONTOR_CHAIN_MODE")?;
    let depth: u32 = env::var("KONTOR_CHAIN_DEPTH")?.parse()?;
    run_chain_probe(mode, depth, None, false, false).await
}

pub(super) async fn resource_chain_probe(mode: String, depth: u32, reduced: bool) -> Result<()> {
    run_chain_probe(mode, depth, Some(reduced), true, false).await
}

pub(super) async fn resource_chain_trap_control(
    mode: String,
    depth: u32,
    reduced: bool,
) -> Result<()> {
    run_chain_probe(mode, depth, Some(reduced), false, false).await
}

pub(super) async fn run_suspended_64_profile() -> Result<()> {
    run_chain_probe("paid".to_owned(), 63, Some(false), true, true).await
}

async fn run_chain_probe(
    mode: String,
    depth: u32,
    diagnostic_reduced: Option<bool>,
    target_only: bool,
    capacity_profile: bool,
) -> Result<()> {
    assert!(matches!(mode.as_str(), "paid" | "view" | "core"));
    assert!(matches!(depth, 32 | 62 | 63 | 64));
    let over_cap = depth == 64;
    assert!(
        !capacity_profile
            || (mode == "paid" && depth == 63 && diagnostic_reduced == Some(false) && target_only)
    );
    let (mut runtime, _dir, _name) = match diagnostic_reduced {
        Some(reduced) => {
            let engine = if reduced {
                Runtime::new_resource_diagnostic_engine()?
            } else {
                Runtime::new_engine()?
            };
            test_runtime_with_engine(engine).await?
        }
        None => test_runtime().await?,
    };
    let actor = if diagnostic_reduced.is_some() {
        funded_with_pubkey(&mut runtime, RESOURCE_CHAIN_SIGNER_X_ONLY_PUBKEY).await?
    } else {
        funded(&mut runtime).await?
    };
    let chain = publish_chain(&mut runtime, &actor, depth).await?;
    assert!(runtime.conversion_probe.is_none());
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let mut user = runtime.linkers.user.clone();
    let host_entered = entered.clone();
    let host_release = release.clone();
    user.allow_shadowing(true)
        .instance("kontor:built-in/testing")?
        .func_wrap_async("host-error", move |_, (): ()| {
            let entered = host_entered.clone();
            let release = host_release.clone();
            Box::new(async move {
                let wait = release.notified();
                tokio::pin!(wait);
                let mut signaled = false;
                poll_fn(|cx| match wait.as_mut().poll(cx) {
                    Poll::Pending => {
                        if !signaled {
                            // The observer may sample memory only after the host future has polled Pending.
                            entered.notify_one();
                            signaled = true;
                        }
                        Poll::Pending
                    }
                    Poll::Ready(()) => Poll::Ready(()),
                })
                .await;
                Ok((String::new(),))
            })
        })?;
    runtime.linkers = Arc::new(Linkers {
        user,
        native: runtime.linkers.native.clone(),
    });
    let conn = runtime.get_storage_conn();
    let root = chain.last().unwrap().clone();
    let chain_addresses = Arc::new(chain.clone());
    let teardown_probe_mode = match env::var("KONTOR_RESOURCE_TEARDOWN_PROBE").as_deref() {
        Ok("on") => Some("on"),
        Ok("off") => Some("off"),
        Err(env::VarError::NotPresent) => None,
        _ => bail!("invalid resource teardown probe mode"),
    };
    assert!(!capacity_profile || teardown_probe_mode == Some("on"));
    assert!(teardown_probe_mode.is_none() || diagnostic_reduced.is_some());
    let process_role = teardown_probe_mode.map(|probe| match (target_only, probe) {
        (true, "on") => "target_observed",
        (false, "on") => "trap_control_observed",
        (true, "off") => "target_probe_off_control",
        (false, "off") => "trap_control_probe_off_control",
        _ => unreachable!(),
    });
    let root_id = runtime.storage.contract_id(&root).await?.unwrap();
    let baseline_resources = runtime.table.lock().await.iter_mut().count();
    let mut over_cap_observation = None;
    let mut trials = Vec::new();

    for (repeat_index, fail) in (if over_cap || target_only {
        [false, false, false]
    } else {
        [false, true, false]
    })
    .into_iter()
    .enumerate()
    {
        if diagnostic_reduced.is_some() {
            resource_diagnostics::record("chain_attempt_start");
            resource_diagnostics::record("chain_preparation_entry");
        }
        let teardown_recorder = (teardown_probe_mode == Some("on"))
            .then(|| Arc::new(ResourceTeardownRecorder::default()));
        let budget = Arc::new(match &teardown_recorder {
            Some(recorder) => InvocationBudget::with_teardown_recorder(recorder.clone()),
            None => InvocationBudget::default(),
        });
        runtime.invocation_budget = Some(budget.clone());
        runtime.resource_probe_phase =
            teardown_probe_mode.map(|_| ResourceProbePhase::PreObservation);
        assert_eq!(budget.live(), 0);
        assert_receipt_stream_initial_state(&conn).await?;
        let state_before_sha256 = persistent_digest(&conn).await?;
        assert!(runtime.conversion_probe.is_none());
        runtime.storage.savepoint().await?;
        conn.execute("DELETE FROM contract_results", ()).await?;
        let saved = runtime.storage.savepoint_stack.peek().await;
        let before = balance(&mut runtime, HolderRef::from(&actor)).await?;
        let burned_before = balance(&mut runtime, HolderRef::Burner).await?;
        let floor_before = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
        let supply_before = token::total_supply(&mut runtime).await?;
        let previous = runtime.start_usage();
        let (signer, payment, function) = match mode.as_str() {
            "paid" => (
                Some(actor.clone()),
                Some(Payment {
                    signer_id: actor.signer_id().unwrap(),
                    gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
                }),
                "chain-probe",
            ),
            "core" => (
                Some(Signer::Core(Box::new(actor.clone()))),
                Some(runtime.core_payment()),
                "core-chain-probe",
            ),
            _ => (None, None, "view-chain-probe"),
        };
        if diagnostic_reduced.is_some() {
            resource_diagnostics::record("chain_preparation_exit");
            resource_diagnostics::record("chain_operation_entry");
        }
        runtime.resource_probe_phase =
            teardown_probe_mode.map(|_| ResourceProbePhase::Target(chain_addresses.clone()));
        if capacity_profile && repeat_index == 0 {
            println!("SUSPENDED_64_BASELINE:{}", memory::snapshot()?);
        }
        let target = root.clone();
        let task = tokio::spawn(async move {
            resource_diagnostics::record("chain_guest_task_entry");
            let result = runtime
                .execute(
                    signer.as_ref(),
                    payment,
                    &target,
                    &format!("{function}({fail})"),
                )
                .await;
            resource_diagnostics::record("chain_guest_task_exit");
            (runtime, result)
        });
        let mut host_io_suspended = false;
        let leaf_callback_seen = if !over_cap {
            timeout(Duration::from_secs(30), entered.notified()).await?;
            host_io_suspended = !task.is_finished();
            assert!(host_io_suspended);
            assert_eq!(budget.live(), depth + 1);
            assert_eq!(tokio::spawn(async { 42 }).await?, 42);
            if capacity_profile && repeat_index == 0 {
                assert_eq!(budget.peak(), 64);
                println!(
                    "SUSPENDED_64_PEAK:{}",
                    json!({
                        "memory": memory::snapshot()?,
                        "pending_host_calls": 1,
                        "reactor_roots": 1,
                        "view_roots": 0,
                        "live_stores": budget.live(),
                        "reservations": budget.peak(),
                        "other_task_progressed": true,
                        "deliberate_guest_memory_pressure_bytes": 0,
                        "cache_state": "warm_compiled_cache",
                        "configuration": "production",
                        "profile_id": "suspended_64",
                    })
                );
            }
            release.notify_one();
            true
        } else {
            false
        };
        let (returned, result) = timeout(Duration::from_secs(30), task).await??;
        runtime = returned;
        runtime.resource_probe_phase =
            teardown_probe_mode.map(|_| ResourceProbePhase::PostObservation(chain[0].clone()));
        if diagnostic_reduced.is_some() {
            resource_diagnostics::record("chain_operation_exit");
            resource_diagnostics::record("chain_postcall_entry");
        }
        assert_eq!(budget.live(), 0);
        let live_store_peak = budget.peak();
        assert_eq!(live_store_peak, (depth + 1).min(MAX_LIVE_INVOCATIONS));
        let usage = runtime.finish_usage(previous)?;
        let savepoint_restored = runtime.storage.savepoint_stack.peek().await == saved;
        let value = if over_cap {
            assert!(
                matches!(result, Err(ExecutionError::Deterministic(ref error))
                    if error.chain().any(|cause| cause.downcast_ref::<InvocationLimitReached>().is_some())
                        && error.chain().all(|cause| cause.downcast_ref::<Trap>().is_none())),
                "{result:?}"
            );
            assert!(
                timeout(Duration::from_millis(25), entered.notified())
                    .await
                    .is_err()
            );
            None
        } else if fail {
            assert!(
                matches!(result, Err(ExecutionError::Deterministic(ref error))
                if error.chain().any(|cause| cause.downcast_ref::<Trap>() == Some(&Trap::UnreachableCodeReached))),
                "{result:?}"
            );
            None
        } else {
            let value = result?;
            assert_eq!(value, "42");
            Some(value)
        };
        let stack_empty = runtime.stack.is_empty().await;
        assert!(stack_empty);
        assert!(savepoint_restored);
        let resource_count = runtime.table.lock().await.iter_mut().count();
        assert_eq!(resource_count, baseline_resources);
        let expected_state = if fail || over_cap || mode == "view" {
            "[0, 0, 0, 0]"
        } else {
            "[2, 0, 0, 0]"
        };
        let storage_state = runtime
            .execute(None, None, &chain[0], "storage-state()")
            .await?;
        assert_eq!(storage_state, expected_state);
        let mut receipts = conn
            .query(
                "SELECT contract_id, status, gas, value FROM contract_results WHERE contract_id = ? ORDER BY id",
                params![root_id],
            )
            .await?;
        let receipt = receipts.next().await?;
        let receipt = if mode == "view" {
            assert!(receipt.is_none());
            None
        } else {
            let receipt = receipt.expect("one root receipt");
            let contract_id = receipt.get::<u64>(0)?;
            assert_eq!(contract_id, root_id);
            let status = receipt.get::<String>(1)?;
            assert_eq!(status, if fail || over_cap { "Other" } else { "Ok" });
            let gas = receipt.get::<u64>(2)?;
            let value = receipt.get::<Option<String>>(3)?;
            assert!(gas > 0);
            assert!(receipts.next().await?.is_none());
            Some(json!({
                "contract_id": contract_id,
                "status": status,
                "gas": gas,
                "value": value,
            }))
        };
        let receipt_gas = receipt
            .as_ref()
            .map_or(0, |value| value["gas"].as_u64().unwrap());
        if over_cap {
            let observation = (
                usage.user_fuel,
                usage.system_fuel,
                usage.deposit_fuel,
                receipt_gas,
            );
            if let Some(expected) = over_cap_observation {
                assert_eq!(observation, expected);
            } else {
                over_cap_observation = Some(observation);
            }
        }
        let mut rows = conn.query(
            "SELECT count(*) FROM contract_results WHERE contract_id IN (SELECT id FROM contracts WHERE name IN ('deep-errors', 'deep-proxy'))",
            (),
        ).await?;
        let receipt_count: u64 = rows.next().await?.unwrap().get(0)?;
        assert_eq!(
            receipt_count,
            if mode == "view" {
                0
            } else if fail || over_cap {
                1
            } else {
                u64::from(depth) + 1
            }
        );
        let after = balance(&mut runtime, HolderRef::from(&actor)).await?;
        let burned_after = balance(&mut runtime, HolderRef::Burner).await?;
        let supply_after = token::total_supply(&mut runtime).await?;
        let paid = sub_decimal(before, after)?;
        let burned = sub_decimal(burned_after, burned_before)?;
        let supply_delta = sub_decimal(supply_before, supply_after)?;
        assert_eq!(paid, burned);
        assert_eq!(supply_delta, burned);
        let floor_after = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
        let live_deposit = live_deposit_gas_sum(&conn, actor.signer_id().unwrap()).await?;
        assert_eq!(floor_after, Pricing::storage_collateral(live_deposit)?);
        // A successful Core write removes the previous user's deposit ownership.
        if mode == "core" && !fail && !over_cap {
            assert!(floor_after < floor_before);
        } else {
            assert_eq!(floor_after, floor_before);
        }
        if mode == "paid" {
            assert!(usage.user_fuel > 0);
            assert!(paid > Decimal::default());
        } else {
            assert!(usage.system_fuel > 0);
            assert_eq!(paid, Decimal::default());
        }
        if diagnostic_reduced.is_some() {
            resource_diagnostics::record("chain_postcall_exit");
            resource_diagnostics::record("chain_teardown_entry");
        }
        runtime.resource_probe_phase =
            teardown_probe_mode.map(|_| ResourceProbePhase::RollbackObservation(chain[0].clone()));
        runtime.storage.rollback().await?;
        assert_receipt_stream_initial_state(&conn).await?;
        let state_after_sha256 = persistent_digest(&conn).await?;
        assert_eq!(state_before_sha256, state_after_sha256);
        let restored = balance(&mut runtime, HolderRef::from(&actor)).await?;
        let floor_restored = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
        let rollback_clean = runtime.storage.savepoint_stack.is_empty().await
            && restored == before
            && floor_restored == floor_before
            && balance(&mut runtime, HolderRef::Burner).await? == burned_before
            && token::total_supply(&mut runtime).await? == supply_before
            && runtime
                .execute(None, None, &chain[0], "storage-state()")
                .await?
                == "[0, 0, 0, 0]";
        assert!(rollback_clean);
        let balances_snapshot = json!({
            "actor": before.to_string(),
            "burner": burned_before.to_string(),
            "floor": floor_before.to_string(),
            "supply": supply_before.to_string(),
        });
        let balances_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&balances_snapshot)?));
        assert_eq!(budget.live(), 0);
        let teardown_events = teardown_recorder.as_ref().map(|recorder| recorder.events());
        runtime.resource_probe_phase = None;
        trials.push(json!({
            "repeat_index": repeat_index,
            "sample_key": if fail { "trap_control" } else { "target" },
            "outcome": if over_cap { "invocation_limit" } else if fail { "trap" } else { "ok" },
            "error_class": if over_cap || fail { Some("deterministic") } else { None },
            "trap": if fail { Some("UnreachableCodeReached") } else { None },
            "value": value,
            "fuel": {
                "user": usage.user_fuel,
                "system": usage.system_fuel,
                "deposit": usage.deposit_fuel,
            },
            "receipt": receipt,
            "state_before_sha256": state_before_sha256,
            "state_after_sha256": state_after_sha256,
            "balances_sha256": balances_sha256,
            "balances_snapshot": balances_snapshot,
            "teardown_events": teardown_events,
            "live_store_peak": live_store_peak,
            "live_stores_before": 0,
            "live_stores_after": budget.live(),
            "storage_state": storage_state,
            "rolled_back": rollback_clean,
            "resource_count": resource_count,
            "baseline_resource_count": baseline_resources,
            "savepoint_restored": savepoint_restored,
            "stack_empty": stack_empty,
            "host_io_suspended": host_io_suspended,
            "leaf_callback_seen": leaf_callback_seen,
            "balances": {
                "before": before.to_string(),
                "after": after.to_string(),
                "restored": restored.to_string(),
                "burned_before": burned_before.to_string(),
                "burned_after": burned_after.to_string(),
                "supply_before": supply_before.to_string(),
                "supply_after": supply_after.to_string(),
                "floor_before": floor_before.to_string(),
                "floor_after": floor_after.to_string(),
                "floor_restored": floor_restored.to_string(),
            },
            "receipt_count": receipt_count,
            "rollback_clean": rollback_clean,
        }));
        if let Some(role) = process_role {
            println!(
                "CHAIN_PROBE_ATTEMPT:{}",
                json!({
                    "case_id": format!("chain_{}_{}", depth + 1, mode),
                    "process_role": role,
                    "configuration": if diagnostic_reduced == Some(true) { "reduced" } else { "production" },
                    "process_attempt_index": 0,
                    "pid": process::id(),
                    "sample_key": if fail { "trap_control" } else { "target" },
                    "repeat_index": repeat_index,
                    "complete": true,
                })
            );
        }
        if diagnostic_reduced.is_some() {
            resource_diagnostics::record("chain_teardown_exit");
            resource_diagnostics::record("chain_attempt_end");
        }
    }
    let trial_count = trials.len();
    if capacity_profile {
        assert!(trials.iter().all(|trial| trial["live_stores_after"] == 0
            && trial["live_store_peak"] == 64
            && trial["host_io_suspended"] == true
            && trial["outcome"] == "ok"));
    }
    let report = json!({
        "case_id": format!("chain_{}_{}", depth + 1, mode),
        "mode": mode,
        "resource_mode": diagnostic_reduced.map(|reduced| if reduced { "reduced" } else { "production" }),
        "teardown_probe_mode": teardown_probe_mode,
        "target_only": target_only,
        "call_hook_installed": runtime.conversion_probe.is_some(),
        "stores": depth + 1,
        "trials": trials,
        "component_sha256": {
            "error_test": hex::encode(Sha256::digest(include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br"))),
            "proxy": hex::encode(Sha256::digest(include_bytes!("../../../../../../test-contracts/binaries/proxy.wasm.br"))),
        },
        "engine_target": runtime.engine.get_target(),
        "max_wasm_stack": runtime.engine.get_max_wasm_stack(),
        "async_stack_size": runtime.engine.get_async_stack_size(),
        "target_os": env::consts::OS,
        "target_arch": env::consts::ARCH,
    });
    println!("CHAIN_PROBE_REPORT:{report}");
    if capacity_profile {
        println!(
            "SUSPENDED_64_COMPLETION:{}",
            json!({
                "memory": memory::snapshot()?,
                "report": report,
                "completed_store_lifecycles": 64,
                "pending_host_calls_after": 0,
                "live_stores_after": 0,
            })
        );
    }
    if let Some(role) = process_role {
        println!(
            "CHAIN_PROBE_TERMINAL:{}",
            json!({
                "case_id": format!("chain_{}_{}", depth + 1, mode),
                "process_role": role,
                "configuration": if diagnostic_reduced == Some(true) { "reduced" } else { "production" },
                "process_attempt_index": 0,
                "pid": process::id(),
                "trial_count": trial_count,
                "complete": true,
            })
        );
    }
    println!("CHAIN_PROBE_COMPLETE mode={mode} stores={}", depth + 1);
    Ok(())
}
