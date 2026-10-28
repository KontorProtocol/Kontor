use std::env;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use indexer_types::Payment;
use libsql::params;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio::sync::Notify;
use tokio::time::timeout;
use wasmtime::Trap;

use super::{balance, funded};
use crate::database::queries::live_deposit_gas_sum;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::pricing::Pricing;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, Linkers, MAX_UNTRUSTED_GAS_LIMIT, Runtime,
    TransactionContext, native_provenance, to_wave_expr,
};
use crate::test_utils::test_runtime;

const CHILD: &str = "runtime::call::tests::sequential_chains::chain_probe_child";

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

#[tokio::test(flavor = "current_thread")]
#[ignore = "invoked by the parent test to contain native process aborts"]
async fn chain_probe_child() -> Result<()> {
    let mode = env::var("KONTOR_CHAIN_MODE")?;
    let depth: u32 = env::var("KONTOR_CHAIN_DEPTH")?.parse()?;
    assert!(matches!(mode.as_str(), "paid" | "view" | "core"));
    assert!(matches!(depth, 32 | 62 | 63 | 64));
    let over_cap = depth == 64;
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = publish_chain(&mut runtime, &actor, depth).await?;
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
                entered.notify_one();
                release.notified().await;
                Ok((String::new(),))
            })
        })?;
    runtime.linkers = Arc::new(Linkers {
        user,
        native: runtime.linkers.native.clone(),
    });
    let conn = runtime.get_storage_conn();
    let root = chain.last().unwrap().clone();
    let root_id = runtime.storage.contract_id(&root).await?.unwrap();
    let baseline_resources = runtime.table.lock().await.iter_mut().count();
    let mut over_cap_observation = None;
    let mut trials = Vec::new();

    for fail in if over_cap {
        [false, false, false]
    } else {
        [false, true, false]
    } {
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
        let target = root.clone();
        let task = tokio::spawn(async move {
            let result = runtime
                .execute(
                    signer.as_ref(),
                    payment,
                    &target,
                    &format!("{function}({fail})"),
                )
                .await;
            (runtime, result)
        });
        let mut host_io_suspended = false;
        let leaf_callback_seen = if !over_cap {
            timeout(Duration::from_secs(30), entered.notified()).await?;
            host_io_suspended = !task.is_finished();
            assert!(host_io_suspended);
            assert_eq!(tokio::spawn(async { 42 }).await?, 42);
            release.notify_one();
            true
        } else {
            false
        };
        let (returned, result) = timeout(Duration::from_secs(30), task).await??;
        runtime = returned;
        let usage = runtime.finish_usage(previous)?;
        let savepoint_restored = runtime.storage.savepoint_stack.peek().await == saved;
        let value = if over_cap {
            assert!(
                matches!(result, Err(ExecutionError::Deterministic(_))),
                "{result:?}"
            );
            assert!(format!("{result:?}").contains("live invocation limit"));
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
                "SELECT status, gas FROM contract_results WHERE contract_id = ? ORDER BY id",
                params![root_id],
            )
            .await?;
        let receipt = receipts.next().await?;
        let receipt = if mode == "view" {
            assert!(receipt.is_none());
            None
        } else {
            let receipt = receipt.expect("one root receipt");
            let status = receipt.get::<String>(0)?;
            assert_eq!(status, if fail || over_cap { "Other" } else { "Ok" });
            let gas = receipt.get::<u64>(1)?;
            assert!(gas > 0);
            assert!(receipts.next().await?.is_none());
            Some(json!({ "status": status, "gas": gas }))
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
        runtime.storage.rollback().await?;
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
        trials.push(json!({
            "outcome": if over_cap { "invocation_limit" } else if fail { "trap" } else { "ok" },
            "value": value,
            "fuel": {
                "user": usage.user_fuel,
                "system": usage.system_fuel,
                "deposit": usage.deposit_fuel,
            },
            "receipt": receipt,
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
    }
    println!(
        "CHAIN_PROBE_REPORT:{}",
        json!({
            "mode": mode,
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
        })
    );
    println!("CHAIN_PROBE_COMPLETE mode={mode} stores={}", depth + 1);
    Ok(())
}
