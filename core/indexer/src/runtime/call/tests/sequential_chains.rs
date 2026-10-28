use std::env;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use indexer_types::Payment;
use libsql::params;
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
        for depth in [32, 64] {
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
                "{mode} depth={depth}: {}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("CHAIN_PROBE_COMPLETE"), "{stdout}");
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
    assert!(matches!(depth, 32 | 64));
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

    for fail in [false, true, false] {
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
        timeout(Duration::from_secs(30), entered.notified()).await?;
        assert!(!task.is_finished());
        assert_eq!(tokio::spawn(async { 42 }).await?, 42);
        release.notify_one();
        let (returned, result) = timeout(Duration::from_secs(30), task).await??;
        runtime = returned;
        let usage = runtime.finish_usage(previous)?;
        if fail {
            assert!(
                matches!(result, Err(ExecutionError::Deterministic(ref error))
                if error.chain().any(|cause| cause.downcast_ref::<Trap>() == Some(&Trap::UnreachableCodeReached))),
                "{result:?}"
            );
        } else {
            assert_eq!(result?, "42");
        }
        assert!(runtime.stack.is_empty().await);
        assert_eq!(runtime.storage.savepoint_stack.peek().await, saved);
        assert_eq!(
            runtime.table.lock().await.iter_mut().count(),
            baseline_resources
        );
        let expected_state = if fail || mode == "view" {
            "[0, 0, 0, 0]"
        } else {
            "[2, 0, 0, 0]"
        };
        assert_eq!(
            runtime
                .execute(None, None, &chain[0], "storage-state()")
                .await?,
            expected_state
        );
        let mut receipts = conn
            .query(
                "SELECT status, gas FROM contract_results WHERE contract_id = ? ORDER BY id",
                params![root_id],
            )
            .await?;
        let receipt = receipts.next().await?;
        if mode == "view" {
            assert!(receipt.is_none());
        } else {
            let receipt = receipt.expect("one root receipt");
            assert_eq!(receipt.get::<String>(0)?, if fail { "Other" } else { "Ok" });
            assert!(receipt.get::<u64>(1)? > 0);
            assert!(receipts.next().await?.is_none());
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
            } else if fail {
                1
            } else {
                u64::from(depth) + 1
            }
        );
        let paid = sub_decimal(
            before,
            balance(&mut runtime, HolderRef::from(&actor)).await?,
        )?;
        let burned = sub_decimal(
            balance(&mut runtime, HolderRef::Burner).await?,
            burned_before,
        )?;
        assert_eq!(paid, burned);
        assert_eq!(
            sub_decimal(supply_before, token::total_supply(&mut runtime).await?)?,
            burned
        );
        let floor_after = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
        let live_deposit = live_deposit_gas_sum(&conn, actor.signer_id().unwrap()).await?;
        assert_eq!(floor_after, Pricing::storage_collateral(live_deposit)?);
        // A successful Core write removes the previous user's deposit ownership.
        if mode == "core" && !fail {
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
        assert!(runtime.storage.savepoint_stack.is_empty().await);
        assert_eq!(
            token::floor(&mut runtime, HolderRef::from(&actor)).await?,
            floor_before
        );
        assert_eq!(
            balance(&mut runtime, HolderRef::from(&actor)).await?,
            before
        );
    }
    println!("CHAIN_PROBE_COMPLETE mode={mode} depth={depth}");
    Ok(())
}
