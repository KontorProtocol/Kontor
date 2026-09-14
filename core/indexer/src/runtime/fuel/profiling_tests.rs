use std::time::Instant;

use anyhow::Result;
use bitcoin::OutPoint;
use indexer_types::{Input, Inst, InstKind, Insts, TransactionRow};
use serde_json::json;
use wasmtime::component::{Component, Linker};
use wasmtime::{Store, Trap};

use super::{Fuel, FuelGauge};
use crate::bitcoin_client::Client;
use crate::database::queries::{get_checkpoint_by_height, insert_transaction};
use crate::reactor::executor::{Executor, RuntimeExecutor};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::staking::{address as staking_address, api as staking};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, ExecutionError, Runtime};
use crate::test_utils::{new_mock_transaction, test_runtime};

#[tokio::test]
async fn host_fuel_exhaustion_is_an_out_of_fuel_trap() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut store = runtime.make_store(Fuel::SignerToString.cost() - 1)?;
    let err = Fuel::SignerToString
        .consume_with_store(&mut store)
        .unwrap_err();
    assert!(
        matches!(err.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)),
        "host exhaustion lost its trap type: {err:#}"
    );
    assert_eq!(store.get_fuel()?, Fuel::SignerToString.cost() - 1);
    store.set_fuel(Fuel::SignerToString.cost())?;
    assert_eq!(Fuel::SignerToString.consume_with_store(&mut store)?, 0);
    assert_eq!(store.get_fuel()?, 0);
    Ok(())
}

#[tokio::test]
async fn initialization_fuel_has_a_platform_independent_boundary() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let component = Component::new(
        &engine,
        r#"(component
            (core module $m
                (memory 1)
                (data (i32.const 0) "hello"))
            (core instance (instantiate $m)))"#,
    )?;
    let pre = Linker::<()>::new(&engine).instantiate_pre(&component)?;
    // Pin the same budget boundary on Linux and macOS, not just repeated runs
    // on one host. Wasmtime's initialization check traps at zero remaining fuel,
    // so consuming seven fuel requires a budget of at least eight.
    for budget in [6, 7, 8, 1_000] {
        let mut store = Store::new(&engine, ());
        store.set_fuel(budget)?;
        let result = pre.instantiate_async(&mut store).await;
        if budget <= 7 {
            let error = result.expect_err("initialization must exhaust the budget");
            assert!(matches!(
                error.downcast_ref::<Trap>(),
                Some(Trap::OutOfFuel)
            ));
        } else {
            result?;
            assert_eq!(budget - store.get_fuel()?, 7);
        }
    }
    Ok(())
}

#[tokio::test]
async fn initialization_fuel_exhaustion_is_deterministic() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let err = runtime
        .prepare_call(
            &staking_address(),
            None,
            None,
            "total-staked()",
            Some(1_000),
        )
        .await
        .err()
        .expect("native initialization must exhaust a 1,000 fuel budget");
    match err {
        ExecutionError::Deterministic(e) => {
            assert!(matches!(e.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)));
        }
        other => panic!("unexpected initialization failure: {other:#}"),
    }
    assert!(runtime.stack.is_empty().await);
    Ok(())
}

async fn fund(runtime: &mut Runtime, key: &str) -> Result<Signer> {
    let signer = Signer::Id(runtime.get_or_create_identity(key).await?);
    token::issue_to(
        runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&signer),
        Decimal::from("1000"),
    )
    .await??;
    Ok(signer)
}

#[tokio::test]
async fn optional_profiling_preserves_state_gas_and_failures() -> Result<()> {
    let key = random_x_only_pubkey();
    let mut outcomes = Vec::new();
    let mut usage_reports = Vec::new();
    for mode in 0..3 {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        assert!(runtime.gauge.is_none());
        runtime.set_context(1, None, None, None).await;
        let signer = fund(&mut runtime, &key).await?;
        let gauge = match mode {
            0 => None,
            1 => Some(FuelGauge::new()),
            _ => Some(FuelGauge::with_profiling()),
        };
        runtime.gauge = gauge.clone();

        // Includes nested token transfers, deposited storage, and a contract error.
        staking::add_stake(&mut runtime, &signer, Decimal::from("10")).await??;
        assert!(
            staking::add_stake(&mut runtime, &signer, Decimal::from("-1"))
                .await?
                .is_err()
        );
        let normal_limit = runtime.gas_limit_for_non_procs;
        runtime.gas_limit_for_non_procs = 1;
        let exhausted = staking::add_stake(&mut runtime, &signer, Decimal::from("1"))
            .await
            .unwrap_err();
        assert!(
            matches!(
                exhausted.downcast_ref::<ExecutionError>(),
                Some(ExecutionError::Deterministic(_))
            ),
            "unexpected exhaustion classification: {exhausted:#}"
        );
        runtime.gas_limit_for_non_procs = normal_limit;
        staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
        assert_eq!(
            staking::get_stake(&mut runtime, &signer)
                .await?
                .unwrap()
                .stake,
            Decimal::from("11")
        );
        let balance = token::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let floor = token::floor(&mut runtime, HolderRef::from(&signer)).await?;
        let burned = token::balance(&mut runtime, HolderRef::Burner).await?;
        let conn = runtime.get_storage_conn();
        let checkpoint = get_checkpoint_by_height(&conn, 1).await?.unwrap();
        let mut rows = conn
            .query(
                "SELECT func, gas, status FROM contract_results ORDER BY id",
                (),
            )
            .await?;
        let mut results = Vec::new();
        while let Some(row) = rows.next().await? {
            results.push((
                row.get::<String>(0)?,
                row.get::<u64>(1)?,
                row.get::<String>(2)?,
            ));
        }
        if let Some(gauge) = gauge {
            let report = gauge.report()?;
            if mode == 2 {
                let profile = report.profile.unwrap();
                assert!(!profile.history.is_empty());
                assert!(profile.consumed_host_fuel > 0);
                assert!(
                    profile.consumed_host_fuel
                        <= report.usage.user_fuel
                            + report.usage.system_fuel
                            + report.usage.deposit_fuel
                );
            } else {
                assert!(report.profile.is_none());
            }
            usage_reports.push(report.usage);
        }
        outcomes.push((checkpoint, results, balance, floor, burned));
    }
    assert_eq!(outcomes[0], outcomes[1]);
    assert_eq!(outcomes[1], outcomes[2]);
    assert_eq!(usage_reports[0], usage_reports[1]);
    Ok(())
}

#[tokio::test]
#[ignore = "manual warm runtime accounting and profiling overhead measurement"]
async fn fuel_accounting_costs() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let signer = fund(&mut runtime, &random_x_only_pubkey()).await?;
    staking::add_stake(&mut runtime, &signer, Decimal::from("10")).await??;

    // Roll back between samples so each mode performs the same writes. Alternate
    // order to reduce cache/thermal bias; timings are observations, never assertions.
    for sample in 0..7 {
        for mode in if sample % 2 == 0 {
            ["disabled", "totals", "profiled"]
        } else {
            ["profiled", "totals", "disabled"]
        } {
            runtime.storage.savepoint().await?;
            let before = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            let gauge = match mode {
                "disabled" => None,
                "totals" => Some(FuelGauge::new()),
                _ => Some(FuelGauge::with_profiling()),
            };
            runtime.gauge = gauge.clone();
            let started = Instant::now();
            for _ in 0..100 {
                staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
            }
            let elapsed = started.elapsed();
            runtime.gauge = None;
            let after = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            let events = if let Some(gauge) = gauge {
                gauge
                    .report()?
                    .profile
                    .map_or(0, |profile| profile.history.len())
            } else {
                0
            };
            println!(
                "FUEL_ACCOUNTING_COST {}",
                json!({
                    "sample": sample, "mode": mode, "calls": 100,
                    "elapsed_us": elapsed.as_micros(), "retained_events": events,
                    "burned_kor": sub_decimal(after, before)?.to_string(),
                })
            );
            runtime.storage.rollback().await?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "manual transaction accounting and persistence overhead measurement"]
async fn fuel_persistence_costs() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let key = random_x_only_pubkey();
    let signer = fund(&mut runtime, &key).await?;
    staking::add_stake(&mut runtime, &signer, Decimal::from("10")).await??;
    let executor = RuntimeExecutor::new(Client::new(
        "http://127.0.0.1:1".into(),
        "".into(),
        "".into(),
    )?);
    let txs = (0..100)
        .map(|i| {
            let mut tx = new_mock_transaction(i);
            tx.inputs.push(Input {
                previous_output: OutPoint::null(),
                input_index: 0,
                x_only_pubkey: key.parse().unwrap(),
                insts: Insts::single(Inst {
                    gas_limit: runtime.gas_limit_for_non_procs,
                    kind: InstKind::Call {
                        contract: staking_address(),
                        expr: format!("add-stake({})", stdlib::to_wave_expr(Decimal::from("1"))),
                    },
                }),
            });
            tx
        })
        .collect::<Vec<_>>();
    let conn = runtime.get_storage_conn();
    for sample in 0..7 {
        for mode in if sample % 2 == 0 {
            ["disabled", "totals", "persisted"]
        } else {
            ["persisted", "totals", "disabled"]
        } {
            runtime.storage.savepoint().await?;
            let before = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            let started = Instant::now();
            for tx in &txs {
                let tx_id = insert_transaction(
                    &conn,
                    TransactionRow::builder()
                        .height(1)
                        .txid(tx.txid.to_string())
                        .build(),
                )
                .await?;
                let failures = match mode {
                    "persisted" => {
                        executor
                            .execute_transaction(&mut runtime, 1, tx_id, tx)
                            .await?
                    }
                    "totals" => {
                        let previous = runtime.start_usage();
                        let failures = executor
                            .execute_transaction_inner(&mut runtime, 1, tx_id, tx)
                            .await?;
                        runtime.finish_usage(previous)?;
                        failures
                    }
                    _ => {
                        executor
                            .execute_transaction_inner(&mut runtime, 1, tx_id, tx)
                            .await?
                    }
                };
                assert!(failures.iter().flatten().all(Option::is_none));
            }
            let elapsed = started.elapsed();
            let rows: u64 = conn
                .query("SELECT count(*) FROM transaction_execution_usage", ())
                .await?
                .next()
                .await?
                .unwrap()
                .get(0)?;
            assert_eq!(rows, if mode == "persisted" { 100 } else { 0 });
            let after = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            println!(
                "FUEL_PERSISTENCE_COST {}",
                json!({
                    "sample": sample, "mode": mode, "transactions": txs.len(), "elapsed_us": elapsed.as_micros(),
                    "usage_rows": rows, "burned_kor": sub_decimal(after, before)?.to_string(),
                })
            );
            runtime.storage.rollback().await?;
            runtime.set_context(1, None, None, None).await;
        }
    }
    Ok(())
}
