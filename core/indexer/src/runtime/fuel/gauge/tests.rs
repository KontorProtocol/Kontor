use anyhow::Result;
use bitcoin::OutPoint;
use indexer_types::{BlockRow, Input, Inst, InstKind, Insts, Payment, TransactionRow};
use libsql::params;
use wasmtime::Trap;

use super::{FuelGauge, UsageKind, record_fuel};
use crate::bitcoin_client::Client;
use crate::database::queries::{
    confirm_transaction, get_checkpoint_by_height, get_transaction_by_txid,
    get_transaction_execution_usage, insert_batch, insert_block, insert_block_execution_usage,
    insert_transaction, insert_transaction_execution_usage,
};
use crate::reactor::executor::{Executor, RuntimeExecutor};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::fuel::{Fuel, FuelDiscriminants};
use crate::runtime::numerics::sub_decimal;
use crate::runtime::pricing::Pricing;
use crate::runtime::staking::{address as staking_address, api as staking};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, Runtime, TransactionContext, native_provenance,
};
use crate::test_utils::{new_mock_block_hash, new_mock_transaction, test_runtime};

async fn fund(runtime: &mut Runtime, key: &str) -> Result<Signer> {
    let signer = Signer::Id(runtime.get_or_create_identity(key).await?);
    token::issue_to(
        runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&signer),
        Decimal::from("100"),
    )
    .await??;
    Ok(signer)
}

#[tokio::test]
async fn nested_execution_charges_child_results_once() -> Result<()> {
    let key = random_x_only_pubkey();
    let mut outcomes = Vec::new();
    for measured in [false, true] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        // Keep the original fuel ceiling but remove gas rounding, which can hide
        // a dropped child result charge smaller than one production gas unit.
        runtime.gas_limit_for_non_procs *= runtime.gas_to_fuel_multiplier;
        runtime.gas_to_fuel_multiplier = 1;
        runtime.set_context(1, None, None, None).await;
        let signer = fund(&mut runtime, &key).await?;
        let burned_before = token::balance(&mut runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        let conn = runtime.get_storage_conn();
        conn.execute("DELETE FROM contract_results", ()).await?;
        let previous = measured.then(|| runtime.start_usage());
        staking::add_stake(&mut runtime, &signer, Decimal::from("10")).await??;
        let usage = if let Some(previous) = previous {
            Some(runtime.finish_usage(previous)?)
        } else {
            None
        };
        let mut rows = conn
            .query(
                "SELECT func, gas, value FROM contract_results ORDER BY id",
                (),
            )
            .await?;
        let mut results = Vec::new();
        let mut child_result_fuel = 0;
        let mut root_gas = 0;
        while let Some(row) = rows.next().await? {
            let func: String = row.get(0)?;
            let gas: u64 = row.get(1)?;
            let value: Option<String> = row.get(2)?;
            if func == "add-stake" {
                root_gas = gas;
            } else {
                child_result_fuel += Fuel::Result.cost()
                    + Fuel::ResultCopyBytes(value.as_ref().unwrap().len() as u64).cost();
            }
            results.push((func, gas, value));
        }
        if let Some(usage) = usage {
            assert!(usage.user_fuel > 0 && usage.system_fuel > 0 && usage.deposit_fuel > 0);
            assert!(child_result_fuel > 0, "must exercise a nested procedure");
            let burned_after = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            assert_eq!(
                sub_decimal(burned_after, burned_before)?,
                runtime.pricing.execution_fee(usage.user_fuel)?,
                "the payer must pay for child results exactly once, excluding reservations"
            );
            assert_eq!(
                usage.user_fuel + usage.deposit_fuel,
                root_gas,
                "the outer result must include all child result fuel"
            );
        }
        let balance = token::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let burned = token::balance(&mut runtime, HolderRef::Burner).await?;
        let floor = token::floor(&mut runtime, HolderRef::from(&signer)).await?;
        let checkpoint = get_checkpoint_by_height(&conn, 1).await?;
        outcomes.push((results, balance, burned, floor, checkpoint));
    }
    assert_eq!(outcomes[0], outcomes[1]);
    Ok(())
}

#[tokio::test]
async fn preparation_failures_and_rejected_charges_report_consumed_work() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let signer = fund(&mut runtime, &random_x_only_pubkey()).await?;
    let payment = Payment {
        signer_id: signer.signer_id().unwrap(),
        gas_limit: 100_000,
    };
    for (expr, limit, has_work) in [
        ("no-such-function()", 100_000, true),
        ("add-stake(\"1\")", 1, true),
        ("(", 100_000, true),
    ] {
        let previous = runtime.start_usage();
        assert!(
            runtime
                .execute(
                    Some(&signer),
                    Some(Payment {
                        gas_limit: limit,
                        ..payment.clone()
                    }),
                    &staking_address(),
                    expr
                )
                .await
                .is_err()
        );
        let usage = runtime.finish_usage(previous)?;
        assert_eq!(usage.user_fuel > 0, has_work);
        assert!(usage.system_fuel > 0);
        assert_eq!(usage.deposit_fuel, 0);
    }
    let previous = runtime.start_usage();
    let absent = ContractAddress {
        name: "absent".into(),
        height: 1,
        tx_index: 0,
    };
    assert!(
        runtime
            .execute(Some(&signer), Some(payment), &absent, "init()")
            .await
            .is_err()
    );
    let usage = runtime.finish_usage(previous)?;
    assert_eq!(
        usage.user_fuel,
        Fuel::WaveInputBytes(6).cost() + Fuel::ContractNameBytes(6).cost()
    );
    assert!(usage.system_fuel > 0);
    assert_eq!(usage.deposit_fuel, 0);

    let unpaid = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    let previous = runtime.start_usage();
    assert!(
        staking::add_stake(&mut runtime, &unpaid, Decimal::from("1"))
            .await
            .is_err()
    );
    let usage = runtime.finish_usage(previous)?;
    assert_eq!(usage.user_fuel, 0);
    assert!(usage.system_fuel > 0);
    assert_eq!(usage.deposit_fuel, 0);

    let previous = runtime.start_usage();
    runtime.usage_kind = UsageKind::User;
    let mut store = runtime.make_store(100)?;
    Fuel::SignerToString.consume_with_store(&mut store)?;
    let error = Fuel::Set(100).consume_with_store(&mut store).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<Trap>(),
        Some(Trap::OutOfFuel)
    ));
    record_fuel(&mut store)?;
    assert_eq!(
        runtime.finish_usage(previous)?.user_fuel,
        Fuel::SignerToString.cost()
    );
    Ok(())
}

#[tokio::test]
async fn publishing_traps_and_reverted_deposits_are_measured() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    let signer = fund(&mut runtime, &random_x_only_pubkey()).await?;
    let payment = Payment {
        signer_id: signer.signer_id().unwrap(),
        gas_limit: 100_000,
    };
    let provenance = native_provenance()?;
    let previous = runtime.start_usage();
    assert!(
        runtime
            .publish(
                &signer,
                Payment {
                    gas_limit: 1,
                    ..payment.clone()
                },
                "failed-init",
                include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br"),
                &provenance
            )
            .await
            .is_err()
    );
    let usage = runtime.finish_usage(previous)?;
    assert!(usage.user_fuel > 0);
    assert_eq!(usage.deposit_fuel, 0);
    assert!(
        runtime
            .storage
            .contract_id(&ContractAddress {
                name: "failed-init".into(),
                height: 1,
                tx_index: 0
            })
            .await?
            .is_none()
    );
    let previous = runtime.start_usage();
    runtime
        .publish(
            &signer,
            payment.clone(),
            "usage-errors",
            include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br"),
            &provenance,
        )
        .await?;
    let usage = runtime.finish_usage(previous)?;
    assert!(usage.user_fuel > 0 && usage.system_fuel > 0 && usage.deposit_fuel > 0);
    let address = ContractAddress {
        name: "usage-errors".into(),
        height: 1,
        tx_index: 0,
    };
    for expr in ["trap-out-of-fuel()", "trap-panic()", "scan-compound(false)"] {
        let previous = runtime.start_usage();
        let result = runtime
            .execute(Some(&signer), Some(payment.clone()), &address, expr)
            .await;
        assert!(
            matches!(result, Err(ExecutionError::Deterministic(_))),
            "{expr}: {result:?}"
        );
        let usage = runtime.finish_usage(previous)?;
        assert!(usage.user_fuel > 0 && usage.system_fuel > 0);
        if expr == "trap-out-of-fuel()" {
            assert_eq!(
                usage.user_fuel,
                payment.gas_limit * runtime.gas_to_fuel_multiplier
            );
        }
        if expr == "scan-compound(false)" {
            assert!(
                usage.deposit_fuel > 0,
                "reverted writes still consumed reservations"
            );
            assert_eq!(
                runtime
                    .execute(None, None, &address, "storage-state()")
                    .await?,
                "[0, 0, 0, 0]"
            );
        }
    }
    let previous = runtime.start_usage();
    assert!(
        staking::add_stake(&mut runtime, &signer, Decimal::from("-1"))
            .await?
            .is_err()
    );
    assert!(runtime.finish_usage(previous)?.user_fuel > 0);
    let previous = runtime.start_usage();
    assert!(
        runtime
            .publish(&signer, payment, "bad-wasm", &[255; 64], &provenance)
            .await
            .is_err()
    );
    let usage = runtime.finish_usage(previous)?;
    assert_eq!(usage.user_fuel, 0);
    assert!(usage.system_fuel > 0);
    assert_eq!(usage.deposit_fuel, 0);
    Ok(())
}

#[tokio::test]
async fn persisted_usage_follows_confirmation_rollback_and_replay() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let signer = fund(&mut runtime, &random_x_only_pubkey()).await?;
    let conn = runtime.get_storage_conn();
    insert_batch(&conn, 1, 2, &new_mock_block_hash(2).to_string(), &[], false).await?;
    let mut expected = None;
    for replay in [false, true] {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(2)
                .hash(new_mock_block_hash(2))
                .relevant(true)
                .build(),
        )
        .await?;
        let tx_id = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(2)
                .batch_height(1)
                .txid("usage-tx".into())
                .build(),
        )
        .await?;
        runtime
            .set_context(
                2,
                Some(TransactionContext::builder().tx_id(tx_id).build()),
                None,
                None,
            )
            .await;
        let previous = runtime.start_usage();
        staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
        let usage = runtime.finish_usage(previous)?;
        let state_checkpoint = get_checkpoint_by_height(&conn, 2).await?;
        insert_transaction_execution_usage(&conn, tx_id, usage).await?;
        assert!(
            insert_transaction_execution_usage(&conn, tx_id, usage)
                .await
                .is_err(),
            "duplicate execution must not silently accumulate"
        );
        let previous = runtime.start_usage();
        token::total_supply(&mut runtime).await?;
        let maintenance = runtime.finish_usage(previous)?;
        insert_block_execution_usage(&conn, 2, maintenance).await?;
        assert_eq!(get_checkpoint_by_height(&conn, 2).await?, state_checkpoint);
        insert_block(
            &conn,
            BlockRow::builder()
                .height(3)
                .hash(new_mock_block_hash(3))
                .relevant(true)
                .build(),
        )
        .await?;
        confirm_transaction(&conn, "usage-tx", 3, 0).await?;
        runtime.storage.rollback_with_footprint(2).await?;
        assert!(
            get_transaction_by_txid(&conn, "usage-tx")
                .await?
                .unwrap()
                .confirmed_height
                .is_none()
        );
        let mut rows = conn.query("SELECT user_fuel, system_fuel, deposit_fuel FROM transaction_execution_usage WHERE tx_id = ?", params![tx_id]).await?;
        let row = rows.next().await?.unwrap();
        assert_eq!(
            (row.get::<u64>(0)?, row.get::<u64>(1)?, row.get::<u64>(2)?),
            (usage.user_fuel, usage.system_fuel, usage.deposit_fuel)
        );
        let checkpoint = get_checkpoint_by_height(&conn, 2).await?;
        let actual = (usage, maintenance, checkpoint);
        if replay {
            assert_eq!(expected, Some(actual));
        } else {
            expected = Some(actual);
        }
        runtime.storage.rollback_with_footprint(1).await?;
        runtime.set_context(1, None, None, None).await;
        for table in ["transaction_execution_usage", "block_execution_usage"] {
            assert_eq!(
                conn.query(&format!("SELECT count(*) FROM {table}"), ())
                    .await?
                    .next()
                    .await?
                    .unwrap()
                    .get::<u64>(0)?,
                0
            );
        }
    }
    Ok(())
}

#[test]
fn overflow_is_reported_instead_of_wrapping() -> Result<()> {
    let meter = FuelGauge::default();
    meter.record(UsageKind::User, u64::MAX)?;
    assert!(meter.record(UsageKind::User, 1).is_err());
    assert_eq!(meter.report()?.usage.user_fuel, u64::MAX);
    Ok(())
}

#[tokio::test]
async fn nested_preparation_failure_is_charged_to_parent() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    let signer = fund(&mut runtime, &random_x_only_pubkey()).await?;
    runtime
        .storage
        .insert_contract(
            "usage-proxy",
            include_bytes!("../../../../../../test-contracts/binaries/proxy.wasm.br"),
        )
        .await?;
    let proxy = ContractAddress {
        name: "usage-proxy".into(),
        height: 1,
        tx_index: 0,
    };
    runtime.execute_api(Some(&signer), &proxy, "init()").await?;
    runtime
        .execute_api(
            Some(&signer),
            &proxy,
            &format!(
                "set-contract-address({})",
                stdlib::to_wave_expr(staking_address())
            ),
        )
        .await?;
    let previous = runtime.start_usage();
    assert!(
        runtime
            .execute_api(Some(&signer), &staking_address(), "no-such-function()")
            .await
            .is_err()
    );
    let child = runtime.finish_usage(previous)?;
    assert!(child.user_fuel > 0);
    let burned_before = token::balance(&mut runtime, HolderRef::Burner)
        .await?
        .unwrap_or_default();
    let previous = runtime.start_usage();
    let error = runtime
        .execute_api(Some(&signer), &proxy, "no-such-function()")
        .await
        .unwrap_err();
    assert!(matches!(error, ExecutionError::Deterministic(_)));
    let nested = runtime.finish_usage(previous)?;
    assert!(nested.user_fuel > child.user_fuel);
    assert!(nested.system_fuel > 0);
    assert_eq!(nested.deposit_fuel, 0);
    assert!(runtime.stack.is_empty().await);
    let burned_after = token::balance(&mut runtime, HolderRef::Burner)
        .await?
        .unwrap_or_default();
    let expected_gas = nested.user_fuel.div_ceil(runtime.gas_to_fuel_multiplier);
    assert_eq!(
        sub_decimal(burned_after, burned_before)?,
        runtime.pricing.execution_fee(expected_gas)?,
        "failed child preparation must still be paid for by the outer operation"
    );
    let conn = runtime.get_storage_conn();
    let mut rows = conn
        .query(
            "SELECT gas FROM contract_results WHERE func = 'fallback' ORDER BY id DESC LIMIT 1",
            (),
        )
        .await?;
    let billed: u64 = rows.next().await?.unwrap().get(0)?;
    assert_eq!(expected_gas, billed);
    Ok(())
}

#[tokio::test]
async fn nested_result_fuel_cannot_exceed_the_signed_budget() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.gas_limit_for_non_procs *= runtime.gas_to_fuel_multiplier;
    runtime.gas_to_fuel_multiplier = 1;
    runtime.set_context(1, None, None, None).await;
    let signer = fund(&mut runtime, &random_x_only_pubkey()).await?;
    staking::add_stake(&mut runtime, &signer, Decimal::from("10")).await??;

    // Measure the same operation on the same starting state. Use the full raw
    // budget (including reservations), then probe its exact success boundary.
    runtime.storage.savepoint().await?;
    let previous = runtime.start_usage();
    staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
    let baseline = runtime.finish_usage(previous)?;
    runtime.storage.rollback().await?;
    assert!(baseline.deposit_fuel > 0);
    let required = baseline.user_fuel + baseline.deposit_fuel;
    let mut outcomes = Vec::new();
    for budget in [required, required - 1] {
        runtime.set_context(1, None, None, None).await;
        runtime.storage.savepoint().await?;
        let previous = runtime.start_usage();
        let result = runtime
            .execute(
                Some(&signer),
                Some(Payment {
                    signer_id: signer.signer_id().unwrap(),
                    gas_limit: budget,
                }),
                &staking_address(),
                &format!("add-stake({})", stdlib::to_wave_expr(Decimal::from("1"))),
            )
            .await;
        let usage = runtime.finish_usage(previous)?;
        assert!(runtime.stack.is_empty().await);
        let stake = staking::get_stake(&mut runtime, &signer)
            .await?
            .unwrap()
            .stake;
        outcomes.push((result, usage, stake));
        runtime.storage.rollback().await?;
    }
    let (success, usage, stake) = &outcomes[0];
    assert!(success.is_ok(), "the full budget must suffice: {success:?}");
    assert_eq!(usage.user_fuel + usage.deposit_fuel, required);
    assert_eq!(*stake, Decimal::from("11"));

    let (short, usage, stake) = &outcomes[1];
    assert!(
        matches!(short, Err(ExecutionError::Deterministic(error))
            if matches!(error.downcast_ref::<Trap>(), Some(Trap::OutOfFuel))),
        "one fuel below the required budget must exhaust: {short:?}"
    );
    assert!(usage.user_fuel + usage.deposit_fuel < required);
    assert_eq!(
        *stake,
        Decimal::from("10"),
        "exhaustion must revert the stake change"
    );
    Ok(())
}

#[tokio::test]
async fn transaction_scope_collects_operations_and_discards_abandoned_execution() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let key = random_x_only_pubkey();
    fund(&mut runtime, &key).await?;
    // execute_transaction performs no RPC; the unused client needs no node.
    let executor = RuntimeExecutor::new(Client::new(
        "http://127.0.0.1:1".into(),
        "".into(),
        "".into(),
    )?);
    let mut tx = new_mock_transaction(42);
    tx.inputs.push(Input {
        previous_output: OutPoint::null(),
        input_index: 0,
        x_only_pubkey: key.parse()?,
        insts: Insts::direct(vec![
            Inst {
                gas_limit: 100_000,
                kind: InstKind::Call {
                    contract: staking_address(),
                    expr: format!("add-stake({})", stdlib::to_wave_expr(Decimal::from("1"))),
                },
            },
            Inst {
                gas_limit: 100_000,
                kind: InstKind::Call {
                    contract: staking_address(),
                    expr: "no-such-function()".into(),
                },
            },
            Inst {
                gas_limit: 1,
                kind: InstKind::Call {
                    contract: staking_address(),
                    expr: format!("add-stake({})", stdlib::to_wave_expr(Decimal::from("1"))),
                },
            },
        ]),
    });
    let conn = runtime.get_storage_conn();
    let mut expected = None;
    for _ in 0..2 {
        runtime.storage.savepoint().await?;
        let tx_id = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(1)
                .txid(tx.txid.to_string())
                .build(),
        )
        .await?;
        assert!(
            get_transaction_execution_usage(&conn, tx_id)
                .await?
                .is_none()
        );
        let failures = executor
            .execute_transaction(&mut runtime, 1, tx_id, &tx)
            .await?;
        assert!(failures[0][0].is_none(), "{:?}", failures[0][0]);
        assert!(failures[0][1].is_some() && failures[0][2].is_some());
        let usage = get_transaction_execution_usage(&conn, tx_id)
            .await?
            .unwrap();
        assert!(usage.user_fuel > 0 && usage.system_fuel > 0 && usage.deposit_fuel > 0);
        if let Some(expected) = expected {
            assert_eq!(usage, expected);
        }
        expected = Some(usage);
        assert!(runtime.gauge.is_none());
        runtime.storage.rollback().await?;
        assert!(
            get_transaction_execution_usage(&conn, tx_id)
                .await?
                .is_none()
        );
    }
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    runtime
        .storage
        .insert_contract(
            "infra-errors",
            include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br"),
        )
        .await?;
    tx.inputs[0].insts = Insts::single(Inst {
        gas_limit: 100_000,
        kind: InstKind::Call {
            contract: ContractAddress {
                name: "infra-errors".into(),
                height: 1,
                tx_index: 0,
            },
            expr: "host-error()".into(),
        },
    });
    runtime.storage.savepoint().await?;
    let tx_id = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .txid(tx.txid.to_string())
            .build(),
    )
    .await?;
    assert!(
        executor
            .execute_transaction(&mut runtime, 1, tx_id, &tx)
            .await
            .is_err()
    );
    assert!(runtime.gauge.is_none());
    assert!(
        get_transaction_execution_usage(&conn, tx_id)
            .await?
            .is_none()
    );
    runtime.storage.rollback().await?;
    Ok(())
}

#[tokio::test]
async fn profile_distinguishes_rejected_charges_from_consumed_fuel() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let gauge = FuelGauge::with_profiling();
    runtime.gauge = Some(gauge.clone());
    runtime.usage_kind = UsageKind::User;
    let mut store = runtime.make_store(100)?;
    Fuel::SignerToString.consume_with_store(&mut store)?;
    assert!(Fuel::Set(100).consume_with_store(&mut store).is_err());
    record_fuel(&mut store)?;
    let report = gauge.report()?;
    assert_eq!(report.usage.user_fuel, 50);
    let profile = report.profile.unwrap();
    assert_eq!(profile.consumed_host_fuel, 50);
    assert_eq!(
        profile.per_type[&FuelDiscriminants::SignerToString].consumed_count,
        1
    );
    let rejected = &profile.per_type[&FuelDiscriminants::Set];
    assert_eq!(rejected.consumed_fuel, 0);
    assert_eq!(rejected.consumed_count, 0);
    assert_eq!(rejected.rejected_count, 1);
    assert_eq!(rejected.rejected_fuel, Fuel::Set(100).cost());
    assert!(profile.history[0].consumed);
    assert!(!profile.history[1].consumed);

    runtime.gauge = None;
    runtime.set_context(1, None, None, None).await;
    let signer = fund(&mut runtime, &random_x_only_pubkey()).await?;
    runtime.pricing = Pricing::new(Decimal::from("0.000000001"), 1_000_000)?;
    let gauge = FuelGauge::with_profiling();
    runtime.gauge = Some(gauge.clone());
    assert!(
        staking::add_stake(&mut runtime, &signer, Decimal::from("1"))
            .await
            .is_err()
    );
    let report = gauge.report()?;
    assert!(report.usage.user_fuel > 0 && report.usage.system_fuel > 0);
    assert_eq!(report.usage.deposit_fuel, 0);
    let profile = report.profile.unwrap();
    let deposits = &profile.per_type[&FuelDiscriminants::Deposit];
    assert_eq!(deposits.consumed_count, 0);
    assert_eq!(deposits.rejected_count, 1);
    assert!(deposits.rejected_fuel > 0);
    assert_eq!(
        profile
            .history
            .iter()
            .filter(|charge| charge.consumed)
            .map(|charge| charge.fuel)
            .sum::<u64>(),
        profile.consumed_host_fuel
    );
    Ok(())
}

#[tokio::test]
async fn scope_reports_do_not_reset_with_transaction_context() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let signer = fund(&mut runtime, &random_x_only_pubkey()).await?;
    let gauge = FuelGauge::with_profiling();
    runtime.gauge = Some(gauge.clone());
    staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
    let first = gauge.report()?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    assert_eq!(gauge.report()?.usage, first.usage);
    staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
    let second = gauge.report()?;
    assert!(second.usage.user_fuel > first.usage.user_fuel);
    assert!(second.profile.as_ref().unwrap().history.len() > first.profile.unwrap().history.len());
    let previous = runtime.start_usage();
    staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
    let inner = runtime.finish_usage(previous)?;
    assert!(inner.user_fuel > 0);
    assert_eq!(gauge.report()?.usage, second.usage);
    staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
    assert!(gauge.report()?.usage.user_fuel > second.usage.user_fuel);
    Ok(())
}
