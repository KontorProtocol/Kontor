use std::sync::Arc;

use anyhow::Result;
use indexer_types::Payment;
use libsql::params;
use wasmtime::Store;

use super::CallOutcome;

use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::fuel::UsageKind;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ContractAddress, Decimal, ExecutionError, Runtime, TransactionContext};
use crate::test_utils::test_runtime;

mod abi_errors;
mod conversion;
mod conversion_parity;
mod conversion_work;
mod errors;
mod preparation_fees;
mod results;
mod wave_costs;

async fn funded(runtime: &mut Runtime) -> Result<Signer> {
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    token::issue_to(
        runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&signer),
        Decimal::from("100"),
    )
    .await??;
    Ok(signer)
}

async fn call_chain(runtime: &mut Runtime, signer: &Signer) -> Result<Vec<ContractAddress>> {
    let mut addresses: Vec<ContractAddress> = Vec::new();
    for (index, name) in ["lifecycle-errors", "lifecycle-proxy", "lifecycle-outer"]
        .into_iter()
        .enumerate()
    {
        runtime
            .set_context(
                1,
                Some(TransactionContext::builder().tx_index(index as u32).build()),
                None,
                None,
            )
            .await;
        let bytes = if index == 0 {
            include_bytes!("../../../../../test-contracts/binaries/error_test.wasm.br").as_slice()
        } else {
            include_bytes!("../../../../../test-contracts/binaries/proxy.wasm.br").as_slice()
        };
        runtime.storage.insert_contract(name, bytes).await?;
        let address = ContractAddress {
            name: name.into(),
            height: 1,
            tx_index: index as u32,
        };
        runtime
            .execute_api(Some(signer), &address, "init()")
            .await?;
        if let Some(child) = addresses.last() {
            runtime
                .execute_api(
                    Some(signer),
                    &address,
                    &format!(
                        "set-contract-address({})",
                        stdlib::to_wave_expr(child.clone())
                    ),
                )
                .await?;
        }
        addresses.push(address);
    }
    runtime.set_context(1, None, None, None).await;
    Ok(addresses)
}

async fn balance(runtime: &mut Runtime, holder: HolderRef) -> Result<Decimal> {
    Ok(token::balance(runtime, holder).await?.unwrap_or_default())
}

#[derive(Debug)]
enum Expected {
    Value(&'static str),
    ContractError,
    Deterministic,
    #[cfg(feature = "testing")]
    Infrastructure,
}

#[tokio::test]
async fn nested_outcomes_preserve_state_refunds_and_cleanup() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let payer = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let conn = runtime.get_storage_conn();
    let cases = [
        ("succeed()", Expected::Value("42")),
        ("primitive-entries()", Expected::Value("")),
        ("contract-error()", Expected::ContractError),
        ("trap-panic()", Expected::Deterministic),
        ("trap-out-of-fuel()", Expected::Deterministic),
        ("scan-compound(false)", Expected::Deterministic),
        #[cfg(feature = "testing")]
        ("host-error()", Expected::Infrastructure),
        #[cfg(feature = "testing")]
        ("host-panic()", Expected::Infrastructure),
    ];
    for (depth, target) in chain.iter().enumerate() {
        for (expr, expected) in &cases {
            // Each case starts from the same state. The outer savepoint models
            // the transaction boundary that discards infrastructure failures.
            runtime.storage.savepoint().await?;
            conn.execute("DELETE FROM contract_results", ()).await?;
            let savepoint = runtime.storage.savepoint_stack.peek().await;
            let actor_before = balance(&mut runtime, HolderRef::from(&actor)).await?;
            let payer_before = balance(&mut runtime, HolderRef::from(&payer)).await?;
            let burned_before = balance(&mut runtime, HolderRef::Burner).await?;
            let supply_before = token::total_supply(&mut runtime).await?;
            let floor_before = token::floor(&mut runtime, HolderRef::from(&payer)).await?;
            let previous = runtime.start_usage();
            let result = runtime
                .execute(
                    Some(&actor),
                    Some(Payment {
                        signer_id: payer.signer_id().unwrap(),
                        gas_limit: 100_000,
                    }),
                    target,
                    expr,
                )
                .await;
            let usage = runtime.finish_usage(previous)?;
            match expected {
                Expected::Value(value) => assert_eq!(result.as_ref().unwrap(), value),
                Expected::ContractError => assert!(result.as_ref().unwrap().starts_with("err(")),
                Expected::Deterministic => assert!(
                    matches!(result, Err(ExecutionError::Deterministic(_))),
                    "depth={depth} {expr}: {result:?}"
                ),
                #[cfg(feature = "testing")]
                Expected::Infrastructure => assert!(
                    matches!(result, Err(ExecutionError::NonDeterministic(_))),
                    "depth={depth} {expr}: {result:?}"
                ),
            }
            assert!(runtime.stack.is_empty().await, "depth={depth} {expr}");
            assert_eq!(runtime.storage.savepoint_stack.peek().await, savepoint);

            let state = runtime
                .execute(None, None, &chain[0], "storage-state()")
                .await?;
            if *expr == "primitive-entries()" {
                assert_ne!(state, "[0, 0, 0, 0]");
                assert!(token::floor(&mut runtime, HolderRef::from(&payer)).await? > floor_before);
            } else {
                assert_eq!(state, "[0, 0, 0, 0]", "depth={depth} {expr}");
                assert_eq!(
                    token::floor(&mut runtime, HolderRef::from(&payer)).await?,
                    floor_before
                );
            }
            assert_eq!(
                balance(&mut runtime, HolderRef::from(&actor)).await?,
                actor_before
            );
            // Infrastructure failures discard the whole transaction. Its
            // provisional fee/result writes are not a committed guarantee.
            if !matches!(result, Err(ExecutionError::NonDeterministic(_))) {
                let burned = sub_decimal(
                    balance(&mut runtime, HolderRef::Burner).await?,
                    burned_before,
                )?;
                let paid = sub_decimal(
                    payer_before,
                    balance(&mut runtime, HolderRef::from(&payer)).await?,
                )?;
                assert_eq!(paid, burned, "escrow refund: depth={depth} {expr}");
                assert_eq!(
                    balance(&mut runtime, HolderRef::Core).await?,
                    Decimal::default()
                );
                assert_eq!(
                    sub_decimal(supply_before, token::total_supply(&mut runtime).await?)?,
                    burned
                );

                let contract_id = runtime.storage.contract_id(target).await?.unwrap();
                let mut rows = conn.query(
                "SELECT gas, signer_id, payer_signer_id, value, status FROM contract_results WHERE contract_id = ? ORDER BY id",
                params![contract_id],
            ).await?;
                let row = rows.next().await?.expect("outer call result");
                assert_eq!(row.get::<u64>(1)?, actor.signer_id().unwrap());
                assert_eq!(row.get::<u64>(2)?, payer.signer_id().unwrap());
                assert_eq!(row.get::<Option<String>>(3)?, result.as_ref().ok().cloned());
                if result.is_ok() {
                    assert_eq!(
                        row.get::<String>(4)?,
                        if matches!(expected, Expected::ContractError) {
                            "ContractErr"
                        } else {
                            "Ok"
                        }
                    );
                }
                let gas: u64 = row.get(0)?;
                let reserved = usage.deposit_fuel / runtime.gas_to_fuel_multiplier;
                assert!(gas >= reserved);
                assert_eq!(
                    paid,
                    runtime.pricing.execution_fee(gas - reserved)?,
                    "refund reservations even on rollback: depth={depth} {expr}"
                );
                assert!(rows.next().await?.is_none(), "duplicate outer result");
            }
            runtime.storage.rollback().await?;
            assert_eq!(
                balance(&mut runtime, HolderRef::from(&payer)).await?,
                payer_before
            );
            assert_eq!(
                balance(&mut runtime, HolderRef::Burner).await?,
                burned_before
            );
            assert_eq!(token::total_supply(&mut runtime).await?, supply_before);
            assert_eq!(
                runtime.execute(None, None, target, "succeed()").await?,
                "42"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn unsigned_nested_views_do_not_charge_fees_or_gain_write_authority() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let conn = runtime.get_storage_conn();
    conn.execute("DELETE FROM contract_results", ()).await?;
    let before = balance(&mut runtime, HolderRef::from(&actor)).await?;
    let burned = balance(&mut runtime, HolderRef::Burner).await?;
    for target in &chain {
        assert_eq!(
            runtime.execute(None, None, target, "succeed()").await?,
            "42"
        );
        let error = runtime
            .execute(None, None, target, "primitive-entries()")
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutionError::Deterministic(_)));
        assert!(runtime.stack.is_empty().await);
        assert_eq!(
            runtime
                .execute(None, None, &chain[0], "storage-state()")
                .await?,
            "[0, 0, 0, 0]"
        );
    }
    assert_eq!(
        balance(&mut runtime, HolderRef::from(&actor)).await?,
        before
    );
    assert_eq!(balance(&mut runtime, HolderRef::Burner).await?, burned);
    assert_eq!(
        conn.query("SELECT count(*) FROM contract_results", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<u64>(0)?,
        0
    );
    Ok(())
}

#[tokio::test]
async fn core_calls_bypass_user_escrow_and_user_gas_limit() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let before = balance(&mut runtime, HolderRef::from(&actor)).await?;
    let burned = balance(&mut runtime, HolderRef::Burner).await?;
    let supply = token::total_supply(&mut runtime).await?;
    runtime.gas_limit_for_non_procs = 1;
    token::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&actor),
        Decimal::from("1"),
    )
    .await??;
    assert_eq!(
        sub_decimal(
            balance(&mut runtime, HolderRef::from(&actor)).await?,
            before
        )?,
        Decimal::from("1")
    );
    assert_eq!(
        sub_decimal(token::total_supply(&mut runtime).await?, supply)?,
        Decimal::from("1")
    );
    assert_eq!(balance(&mut runtime, HolderRef::Burner).await?, burned);
    assert_eq!(
        balance(&mut runtime, HolderRef::Core).await?,
        Decimal::default()
    );
    assert!(runtime.stack.is_empty().await);
    Ok(())
}

#[tokio::test]
async fn recursive_calls_are_rejected_and_the_runtime_can_be_reused() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    runtime
        .execute_api(
            Some(&actor),
            &chain[1],
            &format!(
                "set-contract-address({})",
                stdlib::to_wave_expr(chain[2].clone())
            ),
        )
        .await?;
    runtime.storage.savepoint().await?;
    let savepoint = runtime.storage.savepoint_stack.peek().await;
    let error = runtime
        .execute(None, None, &chain[2], "succeed()")
        .await
        .unwrap_err();
    assert!(matches!(error, ExecutionError::Deterministic(_)));
    assert!(format!("{error:#}").contains("reentrancy prevented"));
    assert!(runtime.stack.is_empty().await);
    assert_eq!(runtime.storage.savepoint_stack.peek().await, savepoint);
    assert_eq!(
        runtime
            .execute(None, None, &chain[0], "storage-state()")
            .await?,
        "[0, 0, 0, 0]"
    );
    runtime
        .execute_api(
            Some(&actor),
            &chain[1],
            &format!(
                "set-contract-address({})",
                stdlib::to_wave_expr(chain[0].clone())
            ),
        )
        .await?;
    assert_eq!(
        runtime.execute(None, None, &chain[2], "succeed()").await?,
        "42"
    );
    runtime.storage.rollback().await?;
    Ok(())
}

#[tokio::test]
async fn storage_traps_release_call_owned_host_resources() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    for (depth, target) in chain.iter().enumerate() {
        let resources = runtime.table.lock().await.iter_mut().count();
        let error = runtime
            .execute_api(Some(&actor), target, "scan-compound(false)")
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutionError::Deterministic(_)));
        assert!(runtime.stack.is_empty().await);
        assert_eq!(
            runtime
                .execute(None, None, &chain[0], "storage-state()")
                .await?,
            "[0, 0, 0, 0]"
        );
        assert_eq!(
            runtime.table.lock().await.iter_mut().count(),
            resources,
            "failed invocation must release its host resources: depth={depth}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn nested_success_releases_call_owned_host_resources() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    for target in &chain[1..] {
        let resources = runtime.table.lock().await.iter_mut().count();
        assert_eq!(
            runtime
                .execute_api(Some(&actor), target, "succeed()")
                .await?,
            "42"
        );
        assert!(runtime.stack.is_empty().await);
        assert_eq!(
            runtime.table.lock().await.iter_mut().count(),
            resources,
            "successful invocation must release its host resources: {target}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn invocation_tables_drop_resources_without_invalidating_parent_handles() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let unpaid = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    let payment = Payment {
        signer_id: actor.signer_id().unwrap(),
        gas_limit: runtime.gas_limit_for_non_procs,
    };
    let unfunded_payment = Payment {
        signer_id: unpaid.signer_id().unwrap(),
        ..payment.clone()
    };
    let parent_handle = runtime.table.lock().await.push(42_u64)?;
    let cases = [
        ("succeed()", Some(&payment), true),
        ("primitive-entries()", Some(&payment), true),
        ("scan-compound(false)", Some(&payment), false),
        ("trap-panic()", Some(&payment), false),
        ("missing()", Some(&payment), false),
        ("primitive-entries()", None, false),
        ("primitive-entries()", Some(&unfunded_payment), false),
        #[cfg(feature = "testing")]
        ("host-panic()", Some(&payment), false),
    ];
    for target in &chain {
        for (expr, payment, succeeds) in cases {
            runtime.storage.savepoint().await?;
            let mut store = runtime.make_store(runtime.fuel_limit_for_non_procs())?;
            store.data_mut().usage_kind = UsageKind::User;
            let table = Arc::downgrade(&store.data().table);
            assert!(!Arc::ptr_eq(&runtime.table, &store.data().table));
            // An owned resource deliberately left live must die with the call,
            // even on preparation errors that never enter the guest function.
            let payload = Arc::new(());
            store.data().table.lock().await.push(payload.clone())?;
            let mut invocation = store.data().clone();
            let (result, store) =
                funded_in_store(&mut invocation, store, target, &actor, payment, expr).await?;
            assert_eq!(result.is_ok(), succeeds, "{target}: {expr}: {result:?}");
            assert!(runtime.stack.is_empty().await);
            drop(invocation);
            drop(store);
            assert!(
                table.upgrade().is_none(),
                "invocation table retained: {target}: {expr}"
            );
            assert_eq!(
                Arc::strong_count(&payload),
                1,
                "call-owned resource retained"
            );
            assert_eq!(*runtime.table.lock().await.get(&parent_handle)?, 42);
            runtime.storage.rollback().await?;
        }
    }
    runtime.table.lock().await.delete(parent_handle)?;
    Ok(())
}

// Retain a caller-supplied Store for exact-fuel and resource-lifetime assertions,
// while exercising the same payment boundary as a normal top-level invocation.
async fn funded_in_store(
    runtime: &mut Runtime,
    store: Store<Runtime>,
    target: &ContractAddress,
    signer: &Signer,
    payment: Option<&Payment>,
    expr: &str,
) -> Result<(Result<String, ExecutionError>, Store<Runtime>), ExecutionError> {
    if !signer.is_core()
        && let Some(payment) = payment
    {
        let starting_fuel = store.get_fuel().map_err(anyhow::Error::from)?;
        let mut slot = Some(store);
        let outcome = runtime
            .with_payment(payment, starting_fuel, async |runtime| {
                let (result, store) = runtime
                    .invoke_in_store(
                        slot.take().unwrap(),
                        target,
                        Some(signer),
                        Some(payment),
                        expr,
                        false,
                    )
                    .await?;
                let remaining_fuel = store.get_fuel().map_err(anyhow::Error::from)?;
                slot = Some(store);
                Ok(CallOutcome {
                    result,
                    remaining_fuel,
                })
            })
            .await?;
        Ok((outcome.result, slot.unwrap()))
    } else {
        runtime
            .invoke_in_store(store, target, Some(signer), payment, expr, false)
            .await
    }
}
