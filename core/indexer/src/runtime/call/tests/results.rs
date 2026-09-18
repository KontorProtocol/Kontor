use anyhow::Result;
use indexer_types::Payment;
use wasmtime::Trap;
use wasmtime::component::{Resource, Val};

use super::{balance, call_chain, funded, funded_in_store};
use crate::runtime::fuel::{FuelDiscriminants, FuelGauge};
use crate::runtime::numerics::sub_decimal;
use crate::runtime::token::api as token;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::wit::{Contract, Signer};
use crate::runtime::{ContractAddress, ExecutionError, Runtime};
use crate::test_utils::test_runtime;

#[tokio::test]
async fn result_encoding_obeys_exact_byte_budgets() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let values = [
        (None, 0),
        (Some(Val::Bool(true)), 1),
        (Some(Val::Option(None)), 1),
        (Some(Val::Tuple(Vec::new())), 1),
        (Some(Val::Flags(vec!["first".into(), "second".into()])), 3),
        (Some(Val::Variant("empty".into(), None)), 1),
        (
            Some(Val::Variant("full".into(), Some(Box::new(Val::U32(7))))),
            2,
        ),
        (Some(Val::Result(Ok(None))), 1),
        (Some(Val::String("é\n\0\\\"".into())), 1),
        (Some(Val::List(vec![Val::U8(0), Val::U8(255)])), 3),
        (
            Some(Val::Record(vec![
                ("missing".into(), Val::Option(None)),
                ("value".into(), Val::U64(42)),
            ])),
            3,
        ),
        (
            Some(Val::Result(Err(Some(Box::new(Val::String(
                "failure".into(),
            )))))),
            2,
        ),
    ];
    for (value, nodes) in values {
        let expected = value
            .as_ref()
            .map(Val::to_wave)
            .transpose()?
            .unwrap_or_default();
        for fallback in [false, true] {
            let results = if fallback {
                vec![Val::String(expected.clone())]
            } else {
                value.clone().into_iter().collect()
            };
            let structural = if fallback { 0 } else { nodes * 50 };
            let cost = 200 + structural + 10 * expected.len() as u64;
            for budget in [0, 199, cost - 1, cost, cost + 9] {
                let mut store = runtime.make_store(budget)?;
                let result =
                    Runtime::decode_result(fallback, Ok(Ok(())), results.clone(), &mut store).await;
                if budget < cost {
                    assert!(
                        matches!(result, Err(ExecutionError::Deterministic(ref error)) if matches!(error.downcast_ref::<Trap>(), Some(Trap::OutOfFuel))),
                        "budget {budget}, result {result:?}"
                    );
                    assert_eq!(
                        store.get_fuel()?,
                        if budget < 200 {
                            budget
                        } else {
                            (budget - 200) % 10
                        }
                    );
                } else {
                    assert_eq!(result?, expected);
                    assert_eq!(store.get_fuel()?, budget - cost);
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn init_projection_uses_the_same_output_budget_and_releases_its_resource() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let address = ContractAddress {
        name: "quoted-\"name".into(),
        height: 1,
        tx_index: 3,
    };
    let expected = stdlib::to_wave_expr(address.clone());
    let cost = 200 + 4 * 50 + 10 * expected.len() as u64;
    for budget in [cost - 1, cost] {
        let mut store = runtime.make_store(budget)?;
        let handle = store.data().table.lock().await.push(Contract {
            address: address.clone(),
        })?;
        let rep = handle.rep();
        let value = Val::Resource(handle.try_into_resource_any(&mut store)?);
        let result = Runtime::decode_result(false, Ok(Ok(())), vec![value], &mut store).await;
        if budget < cost {
            assert!(
                matches!(result, Err(ExecutionError::Deterministic(ref error)) if matches!(error.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)))
            );
            assert_eq!(store.get_fuel()?, 9);
        } else {
            assert_eq!(result?, expected);
            assert_eq!(store.get_fuel()?, 0);
        }
        assert!(
            store
                .data()
                .table
                .lock()
                .await
                .get(&Resource::<Contract>::new_borrow(rep))
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn nested_views_charge_each_result_once_with_or_without_profiling() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let core = Signer::Core(Box::new(actor.clone()));
    let expected = Val::String("é\n".repeat(128)).to_wave()?;
    let budget = runtime.fuel_limit_for_non_procs();
    for (depth, target) in chain.iter().enumerate() {
        for signer in [None, Some(&core)] {
            let mut remaining = Vec::new();
            for profile in [false, true] {
                runtime.storage.savepoint().await?;
                let gauge = profile.then(FuelGauge::with_profiling);
                runtime.gauge = gauge.clone();
                let outcome = runtime
                    .invoke(target, signer, None, "result-payload(128)", Some(budget))
                    .await?;
                runtime.gauge = None;
                assert_eq!(outcome.result?, expected);
                remaining.push(outcome.remaining_fuel);
                if let Some(gauge) = gauge {
                    let profile = gauge.report()?.profile.unwrap();
                    let stats = &profile.per_type[&FuelDiscriminants::ResultBytes];
                    assert_eq!(stats.consumed_count, (depth + 1) as u64);
                    assert_eq!(
                        stats.consumed_fuel,
                        (depth + 1) as u64 * 10 * expected.len() as u64
                    );
                    assert_eq!(
                        profile.per_type[&FuelDiscriminants::Result].consumed_fuel,
                        (depth + 1) as u64 * 200
                    );
                }
                runtime.storage.rollback().await?;
            }
            assert_eq!(remaining[0], remaining[1]);
        }
    }
    Ok(())
}

async fn paid_call(
    runtime: &Runtime,
    target: &ContractAddress,
    actor: &Signer,
    budget: u64,
    expr: &str,
) -> Result<(Result<String, ExecutionError>, u64)> {
    let payment = Payment {
        signer_id: actor.signer_id().unwrap(),
        gas_limit: runtime.gas_limit_for_non_procs,
    };
    let store = runtime.make_store(budget)?;
    let mut invocation = store.data().clone();
    let (result, store) =
        funded_in_store(&mut invocation, store, target, actor, Some(&payment), expr).await?;
    Ok((result, store.get_fuel()?))
}

#[tokio::test]
async fn result_exhaustion_rolls_back_direct_and_nested_writes() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let budget = runtime.fuel_limit_for_non_procs();
    let expected = Val::String("é\n".repeat(128)).to_wave()?;
    let floor_before = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
    for target in &chain {
        runtime.storage.savepoint().await?;
        let (result, remaining) = paid_call(
            &runtime,
            target,
            &actor,
            budget,
            "write-result-payload(128)",
        )
        .await?;
        assert_eq!(result?, expected);
        let used = budget - remaining;
        runtime.storage.rollback().await?;

        for limit in [used - 1, used] {
            runtime.storage.savepoint().await?;
            let payer_before = balance(&mut runtime, HolderRef::from(&actor)).await?;
            let burned_before = balance(&mut runtime, HolderRef::Burner).await?;
            let (result, remaining) =
                paid_call(&runtime, target, &actor, limit, "write-result-payload(128)").await?;
            let state = runtime
                .execute(None, None, &chain[0], "storage-state()")
                .await?;
            if limit < used {
                assert!(
                    matches!(result, Err(ExecutionError::Deterministic(ref error)) if matches!(error.root_cause().downcast_ref::<Trap>(), Some(Trap::OutOfFuel)))
                );
                assert!(remaining < 10);
                assert_eq!(state, "[0, 0, 0, 0]");
                assert_eq!(
                    token::floor(&mut runtime, HolderRef::from(&actor)).await?,
                    floor_before
                );
            } else {
                assert_eq!(result?, expected);
                assert_eq!(remaining, 0);
                assert_eq!(state, "[1, 0, 0, 1]");
                assert!(token::floor(&mut runtime, HolderRef::from(&actor)).await? > floor_before);
            }
            let paid = sub_decimal(
                payer_before,
                balance(&mut runtime, HolderRef::from(&actor)).await?,
            )?;
            let burned = sub_decimal(
                balance(&mut runtime, HolderRef::Burner).await?,
                burned_before,
            )?;
            assert_eq!(paid, burned);
            assert!(paid > Default::default());
            assert!(runtime.stack.is_empty().await);
            assert_eq!(
                runtime.execute(None, None, target, "succeed()").await?,
                "42"
            );
            runtime.storage.rollback().await?;
        }
    }
    Ok(())
}
