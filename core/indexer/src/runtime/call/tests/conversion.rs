use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::Result;
use indexer_types::Payment;
use wasmtime::component::{Component, Linker, Val};
use wasmtime::{AsContextMut, CallHook, Error as WasmtimeError, Trap};

use super::{call_chain, funded, funded_in_store};
use crate::runtime::conversion_probe::{Policy, Probe};
use crate::runtime::wit::Signer;
use crate::runtime::{ContractAddress, ExecutionError, Runtime};
use crate::test_utils::test_runtime;

const BUDGET: u64 = 100_000_000;

#[tokio::test]
async fn abi_dynamic_allowance_tracks_fuel_across_actual_suspension() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.conversion_probe = Some(Probe::new(Policy::Dynamic(10), true));
    let component = Component::new(
        &runtime.engine,
        include_str!("fixtures/abi-suspended-import.wat"),
    )?;
    for second_length in [8, 24] {
        let bodies = Arc::new(AtomicUsize::new(0));
        let seen = bodies.clone();
        let mut linker = Linker::<Runtime>::new(&runtime.engine);
        linker
            .root()
            .func_wrap_concurrent("accept", move |accessor, (_input,): (String,)| {
                let seen = seen.clone();
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    accessor.with(|mut access| {
                        let fuel = access.as_context_mut().get_fuel()?;
                        access
                            .as_context_mut()
                            .set_fuel(fuel.checked_sub(80).ok_or(Trap::OutOfFuel)?)?;
                        seen.fetch_add(1, Ordering::Relaxed);
                        Ok::<_, WasmtimeError>(())
                    })?;
                    tokio::task::yield_now().await;
                    Ok(())
                })
            })?;
        let mut store = runtime.make_store(BUDGET)?;
        let instance = linker.instantiate_async(&mut store, &component).await?;
        store.set_fuel(300)?;
        let func = instance.get_func(&mut store, "run").unwrap();
        let mut results = [Val::Bool(false)];
        let result = func
            .call_async(&mut store, &[Val::U32(second_length)], &mut results)
            .await;
        if second_length == 8 {
            result?;
            assert_eq!(results[0], Val::String("abcdefgh".into()));
            assert_eq!(bodies.load(Ordering::Relaxed), 2);
        } else {
            assert!(result.is_err());
            assert_eq!(bodies.load(Ordering::Relaxed), 1);
            let classified =
                Runtime::decode_result(false, Ok(result), results.to_vec(), &mut store).await;
            assert!(
                matches!(classified, Err(ExecutionError::Deterministic(_))),
                "{classified:?}"
            );
        }
    }
    Ok(())
}

async fn call(
    runtime: &Runtime,
    target: &ContractAddress,
    signer: &Signer,
    expr: &str,
    budget: u64,
) -> Result<(Result<String, ExecutionError>, u64)> {
    let store = runtime.make_store(budget)?;
    let payment = Payment {
        signer_id: signer.signer_id().unwrap(),
        gas_limit: runtime.gas_limit_for_non_procs,
    };
    let mut invocation = store.data().clone();
    let table = Arc::downgrade(&store.data().table);
    let (result, store) =
        funded_in_store(&mut invocation, store, target, signer, Some(&payment), expr).await?;
    let fuel = store.get_fuel()?;
    drop(store);
    drop(invocation);
    assert!(table.upgrade().is_none());
    Ok((result, fuel))
}

#[tokio::test]
async fn abi_conversion_limit_is_deterministic_and_rolls_back() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let core = Signer::Core(Box::new(actor));
    runtime.conversion_probe = Some(Probe::new(Policy::Fixed(1024), true));
    for target in &chain {
        for expr in [
            "result-payload(64)",
            "result-payload(512)",
            "write-result-payload(512)",
        ] {
            runtime.storage.savepoint().await?;
            let (result, remaining) = call(&runtime, target, &core, expr, BUDGET).await?;
            if expr == "result-payload(64)" {
                assert!(result.is_ok(), "{result:?}");
            } else {
                assert!(
                    matches!(result, Err(ExecutionError::Deterministic(_))),
                    "{result:?}"
                );
                println!(
                    "{expr} via {} remaining={remaining} error={result:?}",
                    target.name
                );
                assert_eq!(
                    runtime
                        .execute(None, None, &chain[0], "storage-state()")
                        .await?,
                    "[0, 0, 0, 0]"
                );
            }
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

#[tokio::test]
async fn abi_dynamic_allowance_refreshes_and_reaches_nested_stores() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let core = Signer::Core(Box::new(actor));
    for (depth, target) in chain.iter().enumerate() {
        let mut used = Vec::new();
        for policy in [None, Some(Policy::Observe), Some(Policy::Dynamic(10))] {
            runtime.storage.savepoint().await?;
            let probe = policy.map(|policy| Probe::new(policy, true));
            runtime.conversion_probe = probe.clone();
            let (result, remaining) =
                call(&runtime, target, &core, "result-payload(64)", BUDGET).await?;
            assert!(result.is_ok(), "{result:?}");
            used.push(BUDGET - remaining);
            if let Some(probe) = probe {
                assert_eq!(probe.stores.load(Ordering::Relaxed), depth + 1);
                let events = probe.events.lock().unwrap();
                if matches!(policy, Some(Policy::Dynamic(_))) {
                    for event in events.iter().filter(|event| {
                        matches!(
                            event.kind,
                            CallHook::CallingHost | CallHook::ReturningFromWasm
                        )
                    }) {
                        assert_eq!(event.allowance as u64, event.fuel / 10);
                    }
                }
                for id in 0..=depth {
                    let fuels: Vec<_> = events
                        .iter()
                        .filter(|event| {
                            event.store == id && matches!(event.kind, CallHook::CallingHost)
                        })
                        .map(|event| event.fuel)
                        .collect();
                    assert!(fuels.windows(2).any(|pair| pair[1] < pair[0]));
                }
            }
            runtime.storage.rollback().await?;
        }
        assert!(used.windows(2).all(|pair| pair[0] == pair[1]), "{used:?}");
    }
    Ok(())
}

#[tokio::test]
async fn encoded_results_avoid_host_value_tree_allocation() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let core = Signer::Core(Box::new(actor));
    let (result, remaining) = call(&runtime, &chain[0], &core, "storage-state()", BUDGET).await?;
    assert_eq!(result?, "[0, 0, 0, 0]");
    let exact = BUDGET - remaining;
    let (result, remaining) = call(&runtime, &chain[0], &core, "storage-state()", exact).await?;
    assert_eq!(result?, "[0, 0, 0, 0]");
    assert_eq!(remaining, 0);
    runtime.conversion_probe = Some(Probe::new(Policy::Dynamic(10), true));
    let (result, remaining) = call(&runtime, &chain[0], &core, "storage-state()", exact).await?;
    // Only the encoded bytes cross the boundary now. The former Vec<Val>
    // allocation exceeded this allowance even though formatting was affordable.
    assert_eq!(result?, "[0, 0, 0, 0]");
    assert_eq!(remaining, 0);
    Ok(())
}

#[tokio::test]
async fn abi_hooks_preserve_host_failure_and_guest_trap_classification() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let core = Signer::Core(Box::new(actor));
    runtime.conversion_probe = Some(Probe::new(Policy::Dynamic(10), false));
    for target in &chain {
        for (expr, deterministic) in [
            #[cfg(feature = "testing")]
            ("host-error()", false),
            #[cfg(feature = "testing")]
            ("host-panic()", false),
            ("trap-out-of-fuel()", true),
        ] {
            let (result, _) = call(&runtime, target, &core, expr, BUDGET).await?;
            assert!(result.is_err());
            assert_eq!(
                matches!(result, Err(ExecutionError::Deterministic(_))),
                deterministic,
                "{expr}: {result:?}"
            );
            if !deterministic {
                assert!(
                    format!("{:?}", result.unwrap_err()).contains("deliberate host"),
                    "{expr} must reach the injected host failure"
                );
            }
            assert!(runtime.stack.is_empty().await);
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "manual real-runtime call-hook overhead comparison"]
async fn abi_hook_overhead() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let core = Signer::Core(Box::new(actor));
    for expr in ["succeed()", "storage-state()", "result-payload(512)"] {
        for target in [&chain[0], &chain[2]] {
            let policies = [None, Some(Policy::Observe), Some(Policy::Dynamic(10))];
            let mut samples = [Vec::new(), Vec::new(), Vec::new()];
            for round in 0..5 {
                for offset in 0..3 {
                    let index = (round + offset) % 3;
                    runtime.storage.savepoint().await?;
                    runtime.conversion_probe =
                        policies[index].map(|policy| Probe::new(policy, false));
                    let start = Instant::now();
                    for _ in 0..100 {
                        let (result, _) = call(&runtime, target, &core, expr, BUDGET).await?;
                        result?;
                    }
                    samples[index].push(start.elapsed());
                    runtime.storage.rollback().await?;
                }
            }
            for (policy, mut times) in policies.into_iter().zip(samples) {
                times.sort();
                println!(
                    "{} {expr} {policy:?}: median_us_per_call={:.3}",
                    target.name,
                    times[2].as_secs_f64() * 10_000.0
                );
            }
        }
    }
    Ok(())
}
