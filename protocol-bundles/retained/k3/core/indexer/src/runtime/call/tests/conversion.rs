use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Result;
use indexer_types::Payment;
use wasmtime::CallHook;

use super::{call_chain, funded, funded_in_store};
use crate::runtime::conversion_probe::{Policy, Probe};
use crate::runtime::wit::Signer;
use crate::runtime::{ContractAddress, ExecutionError, Runtime};
use crate::test_utils::test_runtime;

const BUDGET: u64 = 100_000_000;

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
async fn abi_observation_hooks_preserve_nested_fuel() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let core = Signer::Core(Box::new(actor));
    for (depth, target) in chain.iter().enumerate() {
        let mut used = Vec::new();
        for policy in [None, Some(Policy::Observe)] {
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
async fn abi_hooks_preserve_host_failure_and_guest_trap_classification() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    let core = Signer::Core(Box::new(actor));
    runtime.conversion_probe = Some(Probe::new(Policy::Observe, false));
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

#[cfg(feature = "testing")]
#[tokio::test]
async fn host_panic_decoder_preserves_exact_payload_text() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let target = call_chain(&mut runtime, &actor).await?.remove(0);
    let core = Signer::Core(Box::new(actor));
    let (result, _) = call(&runtime, &target, &core, "host-panic()", BUDGET).await?;
    let error = match result {
        Err(ExecutionError::NonDeterministic(error)) => error,
        other => panic!("host panic lost its infrastructure classification: {other:?}"),
    };
    assert_eq!(
        error.root_cause().to_string(),
        "host panic: deliberate host panic for testing"
    );
    Ok(())
}
