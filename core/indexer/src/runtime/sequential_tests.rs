use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Error, Result};
use libsql::params;
use tokio::sync::Notify;
use tokio::time::timeout;
use wasmtime::Engine;
use wasmtime::component::{Component, Val};

use super::component_policy;
use super::lowering::Linker;
use super::storage::ComponentDecodeError;
use super::wit::Signer;
use super::{
    ComponentCache, ContractAddress, ExecutionError, Runtime, TransactionContext, native_provenance,
};
use crate::test_utils::{test_genesis, test_runtime};

const ASYNC_COMPONENTS: &[&str] = &[
    include_str!("call/tests/fixtures/abi-async-string-return.wat"),
    include_str!("call/tests/fixtures/abi-async-realloc.wat"),
];

// Preserved from ca0e6a76 to exercise actual pre-S1 encoded WIT and loading.
const LEGACY_SYSTEM: &[u8] = include_bytes!("call/tests/fixtures/legacy-async-system.wasm.br");

#[tokio::test]
async fn legacy_async_publication_and_cold_loading_fail_closed() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    let signer = Signer::Core(Box::new(Signer::Nobody));
    let error = runtime
        .publish(
            &signer,
            runtime.core_payment(),
            "legacy",
            LEGACY_SYSTEM,
            &native_provenance()?,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ExecutionError::Deterministic(_)));
    let address = ContractAddress {
        name: "legacy".into(),
        height: 1,
        tx_index: 0,
    };
    assert!(runtime.storage.contract_id(&address).await?.is_none());
    assert!(runtime.storage.savepoint_stack.is_empty().await);

    let id = runtime
        .storage
        .insert_contract("legacy", LEGACY_SYSTEM)
        .await?;
    let bytes = runtime
        .storage
        .decode_component_bytes(id)
        .await
        .map_err(|error| match error {
            ComponentDecodeError::Content(error) | ComponentDecodeError::Infrastructure(error) => {
                error
            }
        })?;
    Component::from_binary(&async_engine()?, &bytes)?;
    for _ in 0..2 {
        assert!(runtime.load_component(id).await.is_err());
        assert!(runtime.component_cache.get(&id).await.is_none());
        let error = runtime
            .execute(None, None, &address, "anything()")
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutionError::NonDeterministic(_)));
    }
    Ok(())
}

#[tokio::test]
async fn incompatible_native_artifact_prevents_restart() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    runtime
        .get_storage_conn()
        .execute(
            "UPDATE contracts SET bytes = ?, size = ? WHERE name = 'system' AND height = 0",
            params![LEGACY_SYSTEM, LEGACY_SYSTEM.len() as u64],
        )
        .await?;
    let mut restarted = Runtime::new(ComponentCache::new(), runtime.storage.clone()).await?;
    assert!(
        restarted
            .publish_native_contracts(&test_genesis(&[]))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn cached_component_from_another_engine_is_not_executed() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let reference = async_engine()?;
    let component = Component::new(&reference, ASYNC_COMPONENTS[0])?;
    runtime.component_cache.put(999_999, component, 1).await;
    assert!(runtime.load_component(999_999).await.is_err());
    Ok(())
}

fn async_engine() -> Result<Engine> {
    let mut config = Runtime::new_engine()?.config().clone();
    config
        .concurrency_support(true)
        .wasm_component_model_async(true);
    Ok(Engine::new(&config)?)
}

#[test]
fn resolved_engine_disables_guest_concurrency() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let features = engine.get_wasm_features();
    assert!(!features.cm_async());
    assert!(!features.cm_more_async_builtins());
    assert!(!features.cm_async_stackful());
    assert!(!features.cm_threading());
    assert!(!features.cm_error_context());
    assert!(!features.threads());
    assert!(!features.shared_everything_threads());
    assert!(!features.stack_switching());
    assert!(!engine.get_concurrency_support());
    Ok(())
}

#[test]
fn rejects_valid_async_components_including_nested_components() -> Result<()> {
    let sequential = Runtime::new_engine()?;
    let reference = async_engine()?;
    for fixture in ASYNC_COMPONENTS {
        for wat in [fixture.to_string(), format!("(component {fixture})")] {
            let bytes = wat::parse_str(&wat)?;
            Component::from_binary(&reference, &bytes)?;
            assert!(Component::from_binary(&sequential, &bytes).is_err());
            assert!(matches!(
                component_policy::validate(&bytes),
                Err(ExecutionError::Deterministic(_))
            ));
        }
    }
    Ok(())
}

#[test]
fn serialized_async_artifacts_cannot_bypass_engine_policy() -> Result<()> {
    let sequential = Runtime::new_engine()?;
    let reference = async_engine()?;
    for fixture in ASYNC_COMPONENTS {
        let component = Component::new(&reference, fixture)?;
        let artifact = component.serialize()?;
        // Only bytes compiled and serialized locally in this test are trusted.
        unsafe {
            Component::deserialize(&reference, &artifact)?;
            assert!(Component::deserialize(&sequential, &artifact).is_err());
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn pending_host_io_suspends_guest_and_leaves_executor_available() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let component = Component::new(
        &runtime.engine,
        include_str!("call/tests/fixtures/abi-repeat-import.wat"),
    )?;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut linker = Linker::<Runtime>::new(&runtime.engine);
    let host_entered = entered.clone();
    let host_release = release.clone();
    let host_calls = calls.clone();
    linker
        .root()
        .func_wrap_async("accept", move |_, (_input,): (String,)| {
            let entered = host_entered.clone();
            let release = host_release.clone();
            let calls = host_calls.clone();
            Box::new(async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    entered.notify_one();
                    release.notified().await;
                }
                Ok(())
            })
        })?;
    let mut store = runtime.make_store(1_000_000)?;
    let instance = linker.instantiate_async(&mut store, &component).await?;
    let run = instance.get_func(&mut store, "run").unwrap();
    let task = tokio::spawn(async move {
        let mut results = [Val::U32(0)];
        run.call_async(&mut store, &[Val::U32(8), Val::U32(2)], &mut results)
            .await?;
        Ok::<_, Error>((results, store.get_fuel()?))
    });
    timeout(Duration::from_secs(10), entered.notified()).await?;
    let other_request = tokio::spawn(async { 42 });
    assert_eq!(timeout(Duration::from_secs(10), other_request).await??, 42);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!task.is_finished());
    release.notify_one();
    let (results, fuel) = timeout(Duration::from_secs(10), task).await???;
    assert_eq!(results, [Val::U32(42)]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(fuel < 1_000_000);
    Ok(())
}
