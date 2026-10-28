use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Error, Result, anyhow, bail, ensure};
use brotli::CompressorReader;
use libsql::params;
use tokio::sync::Notify;
use tokio::time::timeout;
use wasm_encoder::{
    CodeSection, Function, FunctionSection, Instruction, Module as EncodedModule, RawSection,
    StartSection,
};
use wasmparser::{BinaryReader, CodeSectionReader, Parser, Payload, TypeRef, Validator};
use wasmtime::component::{Component, Val};
use wasmtime::{Engine, ExternType, Linker as WasmtimeLinker, Module, Store, Trap};

use super::component_policy;
use super::invocation::{
    InvocationBudget, InvocationCapacityExhausted, InvocationLimitReached, MAX_LIVE_INVOCATIONS,
};
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

fn compressed_core_start() -> Result<Vec<u8>> {
    let bytes = wat::parse_str("(module (func $start) (start $start))")?;
    let mut compressed = Vec::new();
    CompressorReader::new(bytes.as_slice(), 4096, 5, 22).read_to_end(&mut compressed)?;
    Ok(compressed)
}

fn host_importing_start(bytes: &[u8], module_name: &str, import_name: &str) -> Result<Vec<u8>> {
    let mut encoded = EncodedModule::new();
    let mut imported_functions = 0;
    let mut defined_functions = 0;
    let mut target = None;
    let mut inserted_start = false;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload?;
        match &payload {
            Payload::Version { .. } | Payload::CodeSectionEntry(_) | Payload::End(_) => continue,
            Payload::ImportSection(imports) => {
                for import in imports.clone().into_imports() {
                    let import = import?;
                    if let TypeRef::Func(type_index) = import.ty {
                        if import.module == module_name && import.name == import_name {
                            target = Some((imported_functions, type_index));
                        }
                        imported_functions += 1;
                    }
                }
            }
            Payload::FunctionSection(functions) => {
                let mut section = FunctionSection::new();
                for function in functions.clone() {
                    section.function(function?);
                    defined_functions += 1;
                }
                // The fixture's type 10 is its empty start signature. A rebuild
                // that changes this layout must fail validation below.
                section.function(10);
                encoded.section(&section);
                continue;
            }
            Payload::ElementSection(_) => {
                encoded.section(&StartSection {
                    function_index: imported_functions + defined_functions,
                });
                inserted_start = true;
            }
            Payload::CodeSectionStart {
                unchecked_range, ..
            } => {
                let start = usize::try_from(unchecked_range.start)?;
                let end = usize::try_from(unchecked_range.end)?;
                let reader = CodeSectionReader::new(BinaryReader::new(
                    &bytes[start..end],
                    unchecked_range.start,
                ))?;
                let mut section = CodeSection::new();
                for body in reader {
                    let range = body?.range();
                    section.raw(&bytes[usize::try_from(range.start)?..usize::try_from(range.end)?]);
                }
                let (target_index, target_type) = target.ok_or_else(|| {
                    anyhow!("missing real host import {module_name}::{import_name}")
                })?;
                let mut body = Function::new([]);
                // These are the real lowered WIT import signatures in the
                // stack-probe fixture, including its foreign-call i64 argument.
                let params: &[bool] = match target_type {
                    19 => &[false, false, false, false, true, false, false, false, false],
                    18 => &[false, false, false, true],
                    _ => bail!("unexpected host import type {target_type}"),
                };
                for parameter in params {
                    if *parameter {
                        body.instruction(&Instruction::I64Const(0));
                    } else {
                        body.instruction(&Instruction::I32Const(0));
                    }
                }
                body.instruction(&Instruction::Call(target_index));
                body.instruction(&Instruction::End);
                section.function(&body);
                encoded.section(&section);
                continue;
            }
            Payload::StartSection { .. } => bail!("source fixture already has a start section"),
            _ => {}
        }
        if let Some((id, range)) = payload.as_section() {
            encoded.section(&RawSection {
                id,
                data: &bytes[usize::try_from(range.start)?..usize::try_from(range.end)?],
            });
        }
    }
    ensure!(inserted_start, "source fixture has no element section");
    let bytes = encoded.finish();
    Validator::new().validate_all(&bytes)?;
    Ok(bytes)
}

#[test]
fn generated_startup_does_not_call_imported_host_function() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut linker = WasmtimeLinker::new(&engine);
    let observed = calls.clone();
    linker.func_wrap("env", "sentinel", move || {
        observed.fetch_add(1, Ordering::SeqCst);
    })?;
    let module = |offset| -> Result<Module> {
        let bytes = wat::parse_str(format!(
            "(module
                    (import \"env\" \"sentinel\" (func))
                    (memory 1)
                    (table 1 funcref)
                    (func $member)
                    (elem (i32.const 0) func $member)
                    (data (i32.const {offset}) \"x\"))"
        ))?;
        component_policy::validate_no_starts(&bytes)?;
        Ok(Module::new(&engine, &bytes)?)
    };
    let valid = module(0)?;
    let mut store = Store::new(&engine, ());
    store.set_fuel(1_000_000)?;
    linker.instantiate(&mut store, &valid)?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let out_of_bounds = module(65536)?;
    let mut store = Store::new(&engine, ());
    store.set_fuel(1_000_000)?;
    assert!(linker.instantiate(&mut store, &out_of_bounds).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let mut store = Store::new(&engine, ());
    store.set_fuel(0)?;
    let error = linker.instantiate(&mut store, &valid).unwrap_err();
    assert_eq!(error.downcast_ref::<Trap>(), Some(&Trap::OutOfFuel));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn host_importing_core_starts_are_rejected_before_side_effects() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let signer = Signer::Core(Box::new(Signer::Nobody));
    for (index, name) in ["foreign-call", "storage-set"].into_iter().enumerate() {
        let wat = format!(
            r#"(module
                (import "env" "{name}" (func $hook))
                (func $start (call $hook))
                (start $start))"#
        );
        let bytes = wat::parse_str(&wat)?;
        let module = Module::new(&runtime.engine, &bytes)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let mut linker = WasmtimeLinker::new(&runtime.engine);
        linker.func_wrap("env", name, move || {
            observed.fetch_add(1, Ordering::SeqCst);
        })?;
        let mut store = Store::new(&runtime.engine, ());
        store.set_fuel(1_000_000)?;
        linker.instantiate(&mut store, &module)?;
        assert_eq!(calls.swap(0, Ordering::SeqCst), 1);
        assert!(component_policy::validate_no_starts(&bytes).is_err());

        runtime
            .set_context(
                1,
                Some(
                    TransactionContext::builder()
                        .tx_index(u32::try_from(index)?)
                        .build(),
                ),
                None,
                None,
            )
            .await;
        let mut compressed = Vec::new();
        CompressorReader::new(bytes.as_slice(), 4096, 5, 22).read_to_end(&mut compressed)?;
        let error = runtime
            .publish(
                &signer,
                runtime.core_payment(),
                name,
                &compressed,
                &native_provenance()?,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutionError::Deterministic(_)));
        let message = format!("{error:#}");
        assert!(
            message.contains("start section") || message.contains("failed to resolve import"),
            "{message}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let address = ContractAddress {
            name: name.into(),
            height: 1,
            tx_index: u32::try_from(index)?,
        };
        assert!(runtime.storage.contract_id(&address).await?.is_none());
        assert!(runtime.storage.savepoint_stack.is_empty().await);
    }
    Ok(())
}

#[tokio::test]
async fn real_wit_host_importing_starts_are_rejected_before_instantiation() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let mut source = Vec::new();
    brotli::Decompressor::new(
        include_bytes!("../../../../test-contracts/binaries/stack_probe.wasm.br").as_slice(),
        4096,
    )
    .read_to_end(&mut source)?;
    let signer = Signer::Core(Box::new(Signer::Nobody));
    for (index, (module_name, import_name, name)) in [
        ("kontor:built-in/foreign", "call", "real-start-foreign"),
        (
            "kontor:built-in/context",
            "[method]proc-storage.set-u64",
            "real-start-storage",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = host_importing_start(&source, module_name, import_name)?;
        let module = Module::new(&runtime.engine, &bytes)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut linker = WasmtimeLinker::new(&runtime.engine);
        for import in module.imports() {
            let ExternType::Func(function_type) = import.ty() else {
                bail!("unexpected non-function import in real WIT fixture")
            };
            let targeted = import.module() == module_name && import.name() == import_name;
            let observed = calls.clone();
            linker.func_new(
                import.module(),
                import.name(),
                function_type,
                move |_, _, _| {
                    if targeted {
                        observed.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(())
                },
            )?;
        }
        let mut store = Store::new(&runtime.engine, ());
        store.set_fuel(1_000_000)?;
        linker.instantiate(&mut store, &module)?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(component_policy::validate_no_starts(&bytes).is_err());

        runtime
            .set_context(
                1,
                Some(
                    TransactionContext::builder()
                        .tx_index(u32::try_from(index)?)
                        .build(),
                ),
                None,
                None,
            )
            .await;
        let mut compressed = Vec::new();
        CompressorReader::new(bytes.as_slice(), 4096, 5, 22).read_to_end(&mut compressed)?;
        let error = runtime
            .publish(
                &signer,
                runtime.core_payment(),
                name,
                &compressed,
                &native_provenance()?,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutionError::Deterministic(_)));
        assert!(format!("{error:#}").contains("start section"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(runtime.storage.savepoint_stack.is_empty().await);
        let address = ContractAddress {
            name: name.into(),
            height: 1,
            tx_index: u32::try_from(index)?,
        };
        assert!(runtime.storage.contract_id(&address).await?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn core_start_is_rejected_on_publish_and_cold_load() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    let bytes = compressed_core_start()?;
    let signer = Signer::Core(Box::new(Signer::Nobody));
    let error = runtime
        .publish(
            &signer,
            runtime.core_payment(),
            "start-policy",
            &bytes,
            &native_provenance()?,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ExecutionError::Deterministic(_)));
    assert!(format!("{error:#}").contains("start section"));
    let address = ContractAddress {
        name: "start-policy".into(),
        height: 1,
        tx_index: 0,
    };
    assert!(runtime.storage.contract_id(&address).await?.is_none());
    assert!(runtime.storage.savepoint_stack.is_empty().await);

    let id = runtime
        .storage
        .insert_contract("start-policy", &bytes)
        .await?;
    let encoded =
        runtime
            .storage
            .decode_component_bytes(id)
            .await
            .map_err(|error| match error {
                ComponentDecodeError::Content(error)
                | ComponentDecodeError::Infrastructure(error) => error,
            })?;
    component_policy::validate_no_starts(&encoded).unwrap_err();
    let unchecked = Component::new(&runtime.engine, "(component)")?;
    runtime
        .component_cache
        .put_unchecked(id, unchecked, encoded.len())
        .await;
    assert!(runtime.component_cache.get_admitted(&id).await.is_none());
    assert!(runtime.load_component(id).await.is_err());
    runtime.component_cache.clear();
    for _ in 0..2 {
        assert!(runtime.component_cache.get(&id).await.is_none());
        assert!(runtime.load_component(id).await.is_err());
        assert!(runtime.component_cache.get(&id).await.is_none());
        assert!(runtime.component_cache.get_admitted(&id).await.is_none());
        let error = runtime
            .execute(None, None, &address, "anything()")
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutionError::NonDeterministic(_)));
    }
    Ok(())
}

#[tokio::test]
async fn native_start_prevents_restart() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let bytes = compressed_core_start()?;
    runtime
        .get_storage_conn()
        .execute(
            "UPDATE contracts SET bytes = ?, size = ? WHERE name = 'system' AND height = 0",
            params![bytes.clone(), bytes.len() as u64],
        )
        .await?;
    let mut restarted = Runtime::new(ComponentCache::new(), runtime.storage.clone()).await?;
    let error = restarted
        .publish_native_contracts(&test_genesis(&[]))
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("start section"));
    Ok(())
}

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
    runtime
        .component_cache
        .put_admitted(999_999, component, 1)
        .await;
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
    assert!(engine.is_pulley());
    assert_eq!(
        engine.get_target().as_deref(),
        Some("pulley64-unknown-unknown-elf")
    );
    assert_eq!(engine.get_max_wasm_stack(), 512 * 1024);
    assert_eq!(engine.get_async_stack_size(), 2 * 1024 * 1024);
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

#[tokio::test]
async fn invocation_budget_counts_the_root_and_releases_each_store() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut stores = vec![runtime.make_store(1_000_000)?];
    let budget = stores[0]
        .data()
        .invocation_budget
        .as_ref()
        .expect("root has an invocation budget")
        .clone();
    assert_eq!(budget.live(), 1);
    assert_eq!(stores[0].data().invocation_depth, 1);
    while stores.len() < MAX_LIVE_INVOCATIONS as usize {
        assert_eq!(
            budget.live(),
            stores.last().unwrap().data().invocation_depth
        );
        let child = stores.last().unwrap().data().make_store(1_000_000)?;
        stores.push(child);
        assert_eq!(budget.live(), stores.len() as u32);
        assert_eq!(
            stores.last().unwrap().data().invocation_depth,
            stores.len() as u32
        );
    }
    assert!(
        stores
            .last()
            .unwrap()
            .data()
            .make_store(1_000_000)
            .err()
            .expect("65th invocation must be rejected")
            .is::<InvocationLimitReached>()
    );
    assert_eq!(budget.live(), MAX_LIVE_INVOCATIONS);

    drop(stores.remove(0));
    assert_eq!(budget.live(), MAX_LIVE_INVOCATIONS - 1);
    assert!(
        stores
            .last()
            .unwrap()
            .data()
            .make_store(1_000_000)
            .err()
            .expect("depth remains capped after root teardown")
            .is::<InvocationLimitReached>()
    );
    let runtime_clone = stores.last().unwrap().data().clone();
    stores.clear();
    assert_eq!(budget.live(), 0);
    drop(runtime_clone);
    let root = runtime.make_store(1_000_000)?;
    assert_eq!(root.data().invocation_depth, 1);
    let budget = root.data().invocation_budget.as_ref().unwrap();
    for _ in 0..128 {
        assert_eq!(budget.live(), root.data().invocation_depth);
        let child = root.data().make_store(1_000_000)?;
        assert_eq!(budget.live(), child.data().invocation_depth);
        drop(child);
        assert_eq!(budget.live(), root.data().invocation_depth);
    }
    Ok(())
}

#[tokio::test]
async fn physical_capacity_is_an_infrastructure_error_below_the_depth_limit() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let budget = Arc::new(InvocationBudget::default());
    runtime.invocation_budget = Some(budget.clone());
    let stores = (0..MAX_LIVE_INVOCATIONS)
        .map(|_| runtime.make_store(1_000_000))
        .collect::<Result<Vec<_>>>()?;
    assert!(
        stores
            .iter()
            .all(|store| store.data().invocation_depth == 1)
    );
    assert_eq!(budget.live(), MAX_LIVE_INVOCATIONS);

    let fallback = runtime.make_store(1_000_000).err().unwrap();
    assert!(fallback.is::<InvocationCapacityExhausted>());
    let address = ContractAddress {
        name: "missing-contract".into(),
        height: 1,
        tx_index: 0,
    };
    let error = runtime
        .invoke_unsettled(&address, None, None, "(", 1_000_000, false)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(error, ExecutionError::NonDeterministic(ref cause) if cause.is::<InvocationCapacityExhausted>())
    );
    assert_eq!(budget.live(), MAX_LIVE_INVOCATIONS);
    drop(stores);
    assert_eq!(budget.live(), 0);
    Ok(())
}

#[tokio::test]
async fn capacity_error_precedes_target_parse_and_fuel_failures() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut stores = vec![runtime.make_store(1_000_000)?];
    while stores.len() < MAX_LIVE_INVOCATIONS as usize {
        let child = stores.last().unwrap().data().make_store(1_000_000)?;
        stores.push(child);
    }
    let address = ContractAddress {
        name: "missing-contract".into(),
        height: 1,
        tx_index: 0,
    };
    let malformed_expr = "(".repeat(65);
    let at_capacity = stores.last().unwrap().data().clone();
    for (expression, fuel) in [
        ("missing()", 1_000_000),
        (malformed_expr.as_str(), 1_000_000),
        ("missing()", 0),
    ] {
        let outcome = at_capacity
            .invoke_unsettled(&address, None, None, expression, fuel, true)
            .await?;
        assert_eq!(outcome.remaining_fuel, fuel);
        assert!(
            matches!(outcome.result, Err(ExecutionError::Deterministic(ref error)) if error.is::<InvocationLimitReached>())
        );
    }
    stores.pop();
    let below_capacity = stores.last().unwrap().data().clone();
    let invalid = below_capacity
        .invoke_unsettled(&address, None, None, "missing()", 1_000_000, true)
        .await?;
    assert!(
        matches!(invalid.result, Err(ExecutionError::Deterministic(ref error)) if error.to_string().contains("Contract not found"))
    );
    let malformed = below_capacity
        .invoke_unsettled(&address, None, None, &malformed_expr, 1_000_000, true)
        .await?;
    assert!(
        matches!(malformed.result, Err(ExecutionError::Deterministic(ref error)) if !error.is::<InvocationLimitReached>() && !error.to_string().contains("Contract not found"))
    );
    let exhausted = below_capacity
        .invoke_unsettled(&address, None, None, "missing()", 0, true)
        .await?;
    assert!(
        matches!(exhausted.result, Err(ExecutionError::Deterministic(ref error)) if error.chain().any(|cause| cause.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel)))
    );
    assert_eq!(stores.len(), 63);
    assert_eq!(
        stores
            .last()
            .unwrap()
            .data()
            .invocation_budget
            .as_ref()
            .unwrap()
            .live(),
        63
    );
    Ok(())
}

#[tokio::test]
async fn failed_store_setup_releases_the_reservation() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let mut config = Runtime::new_engine()?.config().clone();
    config.consume_fuel(false);
    config.consume_lifting_fuel(None);
    runtime.engine = Engine::new(&config)?;
    let budget = Arc::new(InvocationBudget::default());
    runtime.invocation_budget = Some(budget.clone());
    assert!(runtime.make_store(1_000_000).is_err());
    assert_eq!(budget.live(), 0);
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
