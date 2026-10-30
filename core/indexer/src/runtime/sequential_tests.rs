use std::io::Read;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use anyhow::{Error, Result, anyhow, bail, ensure};
use brotli::CompressorReader;
use indexer_types::Payment;
use libsql::params;
use serde_json::to_string;
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;
use wasm_encoder::{
    CodeSection, Function, FunctionSection, Instruction, Module as EncodedModule, RawSection,
    StartSection,
};
use wasmparser::{BinaryReader, CodeSectionReader, Parser, Payload, TypeRef, Validator};
use wasmtime::component::{Component, ResourceTable, ResourceType, Val};
use wasmtime::{Engine, ExternType, Linker as WasmtimeLinker, Module, Store, Trap};

use super::component_policy;
use super::invocation::{
    InvocationBudget, InvocationCapacityExhausted, InvocationLimitReached, MAX_LIVE_INVOCATIONS,
};
use super::lowering::Linker;
use super::numerics::sub_decimal;
use super::stack::CallFrame;
use super::storage::ComponentDecodeError;
use super::token::api as token;
use super::wit::Signer;
use super::wit::kontor::built_in::context::HolderRef;
use super::{
    ComponentCache, ContractAddress, Decimal, ExecutionError, Linkers, MAX_UNTRUSTED_GAS_LIMIT,
    Runtime, TransactionContext, native_provenance,
};
use crate::reg_tester::random_x_only_pubkey;
use crate::test_utils::{test_genesis, test_runtime};

const ASYNC_COMPONENTS: &[&str] = &[
    include_str!("call/tests/fixtures/abi-async-string-return.wat"),
    include_str!("call/tests/fixtures/abi-async-realloc.wat"),
];

const POST_RETURN_CALLBACK: &str = r#"(component
    (import "kontor:built-in/context" (instance $context
        (export "view-context" (type (sub resource)))))
    (alias export $context "view-context" (type $view-context))
    (import "sentinel" (func $sentinel))
    (import "mark" (func $mark))
    (core func $lower (canon lower (func $sentinel)))
    (core func $mark (canon lower (func $mark)))
    (core func $drop (canon resource.drop $view-context))
    (core module $code
        (import "" "" (func $host))
        (import "" "mark" (func $mark))
        (import "" "drop" (func $drop (param i32)))
        (func (export "run") (param i32)
            (call $mark)
            (call $drop (local.get 0)))
        (func (export "post-light") (call $host))
        (func (export "post-heavy")
            (local $i i32)
            (loop $work
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br_if $work (i32.lt_u (local.get $i) (i32.const 16384))))
            (call $host)))
    (core instance $code (instantiate $code
        (with "" (instance
            (export "" (func $lower))
            (export "mark" (func $mark))
            (export "drop" (func $drop))))))
    (func (export "run-light") (param "ctx" (borrow $view-context))
        (canon lift (core func $code "run")
            (post-return (core func $code "post-light"))))
    (func (export "run-heavy") (param "ctx" (borrow $view-context))
        (canon lift (core func $code "run")
            (post-return (core func $code "post-heavy")))))"#;

// Preserved from ca0e6a76 to exercise actual pre-S1 encoded WIT and loading.
const LEGACY_SYSTEM: &[u8] = include_bytes!("call/tests/fixtures/legacy-async-system.wasm.br");

fn compressed_core_start() -> Result<Vec<u8>> {
    let bytes = wat::parse_str("(module (func $start) (start $start))")?;
    let mut compressed = Vec::new();
    CompressorReader::new(bytes.as_slice(), 4096, 5, 22).read_to_end(&mut compressed)?;
    Ok(compressed)
}

async fn install_admitted_component_fixture(
    runtime: &mut Runtime,
    name: &str,
    wat: &str,
    tx_index: u32,
) -> Result<ContractAddress> {
    let bytes = wat::parse_str(wat)?;
    component_policy::validate_no_starts(&bytes)?;
    let component = Component::new(&runtime.engine, &bytes)?;
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(tx_index).build()),
            None,
            None,
        )
        .await;
    let core = wat::parse_str("(module)")?;
    let mut compressed = Vec::new();
    CompressorReader::new(core.as_slice(), 4096, 5, 22).read_to_end(&mut compressed)?;
    // Address resolution uses the row; the admitted cache supplies component
    // fixtures whose canonical callbacks cannot be encoded from a plain module.
    let id = runtime.storage.insert_contract(name, &compressed).await?;
    runtime
        .component_cache
        .put_admitted(id, component, bytes.len())
        .await;
    runtime.set_context(1, None, None, None).await;
    Ok(ContractAddress {
        name: name.into(),
        height: 1,
        tx_index,
    })
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
async fn hostile_canonical_callbacks_are_framed_and_clean_up() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let callback_calls = Arc::new(AtomicUsize::new(0));
    let body_calls = Arc::new(AtomicUsize::new(0));
    let marker_calls = Arc::new(AtomicUsize::new(0));
    let marker_tables: Arc<StdMutex<Vec<Weak<Mutex<ResourceTable>>>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let expected_contract_id = Arc::new(AtomicU64::new(0));
    let mut user = runtime.linkers.user.clone();
    let observed = callback_calls.clone();
    user.root().func_wrap("sentinel", move |_, (): ()| {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })?;
    let observed_body = body_calls.clone();
    user.root().func_wrap("body-entered", move |_, (): ()| {
        observed_body.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })?;
    let observed_markers = marker_calls.clone();
    let observed_tables = marker_tables.clone();
    let expected_id = expected_contract_id.clone();
    user.root().func_wrap_async("mark", move |store, (): ()| {
        let observed_markers = observed_markers.clone();
        let observed_tables = observed_tables.clone();
        let expected_id = expected_id.clone();
        Box::new(async move {
            let frame = store.data().stack.peek().await.expect("active child frame");
            assert_eq!(frame.contract_id, expected_id.load(Ordering::SeqCst));
            assert_eq!(store.data().invocation_depth, 1);
            assert_eq!(store.data().invocation_budget.as_ref().unwrap().live(), 1);
            assert!(store.data().table.lock().await.iter_mut().count() > 0);
            observed_tables
                .lock()
                .unwrap()
                .push(Arc::downgrade(&store.data().table));
            // This call-owned write must be undone when post-return traps.
            let storage = store.data().storage.clone();
            storage
                .set(frame.contract_id, b"callback-marker", b"set", None, None)
                .await
                .expect("marker write");
            assert_eq!(
                storage
                    .get(16, frame.contract_id, b"callback-marker")
                    .await
                    .expect("marker read"),
                Some(b"set".to_vec())
            );
            observed_markers.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    })?;
    runtime.linkers = Arc::new(Linkers {
        user,
        native: runtime.linkers.native.clone(),
    });
    let post_return = POST_RETURN_CALLBACK;
    let realloc = r#"(component
        (import "kontor:built-in/context" (instance $context
            (export "view-context" (type (sub resource)))))
        (alias export $context "view-context" (type $view-context))
        (core func $drop (canon resource.drop $view-context))
        (core module $code
            (import "" "drop" (func $drop (param i32)))
            (memory (export "memory") 1)
            (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                unreachable)
            (func (export "run") (param i32 i32 i32)
                (call $drop (local.get 0))))
        (core instance $code (instantiate $code
            (with "" (instance (export "drop" (func $drop))))))
        (func (export "run") (param "ctx" (borrow $view-context)) (param "text" string)
            (canon lift (core func $code "run")
                (memory (core memory $code "memory"))
                (realloc (core func $code "realloc")))))"#;
    let realloc_import = r#"(component
        (import "kontor:built-in/context" (instance $context
            (export "view-context" (type (sub resource)))))
        (alias export $context "view-context" (type $view-context))
        (import "sentinel" (func $sentinel))
        (import "body-entered" (func $body-entered))
        (core func $lower (canon lower (func $sentinel)))
        (core func $body (canon lower (func $body-entered)))
        (core func $drop (canon resource.drop $view-context))
        (core module $code
            (import "" "" (func $host))
            (import "" "body" (func $body))
            (import "" "drop" (func $drop (param i32)))
            (memory (export "memory") 1)
            (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                (if (i32.eq (local.get 3) (i32.const 16384))
                    (then (call $host)))
                (i32.const 64))
            (func (export "run") (param i32 i32 i32)
                (call $body)
                (call $drop (local.get 0))))
        (core instance $code (instantiate $code
            (with "" (instance
                (export "" (func $lower))
                (export "body" (func $body))
                (export "drop" (func $drop))))))
        (func (export "run") (param "ctx" (borrow $view-context)) (param "text" string)
            (canon lift (core func $code "run")
                (memory (core memory $code "memory"))
                (realloc (core func $code "realloc")))))"#;
    let large_input = format!("run({})", to_string(&"x".repeat(16 * 1024))?);
    let budget = Arc::new(InvocationBudget::default());
    runtime.invocation_budget = Some(budget.clone());
    for (index, name, wat, expression, trap) in [
        (
            0,
            "post-return",
            post_return,
            "run-light()",
            Trap::CannotLeaveComponent,
        ),
        (
            1,
            "realloc",
            realloc,
            large_input.as_str(),
            Trap::UnreachableCodeReached,
        ),
        (
            2,
            "realloc-import",
            realloc_import,
            large_input.as_str(),
            Trap::CannotLeaveComponent,
        ),
    ] {
        let address = install_admitted_component_fixture(&mut runtime, name, wat, index).await?;
        if name == "post-return" {
            expected_contract_id.store(
                runtime.storage.contract_id(&address).await?.unwrap(),
                Ordering::SeqCst,
            );
        }
        if name == "realloc-import" {
            assert!(
                runtime
                    .execute(None, None, &address, "run(\"ok\")")
                    .await
                    .is_ok()
            );
            assert_eq!(body_calls.load(Ordering::SeqCst), 1);
            assert_eq!(budget.live(), 0);
        }
        let body_before = body_calls.load(Ordering::SeqCst);
        let conn = runtime.get_storage_conn();
        let mut rows = conn
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        let receipts_before: u64 = rows.next().await?.unwrap().get(0)?;
        let mut expected_fuel = None;
        for trial in 0..2 {
            let previous = runtime.start_usage();
            let error = runtime
                .execute(None, None, &address, expression)
                .await
                .unwrap_err();
            assert!(
                matches!(error, ExecutionError::Deterministic(ref cause)
                    if cause.chain().any(|item| item.downcast_ref::<Trap>() == Some(&trap))),
                "{name}: {error:?}"
            );
            let usage = runtime.finish_usage(previous)?;
            assert!(usage.system_fuel > 0, "{name}");
            if let Some(fuel) = expected_fuel {
                assert_eq!(usage.system_fuel, fuel, "{name}");
            } else {
                expected_fuel = Some(usage.system_fuel);
            }
            assert!(runtime.stack.is_empty().await, "{name}");
            assert!(runtime.storage.savepoint_stack.is_empty().await, "{name}");
            assert_eq!(budget.live(), 0, "{name}");
            assert_eq!(callback_calls.load(Ordering::SeqCst), 0);
            assert_eq!(body_calls.load(Ordering::SeqCst), body_before);
            if name == "post-return" {
                assert_eq!(marker_calls.load(Ordering::SeqCst), trial + 1);
                let child_table = marker_tables.lock().unwrap().pop().unwrap();
                assert!(
                    child_table.upgrade().is_none(),
                    "post-return trap must release the child resource table"
                );
                assert!(
                    runtime
                        .storage
                        .get(
                            16,
                            expected_contract_id.load(Ordering::SeqCst),
                            b"callback-marker",
                        )
                        .await?
                        .is_none(),
                    "post-return trap must roll back the child marker"
                );
            }
            let mut rows = conn
                .query("SELECT COUNT(*) FROM contract_results", ())
                .await?;
            let receipts_after: u64 = rows.next().await?.unwrap().get(0)?;
            assert_eq!(receipts_after, receipts_before, "{name}");
        }
        if name == "post-return" {
            let light_fuel = expected_fuel.unwrap();
            let mut heavy_fuel = None;
            for trial in 0..2 {
                let previous = runtime.start_usage();
                let error = runtime
                    .execute(None, None, &address, "run-heavy()")
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, ExecutionError::Deterministic(ref cause)
                        if cause.chain().any(|item| item.downcast_ref::<Trap>()
                            == Some(&Trap::CannotLeaveComponent))),
                    "{error:?}"
                );
                let fuel = runtime.finish_usage(previous)?.system_fuel;
                // The pinned engine charges each BrIf backedge at least one fuel.
                assert!(fuel >= light_fuel + 16_384);
                if let Some(expected) = heavy_fuel {
                    assert_eq!(fuel, expected);
                } else {
                    heavy_fuel = Some(fuel);
                }
                assert_eq!(marker_calls.load(Ordering::SeqCst), trial + 3);
                assert_eq!(callback_calls.load(Ordering::SeqCst), 0);
                assert!(
                    marker_tables
                        .lock()
                        .unwrap()
                        .pop()
                        .unwrap()
                        .upgrade()
                        .is_none()
                );
                assert!(
                    runtime
                        .storage
                        .get(
                            16,
                            expected_contract_id.load(Ordering::SeqCst),
                            b"callback-marker",
                        )
                        .await?
                        .is_none()
                );
                assert!(runtime.stack.is_empty().await);
                assert!(runtime.storage.savepoint_stack.is_empty().await);
                assert_eq!(budget.live(), 0);
                let mut rows = conn
                    .query("SELECT COUNT(*) FROM contract_results", ())
                    .await?;
                let receipts_after: u64 = rows.next().await?.unwrap().get(0)?;
                assert_eq!(receipts_after, receipts_before);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn partial_instantiation_does_not_invoke_registered_destructors() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let guest_calls = Arc::new(AtomicUsize::new(0));
    let host_drops = Arc::new(AtomicUsize::new(0));
    let mut user = runtime.linkers.user.clone();
    let observed_guest = guest_calls.clone();
    user.root()
        .func_wrap("guest-dtor-sentinel", move |_, (): ()| {
            observed_guest.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })?;
    let observed_host = host_drops.clone();
    user.root()
        .resource_async("host-resource", ResourceType::host::<u64>(), move |_, _| {
            let observed_host = observed_host.clone();
            Box::new(async move {
                observed_host.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        })?;
    runtime.linkers = Arc::new(Linkers {
        user,
        native: runtime.linkers.native.clone(),
    });
    let component = r#"(component
        (import "kontor:built-in/context" (instance $context
            (export "view-context" (type (sub resource)))))
        (alias export $context "view-context" (type $view-context))
        (import "guest-dtor-sentinel" (func $sentinel))
        (import "host-resource" (type $host-resource (sub resource)))
        (core func $lower (canon lower (func $sentinel)))
        (core module $dtor-code
            (import "" "" (func $host))
            (func (export "dtor") (param i32) (call $host)))
        (core instance $dtor-code (instantiate $dtor-code
            (with "" (instance (export "" (func $lower))))))
        (type $guest-resource
            (resource (rep i32) (dtor (core func $dtor-code "dtor"))))
        (export "guest-resource" (type $guest-resource))
        (core func $new (canon resource.new $guest-resource))
        (core func $drop-resource (canon resource.drop $guest-resource))
        (core func $drop-context (canon resource.drop $view-context))
        (core module $fail
            (import "" "new" (func $new (param i32) (result i32)))
            (import "" "drop-resource" (func $drop-resource (param i32)))
            (import "" "drop-context" (func $drop-context (param i32)))
            (memory 1)
            (data (i32.const 65536) "x")
            (func (export "run") (param i32)
                (call $drop-resource (call $new (i32.const 1)))
                (call $drop-context (local.get 0))))
        (core instance $fail (instantiate $fail
            (with "" (instance
                (export "new" (func $new))
                (export "drop-resource" (func $drop-resource))
                (export "drop-context" (func $drop-context))))))
        (func (export "run") (param "ctx" (borrow $view-context))
            (canon lift (core func $fail "run"))))"#;
    let address =
        install_admitted_component_fixture(&mut runtime, "failed-init", component, 0).await?;
    let working_component = component.replace("(i32.const 65536)", "(i32.const 0)");
    let working =
        install_admitted_component_fixture(&mut runtime, "valid-init", &working_component, 1)
            .await?;
    let budget = Arc::new(InvocationBudget::default());
    runtime.invocation_budget = Some(budget.clone());
    let failed_id = runtime.storage.contract_id(&address).await?.unwrap();
    let failed_component = runtime
        .component_cache
        .get_admitted(&failed_id)
        .await
        .unwrap();
    let mut store = runtime.make_store(1_000_000)?;
    let call_table = Arc::downgrade(&store.data().table);
    let direct_error = runtime
        .linkers
        .user
        .instantiate_async(&mut store, &failed_component)
        .await
        .unwrap_err();
    assert!(
        direct_error
            .chain()
            .any(|cause| cause.downcast_ref::<Trap>() == Some(&Trap::MemoryOutOfBounds))
    );
    assert_eq!(budget.live(), 1);
    drop(store);
    assert!(call_table.upgrade().is_none());
    assert_eq!(budget.live(), 0);
    let resources_before = runtime.table.lock().await.iter_mut().count();
    let conn = runtime.get_storage_conn();
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    let receipts_before: u64 = rows.next().await?.unwrap().get(0)?;
    for _ in 0..2 {
        let result = runtime.execute(None, None, &address, "run()").await;
        assert!(
            matches!(result, Err(ExecutionError::Deterministic(ref error))
                if error.chain().any(|cause| cause.downcast_ref::<Trap>() == Some(&Trap::MemoryOutOfBounds))),
            "{result:?}"
        );
        assert_eq!(budget.live(), 0);
        assert!(runtime.stack.is_empty().await);
        assert!(runtime.storage.savepoint_stack.is_empty().await);
        assert_eq!(
            runtime.table.lock().await.iter_mut().count(),
            resources_before
        );
        assert_eq!(guest_calls.load(Ordering::SeqCst), 0);
        assert_eq!(host_drops.load(Ordering::SeqCst), 0);
        let mut rows = conn
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        let receipts_after: u64 = rows.next().await?.unwrap().get(0)?;
        assert_eq!(receipts_after, receipts_before);
    }
    assert!(runtime.execute(None, None, &working, "run()").await.is_ok());
    assert_eq!(guest_calls.load(Ordering::SeqCst), 1);
    assert_eq!(host_drops.load(Ordering::SeqCst), 0);
    assert_eq!(budget.live(), 0);
    Ok(())
}

#[tokio::test]
async fn explicit_guest_resource_drop_invokes_host_callback_and_cleans_up() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let callback_calls = Arc::new(AtomicUsize::new(0));
    let callback_tables: Arc<StdMutex<Vec<Weak<Mutex<ResourceTable>>>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let mut user = runtime.linkers.user.clone();
    let observed = callback_calls.clone();
    let observed_tables = callback_tables.clone();
    user.root()
        .func_wrap("destructor-callback", move |store, (): ()| {
            observed_tables
                .lock()
                .unwrap()
                .push(Arc::downgrade(&store.data().table));
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })?;
    runtime.linkers = Arc::new(Linkers {
        user,
        native: runtime.linkers.native.clone(),
    });
    let component = r#"(component
        (import "kontor:built-in/context" (instance $context
            (export "view-context" (type (sub resource)))))
        (alias export $context "view-context" (type $view-context))
        (import "destructor-callback" (func $callback))
        (core func $callback (canon lower (func $callback)))
        (core module $dtor-code
            (import "" "callback" (func $callback))
            (func (export "dtor") (param i32) (call $callback)))
        (core instance $dtor-code (instantiate $dtor-code
            (with "" (instance (export "callback" (func $callback))))))
        (type $guest-resource
            (resource (rep i32) (dtor (core func $dtor-code "dtor"))))
        (core func $new (canon resource.new $guest-resource))
        (core func $drop-resource (canon resource.drop $guest-resource))
        (core func $drop-context (canon resource.drop $view-context))
        (core module $code
            (import "" "new" (func $new (param i32) (result i32)))
            (import "" "drop-resource" (func $drop-resource (param i32)))
            (import "" "drop-context" (func $drop-context (param i32)))
            (func $run (param $ctx i32) (param $fail i32)
                (call $drop-resource (call $new (i32.const 7)))
                (call $drop-context (local.get $ctx))
                (if (local.get $fail) (then unreachable)))
            (func (export "success") (param i32)
                (call $run (local.get 0) (i32.const 0)))
            (func (export "trap") (param i32)
                (call $run (local.get 0) (i32.const 1))))
        (core instance $code (instantiate $code
            (with "" (instance
                (export "new" (func $new))
                (export "drop-resource" (func $drop-resource))
                (export "drop-context" (func $drop-context))))))
        (func (export "success") (param "ctx" (borrow $view-context))
            (canon lift (core func $code "success")))
        (func (export "trap") (param "ctx" (borrow $view-context))
            (canon lift (core func $code "trap"))))"#;
    let address =
        install_admitted_component_fixture(&mut runtime, "explicit-drop", component, 0).await?;
    let budget = Arc::new(InvocationBudget::default());
    runtime.invocation_budget = Some(budget.clone());
    let conn = runtime.get_storage_conn();
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    let receipts_before: u64 = rows.next().await?.unwrap().get(0)?;
    for (index, expression) in ["success()", "trap()", "success()"].into_iter().enumerate() {
        let previous = runtime.start_usage();
        let result = runtime.execute(None, None, &address, expression).await;
        if expression == "trap()" {
            assert!(
                matches!(result, Err(ExecutionError::Deterministic(ref error))
                if error.chain().any(|cause| cause.downcast_ref::<Trap>() == Some(&Trap::UnreachableCodeReached))),
                "{result:?}"
            );
        } else {
            assert!(result.is_ok(), "{result:?}");
        }
        assert!(runtime.finish_usage(previous)?.system_fuel > 0);
        assert_eq!(callback_calls.load(Ordering::SeqCst), index + 1);
        assert!(
            callback_tables
                .lock()
                .unwrap()
                .pop()
                .unwrap()
                .upgrade()
                .is_none()
        );
        assert_eq!(budget.live(), 0);
        assert!(runtime.stack.is_empty().await);
        assert!(runtime.storage.savepoint_stack.is_empty().await);
        let mut rows = conn
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        let receipts_after: u64 = rows.next().await?.unwrap().get(0)?;
        assert_eq!(receipts_after, receipts_before);
    }
    Ok(())
}

#[tokio::test]
async fn paid_hostile_realloc_charges_one_root_receipt_and_preserves_state() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let component = r#"(component
        (import "kontor:built-in/context" (instance $context
            (export "proc-context" (type (sub resource)))))
        (alias export $context "proc-context" (type $proc-context))
        (core func $drop (canon resource.drop $proc-context))
        (core module $code
            (import "" "drop" (func $drop (param i32)))
            (memory (export "memory") 1)
            (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                unreachable)
            (func (export "run") (param i32 i32 i32)
                (call $drop (local.get 0))))
        (core instance $code (instantiate $code
            (with "" (instance (export "drop" (func $drop))))))
        (func (export "run") (param "ctx" (borrow $proc-context)) (param "text" string)
            (canon lift (core func $code "run")
                (memory (core memory $code "memory"))
                (realloc (core func $code "realloc")))))"#;
    let address =
        install_admitted_component_fixture(&mut runtime, "paid-realloc", component, 0).await?;
    let contract_id = runtime.storage.contract_id(&address).await?.unwrap();
    let actor = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    token::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&actor),
        Decimal::from("100"),
    )
    .await??;
    let payment = Payment {
        signer_id: actor.signer_id().unwrap(),
        gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
    };
    let expression = format!("run({})", to_string(&"x".repeat(16 * 1024))?);
    let budget = Arc::new(InvocationBudget::default());
    runtime.invocation_budget = Some(budget.clone());
    let floor_before = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
    let conn = runtime.get_storage_conn();
    let mut rows = conn
        .query(
            "SELECT COUNT(*) FROM contract_results WHERE contract_id = ?",
            params![contract_id],
        )
        .await?;
    let receipts_before: u64 = rows.next().await?.unwrap().get(0)?;
    let mut repeated = None;
    for trial in 0..2 {
        let actor_before = token::balance(&mut runtime, HolderRef::from(&actor))
            .await?
            .unwrap_or_default();
        let burner_before = token::balance(&mut runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        let previous = runtime.start_usage();
        let result = runtime
            .execute(Some(&actor), Some(payment.clone()), &address, &expression)
            .await;
        assert!(
            matches!(result, Err(ExecutionError::Deterministic(ref error))
                if error.chain().any(|cause| cause.downcast_ref::<Trap>() == Some(&Trap::UnreachableCodeReached))),
            "{result:?}"
        );
        let usage = runtime.finish_usage(previous)?;
        assert!(usage.user_fuel > 0);
        assert_eq!(budget.live(), 0);
        assert!(runtime.stack.is_empty().await);
        assert!(runtime.storage.savepoint_stack.is_empty().await);
        // Canonical realloc denies host callbacks before the guest body. The
        // outer table cannot observe this invocation's child table teardown.
        assert!(
            runtime
                .storage
                .get(16, contract_id, b"callback-marker")
                .await?
                .is_none()
        );
        let mut rows = conn
            .query(
                "SELECT status, gas FROM contract_results WHERE contract_id = ? ORDER BY id DESC LIMIT 1",
                params![contract_id],
            )
            .await?;
        let receipt = rows.next().await?.expect("one root result");
        assert_eq!(receipt.get::<String>(0)?, "Trap");
        let gas: u64 = receipt.get(1)?;
        assert!(gas > 0);
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM contract_results WHERE contract_id = ?",
                params![contract_id],
            )
            .await?;
        let receipts_after: u64 = rows.next().await?.unwrap().get(0)?;
        assert_eq!(receipts_after, receipts_before + trial + 1);
        let actor_after = token::balance(&mut runtime, HolderRef::from(&actor))
            .await?
            .unwrap_or_default();
        let burner_after = token::balance(&mut runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        let paid = sub_decimal(actor_before, actor_after)?;
        let burned = sub_decimal(burner_after, burner_before)?;
        assert_eq!(paid, burned);
        assert!(paid > Decimal::default());
        assert_eq!(
            token::floor(&mut runtime, HolderRef::from(&actor)).await?,
            floor_before
        );
        let observation = (usage.user_fuel, gas, paid.to_string());
        if let Some(expected) = &repeated {
            assert_eq!(&observation, expected);
        } else {
            repeated = Some(observation);
        }
    }
    Ok(())
}

#[tokio::test]
async fn paid_post_return_callback_work_charges_fuel_gas_and_burn() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let mark_calls = Arc::new(AtomicUsize::new(0));
    let sentinel_calls = Arc::new(AtomicUsize::new(0));
    let mark_tables: Arc<StdMutex<Vec<Weak<Mutex<ResourceTable>>>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let mut user = runtime.linkers.user.clone();
    let observed_sentinel = sentinel_calls.clone();
    user.root().func_wrap("sentinel", move |_, (): ()| {
        observed_sentinel.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })?;
    let observed_marks = mark_calls.clone();
    let observed_tables = mark_tables.clone();
    user.root().func_wrap_async("mark", move |store, (): ()| {
        let observed_marks = observed_marks.clone();
        let observed_tables = observed_tables.clone();
        Box::new(async move {
            let frame = store.data().stack.peek().await.expect("active paid frame");
            observed_tables
                .lock()
                .unwrap()
                .push(Arc::downgrade(&store.data().table));
            let storage = store.data().storage.clone();
            storage
                .set(frame.contract_id, b"callback-marker", b"set", None, None)
                .await
                .expect("marker write");
            observed_marks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    })?;
    runtime.linkers = Arc::new(Linkers {
        user,
        native: runtime.linkers.native.clone(),
    });
    let paid_component = POST_RETURN_CALLBACK.replace("view-context", "proc-context");
    let address =
        install_admitted_component_fixture(&mut runtime, "paid-post-return", &paid_component, 0)
            .await?;
    let contract_id = runtime.storage.contract_id(&address).await?.unwrap();
    let actor = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    token::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&actor),
        Decimal::from("100"),
    )
    .await??;
    let payment = Payment {
        signer_id: actor.signer_id().unwrap(),
        gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
    };
    let budget = Arc::new(InvocationBudget::default());
    runtime.invocation_budget = Some(budget.clone());
    let floor_before = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
    let conn = runtime.get_storage_conn();
    let mut rows = conn
        .query(
            "SELECT COUNT(*) FROM contract_results WHERE contract_id = ?",
            params![contract_id],
        )
        .await?;
    let receipts_before: u64 = rows.next().await?.unwrap().get(0)?;
    let mut observations = Vec::new();
    for (variant, expression) in ["run-light()", "run-heavy()"].into_iter().enumerate() {
        let mut repeated = None;
        for trial in 0..2 {
            let actor_before = token::balance(&mut runtime, HolderRef::from(&actor))
                .await?
                .unwrap_or_default();
            let burner_before = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            let previous = runtime.start_usage();
            let error = runtime
                .execute(Some(&actor), Some(payment.clone()), &address, expression)
                .await
                .unwrap_err();
            assert!(
                matches!(error, ExecutionError::Deterministic(ref cause)
                    if cause.chain().any(|item| item.downcast_ref::<Trap>()
                        == Some(&Trap::CannotLeaveComponent))),
                "{expression}: {error:?}"
            );
            let usage = runtime.finish_usage(previous)?;
            assert!(usage.user_fuel > 0);
            assert_eq!(mark_calls.load(Ordering::SeqCst), variant * 2 + trial + 1);
            assert_eq!(sentinel_calls.load(Ordering::SeqCst), 0);
            assert!(
                mark_tables
                    .lock()
                    .unwrap()
                    .pop()
                    .unwrap()
                    .upgrade()
                    .is_none()
            );
            assert_eq!(budget.live(), 0);
            assert!(runtime.stack.is_empty().await);
            assert!(runtime.storage.savepoint_stack.is_empty().await);
            assert!(
                runtime
                    .storage
                    .get(16, contract_id, b"callback-marker")
                    .await?
                    .is_none()
            );
            let mut rows = conn
                .query(
                    "SELECT status, gas FROM contract_results WHERE contract_id = ? ORDER BY id DESC LIMIT 1",
                    params![contract_id],
                )
                .await?;
            let receipt = rows.next().await?.expect("one root result");
            assert_eq!(receipt.get::<String>(0)?, "Trap");
            let gas: u64 = receipt.get(1)?;
            let mut rows = conn
                .query(
                    "SELECT COUNT(*) FROM contract_results WHERE contract_id = ?",
                    params![contract_id],
                )
                .await?;
            let receipts_after: u64 = rows.next().await?.unwrap().get(0)?;
            assert_eq!(
                receipts_after,
                receipts_before + (variant * 2 + trial + 1) as u64
            );
            let actor_after = token::balance(&mut runtime, HolderRef::from(&actor))
                .await?
                .unwrap_or_default();
            let burner_after = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            let paid = sub_decimal(actor_before, actor_after)?;
            let burned = sub_decimal(burner_after, burner_before)?;
            assert_eq!(paid, burned);
            assert!(paid > Decimal::default());
            assert_eq!(
                token::floor(&mut runtime, HolderRef::from(&actor)).await?,
                floor_before
            );
            let observation = (usage.user_fuel, gas, paid);
            if let Some(expected) = &repeated {
                assert_eq!(&observation, expected);
            } else {
                repeated = Some(observation);
            }
        }
        observations.push(repeated.unwrap());
    }
    let light = &observations[0];
    let heavy = &observations[1];
    // The pinned engine charges at least one fuel for each BrIf backedge.
    assert!(heavy.0 >= light.0 + 16_384);
    assert!(heavy.1 > light.1);
    assert!(heavy.2 > light.2);
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
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    let signer = Signer::Core(Box::new(Signer::Nobody));
    runtime
        .publish(
            &signer,
            runtime.core_payment(),
            "capacity-cycle",
            include_bytes!("../../../../test-contracts/binaries/error_test.wasm.br"),
            &native_provenance()?,
        )
        .await?;
    runtime.set_context(1, None, None, None).await;
    let core_payment = runtime.core_payment();
    let cycle_address = ContractAddress {
        name: "capacity-cycle".into(),
        height: 1,
        tx_index: 0,
    };
    let cycle_id = runtime.storage.contract_id(&cycle_address).await?.unwrap();
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
    at_capacity
        .stack
        .push(CallFrame {
            contract_id: cycle_id,
            is_proc: true,
            depositor: None,
        })
        .await?;
    let cycle_at_capacity = at_capacity
        .invoke_unsettled(
            &cycle_address,
            Some(&signer),
            Some(&core_payment),
            "chain-probe(false)",
            1_000_000,
            true,
        )
        .await?;
    assert!(
        matches!(cycle_at_capacity.result, Err(ExecutionError::Deterministic(ref error)) if error.is::<InvocationLimitReached>())
    );
    stores.pop();
    let below_capacity = stores.last().unwrap().data().clone();
    let cycle_below_capacity = below_capacity
        .invoke_unsettled(
            &cycle_address,
            Some(&signer),
            Some(&core_payment),
            "chain-probe(false)",
            1_000_000,
            true,
        )
        .await?;
    assert!(
        matches!(cycle_below_capacity.result, Err(ExecutionError::Deterministic(ref error)) if error.to_string().contains("reentrancy prevented"))
    );
    assert_eq!(
        below_capacity.stack.pop().await.unwrap().contract_id,
        cycle_id
    );
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
