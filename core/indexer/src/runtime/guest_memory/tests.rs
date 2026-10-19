use anyhow::Result;
use wasmtime::{
    Engine, GcHeapOutOfMemory, Instance, Memory, MemoryType, Module, Store, WasmFeatures,
};

use super::{GuestMemoryLimitExceeded, GuestMemoryLimiter, GuestMemoryLimits};
use crate::runtime::Runtime;
use crate::test_utils::test_runtime;

const PAGE: usize = 65_536;

struct TestState {
    limiter: GuestMemoryLimiter,
}

fn limits(per_root: usize) -> GuestMemoryLimits {
    GuestMemoryLimits {
        per_root,
        table_elements_per_root: 32,
        memories: 4,
        instances: 8,
        tables: 4,
        table_elements: 16,
    }
}

fn store(engine: &Engine, limiter: GuestMemoryLimiter) -> Store<TestState> {
    let mut store = Store::new(engine, TestState { limiter });
    store.limiter(|state| &mut state.limiter);
    store
}

#[test]
fn runtime_engine_pins_growth_assumptions() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let features = engine.get_wasm_features();
    assert!(!features.contains(WasmFeatures::CUSTOM_PAGE_SIZES));
    assert!(!features.contains(WasmFeatures::THREADS));
    assert!(features.contains(WasmFeatures::GC));
    assert!(features.contains(WasmFeatures::GC_TYPES));
    assert!(features.contains(WasmFeatures::FUNCTION_REFERENCES));
    assert!(features.contains(WasmFeatures::EXCEPTIONS));
    assert!(!features.contains(WasmFeatures::LEGACY_EXCEPTIONS));
    assert!(features.contains(WasmFeatures::MEMORY64));
    assert!(engine.get_memory_may_move());
    assert!(engine.get_gc_heap_may_move());
    Ok(())
}

#[test]
fn normal_page_growth_boundaries_never_report_backing_failure() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let root = GuestMemoryLimiter::new_root(limits(2 * PAGE));
    let module = Module::new(
        &engine,
        "(module (memory 1 1) (func (export \"grow\") (param i32) (result i32) local.get 0 memory.grow))",
    )?;
    let mut memory32 = store(&engine, root.new_child());
    memory32.set_fuel(1_000_000)?;
    let instance = Instance::new(&mut memory32, &module, &[])?;
    let grow = instance.get_typed_func::<i32, i32>(&mut memory32, "grow")?;
    assert_eq!(grow.call(&mut memory32, 0)?, 1);
    assert_eq!(grow.call(&mut memory32, 1)?, -1);
    assert_eq!(grow.call(&mut memory32, -1)?, -1);
    assert_eq!(root.admitted(), PAGE);
    drop(memory32);

    let module = Module::new(
        &engine,
        "(module (memory i64 1 1) (func (export \"grow\") (param i64) (result i64) local.get 0 memory.grow))",
    )?;
    let mut memory64 = store(&engine, root.new_child());
    memory64.set_fuel(1_000_000)?;
    let instance = Instance::new(&mut memory64, &module, &[])?;
    let grow = instance.get_typed_func::<i64, i64>(&mut memory64, "grow")?;
    assert_eq!(grow.call(&mut memory64, 0)?, 1);
    assert_eq!(grow.call(&mut memory64, 1)?, -1);
    assert_eq!(grow.call(&mut memory64, -1)?, -1);
    assert_eq!(root.admitted(), PAGE);
    drop(memory64);
    assert_eq!(root.admitted(), 0);

    let mut host = store(&engine, root.new_child());
    let memory = Memory::new(&mut host, MemoryType::new(1, Some(1)))?;
    assert!(memory.grow(&mut host, 1).is_err());
    assert!(!root.backing_failed());
    Ok(())
}

#[test]
fn guest_gc_succeeds_with_budget_and_rejects_excess() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let module = Module::new(
        &engine,
        "(module (type $a (array (mut i32))) (func (export \"allocate\") (param i32) (result i32) (array.len (array.new_default $a (local.get 0)))))",
    )?;
    let root = GuestMemoryLimiter::new_root(limits(16 * PAGE));
    let mut successful = store(&engine, root.new_child());
    successful.set_fuel(1_000_000)?;
    let instance = Instance::new(&mut successful, &module, &[])?;
    let allocate = instance.get_typed_func::<i32, i32>(&mut successful, "allocate")?;
    assert_eq!(allocate.call(&mut successful, 1_000)?, 1_000);
    assert!(root.admitted() > 0);
    assert_eq!(root.admitted(), successful.gc_heap_capacity());
    assert!(!root.backing_failed());
    drop(successful);
    assert_eq!(root.admitted(), 0);

    let limited = GuestMemoryLimiter::new_root(limits(PAGE));
    let mut denied = store(&engine, limited.new_child());
    denied.set_fuel(1_000_000)?;
    let instance = Instance::new(&mut denied, &module, &[])?;
    let allocate = instance.get_typed_func::<i32, i32>(&mut denied, "allocate")?;
    let error = allocate.call(&mut denied, 100_000).unwrap_err();
    assert!(
        error
            .chain()
            .any(|cause| cause.is::<GcHeapOutOfMemory<()>>()),
        "{error:#}"
    );
    assert!(!limited.backing_failed());
    assert_eq!(limited.admitted(), 0);
    assert_eq!(denied.gc_heap_capacity(), 0);
    Ok(())
}

#[test]
fn quota_denials_preserve_a_typed_error() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let root = GuestMemoryLimiter::new_root(limits(PAGE));
    let mut initial = store(&engine, root.new_child());
    let error = Memory::new(&mut initial, MemoryType::new(2, None)).unwrap_err();
    assert!(error.is::<GuestMemoryLimitExceeded>(), "{error:#}");
    assert_eq!(root.admitted(), 0);

    let oversized = Module::new(&engine, "(module (memory 2))")?;
    let mut instantiate = store(&engine, root.new_child());
    let error = Instance::new(&mut instantiate, &oversized, &[]).unwrap_err();
    assert!(error.is::<GuestMemoryLimitExceeded>(), "{error:#}");
    assert_eq!(root.admitted(), 0);

    let module = Module::new(
        &engine,
        "(module (memory 1) (func (export \"grow\") (result i32) i32.const 1 memory.grow))",
    )?;
    let mut growth = store(&engine, root.new_child());
    growth.set_fuel(1_000_000)?;
    let instance = Instance::new(&mut growth, &module, &[])?;
    let grow = instance.get_typed_func::<(), i32>(&mut growth, "grow")?;
    let error = grow.call(&mut growth, ()).unwrap_err();
    assert!(error.is::<GuestMemoryLimitExceeded>(), "{error:#}");
    assert_eq!(root.admitted(), PAGE);
    Ok(())
}

#[tokio::test]
async fn runtime_defaults_reject_excess_initial_memory_and_growth() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let mut store = runtime.make_store(1_000_000)?;
    let root = store.data().guest_memory_limiter.as_ref().unwrap().clone();
    let limit_pages = 8192;

    // Both requests exceed the default 512 MiB quota before allocating it.
    let error = Memory::new(&mut store, MemoryType::new(limit_pages + 1, None)).unwrap_err();
    assert!(error.is::<GuestMemoryLimitExceeded>(), "{error:#}");
    assert_eq!(root.admitted(), 0);

    let memory = Memory::new(&mut store, MemoryType::new(1, None))?;
    let error = memory.grow(&mut store, u64::from(limit_pages)).unwrap_err();
    assert!(error.is::<GuestMemoryLimitExceeded>(), "{error:#}");
    assert_eq!(root.admitted(), PAGE);
    memory.grow(&mut store, 1)?;
    assert_eq!(root.admitted(), 2 * PAGE);
    drop(store);
    assert_eq!(root.admitted(), 0);
    Ok(())
}

#[tokio::test]
async fn runtime_nested_stores_share_and_release_multi_memory_budget() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.guest_memory_limits = Some(limits(5 * PAGE));
    let mut parent = runtime.make_store(1_000_000)?;
    let root = parent.data().guest_memory_limiter.as_ref().unwrap().clone();
    let parent_memory = Memory::new(&mut parent, MemoryType::new(2, Some(3)))?;
    let _second = Memory::new(&mut parent, MemoryType::new(1, Some(3)))?;
    let mut child = parent.data().make_store(1_000_000)?;
    let _child_memory = Memory::new(&mut child, MemoryType::new(2, Some(3)))?;
    assert_eq!(root.admitted(), 5 * PAGE);
    assert!(Memory::new(&mut child, MemoryType::new(1, Some(3))).is_err());
    assert!(parent_memory.grow(&mut parent, 1).is_err());
    drop(child);
    assert_eq!(root.admitted(), 3 * PAGE);
    parent_memory.grow(&mut parent, 1)?;
    assert_eq!(root.admitted(), 4 * PAGE);
    drop(parent);
    assert_eq!(root.admitted(), 0);

    let mut next = runtime.make_store(1_000_000)?;
    let _next_memory = Memory::new(&mut next, MemoryType::new(5, None))?;
    assert_eq!(
        next.data()
            .guest_memory_limiter
            .as_ref()
            .unwrap()
            .admitted(),
        5 * PAGE
    );
    Ok(())
}

#[test]
fn nested_stores_share_and_release_table_slots() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let module = Module::new(
        &engine,
        "(module (table 2 3 funcref) (func (export \"grow\") (param i32) (result i32) ref.null func local.get 0 table.grow))",
    )?;
    let root = GuestMemoryLimiter::new_root(GuestMemoryLimits {
        table_elements_per_root: 5,
        ..limits(PAGE)
    });
    let mut parent = store(&engine, root.new_child());
    parent.set_fuel(1_000_000)?;
    let instance = Instance::new(&mut parent, &module, &[])?;
    let parent_grow = instance.get_typed_func::<i32, i32>(&mut parent, "grow")?;
    assert_eq!(root.table_elements_admitted(), 2);
    drop(parent.data().limiter.clone());
    assert_eq!(root.table_elements_admitted(), 2);

    let mut child = store(&engine, parent.data().limiter.new_child());
    child.set_fuel(1_000_000)?;
    let instance = Instance::new(&mut child, &module, &[])?;
    let child_grow = instance.get_typed_func::<i32, i32>(&mut child, "grow")?;
    assert_eq!(child_grow.call(&mut child, 0)?, 2);
    assert_eq!(root.table_elements_admitted(), 4);
    assert_eq!(child_grow.call(&mut child, 1)?, 2);
    assert_eq!(root.table_elements_admitted(), 5);
    assert_eq!(parent_grow.call(&mut parent, 1)?, -1);
    assert_eq!(child_grow.call(&mut child, 1)?, -1);
    assert_eq!(root.table_elements_admitted(), 5);

    let mut denied = store(&engine, parent.data().limiter.new_child());
    denied.set_fuel(1_000_000)?;
    let error = Instance::new(&mut denied, &module, &[]).unwrap_err();
    assert!(
        error.to_string().contains("table minimum size"),
        "{error:#}"
    );
    assert_eq!(root.table_elements_admitted(), 5);
    drop(denied);
    drop(child);
    assert_eq!(root.table_elements_admitted(), 2);
    assert_eq!(parent_grow.call(&mut parent, 1)?, 2);
    assert_eq!(root.table_elements_admitted(), 3);
    assert_eq!(parent_grow.call(&mut parent, 1)?, -1);
    assert_eq!(parent_grow.call(&mut parent, 0)?, 3);
    assert_eq!(root.table_elements_admitted(), 3);
    drop(parent);
    assert_eq!(root.table_elements_admitted(), 0);
    Ok(())
}
