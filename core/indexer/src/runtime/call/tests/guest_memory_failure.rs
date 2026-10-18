use std::ptr::null_mut;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use libsql::params;
use rustix::mm::{MapFlags, MprotectFlags, ProtFlags, mmap_anonymous, mprotect, munmap};
use rustix::param::page_size;
use wasmtime::component::Component;
use wasmtime::{
    Config, Engine, Error, GcHeapOutOfMemory, Instance, InstanceAllocationStrategy, LinearMemory,
    MemoryCreator, MemoryType, Module, Result as WasmtimeResult, Store,
};

use super::funded;
use crate::runtime::guest_memory::{GuestMemoryLimiter, GuestMemoryLimits};
use crate::runtime::{ContractAddress, ExecutionError, Runtime, TransactionContext};
use crate::test_utils::test_runtime;

const PAGE: usize = 65_536;

#[derive(Clone, Copy)]
enum Kind {
    Linear,
    Gc,
}

struct FailingMemory {
    mapping: usize,
    mapping_len: usize,
    size: usize,
    failures: Arc<AtomicUsize>,
}

impl Drop for FailingMemory {
    fn drop(&mut self) {
        unsafe { munmap(self.mapping as *mut _, self.mapping_len).expect("valid mapping") };
    }
}

// SAFETY: The mapping is page-aligned and zero-filled. Its final page is a
// protected guard, and growth fails before either the size or base can change.
unsafe impl LinearMemory for FailingMemory {
    fn byte_size(&self) -> usize {
        self.size
    }

    fn byte_capacity(&self) -> usize {
        2 * PAGE
    }

    fn grow_to(&mut self, _new_size: usize) -> WasmtimeResult<()> {
        self.failures.fetch_add(1, Ordering::SeqCst);
        Err(Error::msg("injected backing failure"))
    }

    fn as_ptr(&self) -> *mut u8 {
        self.mapping as *mut u8
    }
}

struct FailingCreator {
    kind: Kind,
    failures: Arc<AtomicUsize>,
}

// SAFETY: Each returned memory exclusively owns its guarded mapping. The
// creator keeps only the failure counter, never a pointer to the mapping.
unsafe impl MemoryCreator for FailingCreator {
    fn new_memory(
        &self,
        _ty: MemoryType,
        minimum: usize,
        maximum: Option<usize>,
        reserved_size_in_bytes: Option<usize>,
        guard_size_in_bytes: usize,
    ) -> StdResult<Box<dyn LinearMemory>, String> {
        match self.kind {
            Kind::Linear => {
                assert_eq!(minimum, PAGE);
                assert_eq!(maximum, Some(2 * PAGE));
            }
            Kind::Gc => {
                assert_eq!(minimum, 0);
                assert_eq!(maximum, Some(1 << 32));
            }
        }
        assert_eq!(reserved_size_in_bytes, Some(0));
        assert_eq!(guard_size_in_bytes, 0);
        let host_page = page_size();
        assert_eq!(PAGE % host_page, 0);
        let mapping_len = 2 * PAGE + host_page;
        let mapping = unsafe {
            mmap_anonymous(
                null_mut(),
                mapping_len,
                ProtFlags::empty(),
                MapFlags::PRIVATE,
            )
        }
        .map_err(|error| error.to_string())?;
        if minimum != 0
            && let Err(error) =
                unsafe { mprotect(mapping, minimum, MprotectFlags::READ | MprotectFlags::WRITE) }
        {
            unsafe { munmap(mapping, mapping_len).expect("valid mapping") };
            return Err(error.to_string());
        }
        Ok(Box::new(FailingMemory {
            mapping: mapping as usize,
            mapping_len,
            size: minimum,
            failures: self.failures.clone(),
        }))
    }
}

fn failure_engine(kind: Kind, failures: Arc<AtomicUsize>) -> Result<Engine> {
    let mut config = Config::new();
    config
        .with_host_memory(Arc::new(FailingCreator { kind, failures }))
        .wasm_component_model_async(true)
        .consume_fuel(true)
        .allocation_strategy(InstanceAllocationStrategy::OnDemand)
        .wasm_custom_page_sizes(false)
        .wasm_threads(false)
        .memory_init_cow(false)
        .memory_may_move(true)
        .signals_based_traps(false)
        .memory_reservation(0)
        .memory_reservation_for_growth(0)
        .memory_guard_size(0);
    Ok(Engine::new(&config)?)
}

fn limits() -> GuestMemoryLimits {
    GuestMemoryLimits {
        per_root: 16 * PAGE,
        memories: 4,
        instances: 8,
        tables: 4,
        table_elements: 16,
    }
}

struct State {
    limiter: GuestMemoryLimiter,
}

fn store(engine: &Engine, limiter: GuestMemoryLimiter) -> Store<State> {
    let mut store = Store::new(engine, State { limiter });
    store.limiter(|state| &mut state.limiter);
    store
}

#[test]
fn admitted_linear_and_gc_backing_failures_are_latched() -> Result<()> {
    for (kind, wat) in [
        (
            Kind::Linear,
            "(module (memory 1 2) (func (export \"allocate\") (result i32) i32.const 1 memory.grow))",
        ),
        (
            Kind::Gc,
            "(module (type $a (array (mut i32))) (func (export \"allocate\") (result i32) (array.len (array.new_default $a (i32.const 100000)))))",
        ),
    ] {
        let failures = Arc::new(AtomicUsize::new(0));
        let engine = failure_engine(kind, failures.clone())?;
        let root = GuestMemoryLimiter::new_root(limits());
        let mut store = store(&engine, root.new_child());
        store.set_fuel(1_000_000)?;
        let module = Module::new(&engine, wat)?;
        let instance = Instance::new(&mut store, &module, &[])?;
        let allocate = instance.get_typed_func::<(), i32>(&mut store, "allocate")?;
        let error = allocate.call(&mut store, ()).unwrap_err();
        assert!(failures.load(Ordering::SeqCst) > 0);
        assert!(root.backing_failed());
        assert!(!root.quota_denied());
        assert!(root.admitted() > 0);
        if matches!(kind, Kind::Gc) {
            assert!(
                error
                    .chain()
                    .any(|cause| cause.is::<GcHeapOutOfMemory<()>>()),
                "{error:#}"
            );
        }
        drop(store);
        assert_eq!(root.admitted(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn swallowed_gc_backing_failure_aborts_before_result_persistence() -> Result<()> {
    const WAT: &str = r#"
        (component
          (import "kontor:built-in/context" (instance $context
            (export "proc-context" (type (sub resource)))))
          (alias export $context "proc-context" (type $proc-context))
          (core module $code
            (type $a (array (mut i32)))
            (func (export "succeed") (param i32) (result i64)
              local.get 0 drop
              i32.const 100000 array.new_default $a array.len drop
              i64.const 42))
          (core instance $code (instantiate $code))
          (func (export "succeed") async
            (param "ctx" (borrow $proc-context)) (result u64)
            (canon lift (core func $code "succeed"))))
    "#;
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let signer = funded(&mut runtime).await?;
    let failures = Arc::new(AtomicUsize::new(0));
    let engine = failure_engine(Kind::Gc, failures.clone())?;
    runtime.engine = engine.clone();
    runtime.linkers = Runtime::new_linkers(&engine)?;
    runtime.component_cache.clear();
    runtime.guest_memory_limits = Some(limits());
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(99).build()),
            None,
            None,
        )
        .await;
    let contract_id = runtime.storage.insert_contract("gc-backing", &[]).await?;
    runtime
        .component_cache
        .put(contract_id, Component::new(&engine, WAT)?, WAT.len())
        .await;
    let address = ContractAddress {
        name: "gc-backing".into(),
        height: 1,
        tx_index: 99,
    };
    let result = runtime
        .invoke_unsettled(&address, Some(&signer), None, "succeed()", 1_000_000, true)
        .await?
        .result;
    assert!(
        matches!(result, Err(ExecutionError::NonDeterministic(_))),
        "{result:?}"
    );
    assert!(failures.load(Ordering::SeqCst) > 0);
    assert!(runtime.stack.is_empty().await);
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    let conn = runtime.get_storage_conn();
    let mut rows = conn
        .query(
            "SELECT status FROM contract_results WHERE contract_id = ?",
            params![contract_id],
        )
        .await?;
    assert!(rows.next().await?.is_none());
    Ok(())
}
