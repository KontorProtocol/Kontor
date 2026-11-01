use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

#[cfg(feature = "kontor")]
use wasmtime::InstanceAllocationStrategy;
use wasmtime::component::{Component, Linker};
use wasmtime::{
    Config, Engine, Instance, LiftingPrices, Module, ProfilingStrategy, Result, Store, Trap,
};

struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn complete<T>(future: impl Future<Output = T>) -> (T, usize) {
    let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    for _ in 0..100_000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return (value, counter.0.load(Ordering::Relaxed));
        }
    }
    panic!("fuel-yielding VM did not finish within the test polling bound");
}

fn exercise() -> Result<(u64, usize)> {
    let rate: u64 = env!("BUNDLE_LIFT_RATE").parse().unwrap();
    let mut config = Config::new();
    config.target("pulley64")?;
    config.max_wasm_stack(524_288).async_stack_size(2_097_152);
    config.wasm_component_model_async(false);
    config.wasm_component_model_more_async_builtins(false);
    config.wasm_component_model_async_stackful(false);
    config.wasm_component_model_threading(false);
    config.wasm_component_model_error_context(false);
    config.wasm_shared_everything_threads(false);
    config.wasm_stack_switching(false);
    config.concurrency_support(false);
    config.wasm_threads(false);
    // Independent Mach-port handlers overwrite each other's per-thread port.
    // Unix handlers can delegate faults to the other retained VM's handler.
    config
        .macos_use_mach_ports(false)
        .debug_info(false)
        .profiler(ProfilingStrategy::None)
        .consume_fuel(true)
        .consume_lifting_fuel(Some(LiftingPrices {
            lift_value: rate,
            string_byte: 7,
            metadata_byte: 11,
        }));
    #[cfg(feature = "kontor")]
    config
        .consume_lifting_fuel(Some(LiftingPrices {
            lift_value: rate,
            string_byte: 16,
            metadata_byte: 16,
        }))
        .memory_init_cow(false)
        .wasm_custom_page_sizes(false)
        .allocation_strategy(InstanceAllocationStrategy::OnDemand)
        .memory_may_move(true)
        .wasm_relaxed_simd(false)
        .cranelift_nan_canonicalization(true);
    let engine = Engine::new(&config)?;
    assert!(engine.is_pulley());
    assert_eq!(
        engine.get_target().as_deref(),
        Some("pulley64-unknown-unknown-elf")
    );
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
    assert_eq!(engine.get_max_wasm_stack(), 524_288);
    assert_eq!(engine.get_async_stack_size(), 2_097_152);
    println!(
        "KONTOR_VM_ATTESTATION {}",
        serde_json::json!({
            "graph": env!("BUNDLE_GRAPH"),
            "target": engine.get_target().unwrap(),
            "max_wasm_stack": engine.get_max_wasm_stack(),
            "async_stack_size": engine.get_async_stack_size(),
            "logical_stack_alignment": 16,
            "guest_concurrency": engine.get_concurrency_support(),
            "lift_rate": rate,
        })
    );
    host_suspension(&engine, rate)?;
    let component = Component::new(
        &engine,
        r#"(component
          (core module $m (func (export "run") (result i32) (i32.const 42)))
          (core instance $i (instantiate $m))
          (func (export "run") (result u32) (canon lift (core func $i "run"))))"#,
    )?;
    let mut store = Store::new(&engine, ());
    store.set_hostcall_fuel_enabled(false);
    store.set_fuel(1_000_000)?;
    let instance = Linker::new(&engine).instantiate(&mut store, &component)?;
    store.set_fuel(1_000_000)?;
    let run = instance.get_typed_func::<(), (u32,)>(&mut store, "run")?;
    assert_eq!(run.call(&mut store, ())?.0, 42);
    let charged = 1_000_000 - store.get_fuel()?;
    assert_eq!(charged, 2 + 2 * rate);

    #[cfg(feature = "kontor")]
    {
        let mut async_store = Store::new(&engine, ());
        async_store.set_hostcall_fuel_enabled(false);
        async_store.set_fuel(1_000_000)?;
        let linker = Linker::new(&engine);
        let (instance, _) = complete(linker.instantiate_async(&mut async_store, &component));
        let instance = instance?;
        let run = instance.get_typed_func::<(), (u32,)>(&mut async_store, "run")?;
        async_store.set_fuel(1_000_000)?;
        let (result, _) = complete(run.call_async(&mut async_store, ()));
        assert_eq!(result?.0, 42);
        assert_eq!(1_000_000 - async_store.get_fuel()?, charged);
    }

    let module = Module::new(
        &engine,
        r#"(module
          (memory 1)
          (func (export "load") (param i32) (result i32)
            (i32.load (local.get 0)))
          (func $recurse (export "recurse") (call $recurse))
          (func (export "spin") (loop $again (br $again))))"#,
    )?;
    let instance = Instance::new(&mut store, &module, &[])?;
    let load = instance.get_typed_func::<u32, u32>(&mut store, "load")?;
    let error = load.call(&mut store, 65536).unwrap_err();
    assert_eq!(error.downcast_ref::<Trap>(), Some(&Trap::MemoryOutOfBounds));
    store.set_fuel(1_000_000)?;
    let recurse = instance.get_typed_func::<(), ()>(&mut store, "recurse")?;
    let error = recurse.call(&mut store, ()).unwrap_err();
    assert_eq!(error.downcast_ref::<Trap>(), Some(&Trap::StackOverflow));

    store.set_fuel(1000)?;
    store.fuel_async_yield_interval(Some(10))?;
    let spin = instance.get_typed_func::<(), ()>(&mut store, "spin")?;
    let (result, wakes) = complete(spin.call_async(&mut store, ()));
    assert_eq!(
        result.unwrap_err().downcast_ref::<Trap>(),
        Some(&Trap::OutOfFuel)
    );
    assert!(wakes > 0, "async fiber never yielded");
    Ok((charged, wakes))
}

fn host_suspension(engine: &Engine, rate: u64) -> Result<()> {
    let component = Component::new(
        engine,
        r#"(component
      (import "increment" (func $increment (param "value" u32) (result u32)))
      (core func $lowered (canon lower (func $increment)))
      (core module $m
        (import "host" "increment" (func $increment (param i32) (result i32)))
        (func (export "run") (result i32) (call $increment (i32.const 41))))
      (core instance $host (export "increment" (func $lowered)))
      (core instance $i (instantiate $m (with "host" (instance $host))))
      (func (export "run") (result u32) (canon lift (core func $i "run"))))"#,
    )?;
    let mut charges = Vec::new();
    for suspend in [false, true] {
        let mut linker = Linker::<()>::new(engine);
        linker
            .root()
            .func_wrap_async("increment", move |_, (value,): (u32,)| {
                Box::new(async move {
                    let mut pending = suspend;
                    poll_fn(|cx| {
                        if pending {
                            pending = false;
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        } else {
                            Poll::Ready(())
                        }
                    })
                    .await;
                    Ok((value + 1,))
                })
            })?;
        let mut store = Store::new(engine, ());
        store.set_hostcall_fuel_enabled(false);
        store.set_fuel(1_000_000)?;
        let (instance, _) = complete(linker.instantiate_async(&mut store, &component));
        let run = instance?.get_typed_func::<(), (u32,)>(&mut store, "run")?;
        store.set_fuel(1_000_000)?;
        let (result, wakes) = complete(run.call_async(&mut store, ()));
        assert_eq!(result?.0, 42);
        assert_eq!(
            wakes > 0,
            suspend,
            "host suspension did not reach the executor"
        );
        charges.push(1_000_000 - store.get_fuel()?);
    }
    assert_eq!(charges[0], charges[1], "host readiness changed metering");
    assert_eq!(charges[0], 3 + 4 * rate);
    println!("Host suspension fuel: {}", charges[0]);
    Ok(())
}

pub fn run() -> (u64, usize) {
    exercise().unwrap()
}
