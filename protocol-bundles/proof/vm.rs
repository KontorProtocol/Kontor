use std::future::Future;
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
        .wasm_component_model_async(true)
        .consume_lifting_fuel(Some(LiftingPrices {
            lift_value: rate,
            string_byte: 16,
            metadata_byte: 16,
        }))
        .memory_init_cow(false)
        .wasm_custom_page_sizes(false)
        .allocation_strategy(InstanceAllocationStrategy::OnDemand)
        .memory_may_move(true)
        .wasm_threads(false)
        .wasm_relaxed_simd(false)
        .cranelift_nan_canonicalization(true);
    let engine = Engine::new(&config)?;
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

pub fn run() -> (u64, usize) {
    exercise().unwrap()
}
