use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use wasmtime::component::{Component, Linker, Val};
use wasmtime::{Error as WasmtimeError, Trap};

use crate::runtime::fuel::Fuel;
use crate::runtime::{ExecutionError, Runtime};
use crate::test_utils::test_runtime;

const BUDGET: u64 = 10_000_000;
const ALLOCATION_ERROR: &str = "too much data is being copied between the host and the guest: fuel allocated for hostcalls has been exhausted";

// These characterize the engine/host boundary, not production metering. Keep
// engine-only measurements separate from tariffs supplied by Kontor's imports.
#[tokio::test]
async fn repeated_conversion_needs_host_charges_not_just_an_allocation_allowance() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let component = Component::new(
        &runtime.engine,
        include_str!("fixtures/abi-repeat-import.wat"),
    )?;
    for count in [1, 4, 16] {
        let mut engine_costs = Vec::new();
        for length in [8, 8192] {
            let mut costs = Vec::new();
            for hash in [false, true] {
                let bytes = Arc::new(AtomicUsize::new(0));
                let seen = bytes.clone();
                let mut linker = Linker::<Runtime>::new(&runtime.engine);
                linker.root().func_wrap_concurrent(
                    "accept",
                    move |accessor, (input,): (String,)| {
                        let seen = seen.clone();
                        Box::pin(async move {
                            tokio::task::yield_now().await;
                            seen.fetch_add(input.len(), Ordering::Relaxed);
                            if hash {
                                let accessor = accessor.with_getter::<Runtime>(|runtime| runtime);
                                let runtime = accessor.with(|mut access| access.get().clone());
                                runtime
                                    ._sha256(&accessor, input.into_bytes())
                                    .await
                                    .map_err(WasmtimeError::from_anyhow)?;
                            }
                            Ok(())
                        })
                    },
                )?;
                let mut store = runtime.make_store(BUDGET)?;
                store.set_hostcall_fuel(length as usize);
                let instance = linker.instantiate_async(&mut store, &component).await?;
                let func = instance.get_func(&mut store, "run").unwrap();
                store.set_fuel(BUDGET)?;
                let mut results = [Val::Bool(false)];
                func.call_async(
                    &mut store,
                    &[Val::U32(length), Val::U32(count)],
                    &mut results,
                )
                .await?;
                assert_eq!(results, [Val::U32(42)]);
                assert_eq!(bytes.load(Ordering::Relaxed), (length * count) as usize);
                assert_eq!(store.hostcall_fuel(), length as usize);
                costs.push(BUDGET - store.get_fuel()?);
            }
            assert_eq!(
                costs[1] - costs[0],
                u64::from(count) * Fuel::CryptoHash(u64::from(length)).cost(),
                "host payload charge must survive each suspension and repetition"
            );
            engine_costs.push(costs[0]);
            println!(
                "ABI repeated import: count={count} bytes_per_call={length} engine_fuel={} with_hash_tariff={}",
                costs[0], costs[1]
            );
        }
        assert_eq!(
            engine_costs[0], engine_costs[1],
            "Wasmtime instruction fuel alone does not price conversion bytes"
        );
    }
    Ok(())
}

#[tokio::test]
async fn allocation_guard_precedes_import_entry_but_a_tariff_does_not() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let component = Component::new(
        &runtime.engine,
        include_str!("fixtures/abi-repeat-import.wat"),
    )?;
    let length = 8192;
    for allowance in [length - 1, length] {
        let bytes = Arc::new(AtomicUsize::new(0));
        let seen = bytes.clone();
        let mut linker = Linker::<Runtime>::new(&runtime.engine);
        linker
            .root()
            .func_wrap_concurrent("accept", move |accessor, (input,): (String,)| {
                let seen = seen.clone();
                Box::pin(async move {
                    let accessor = accessor.with_getter::<Runtime>(|runtime| runtime);
                    seen.fetch_add(input.len(), Ordering::Relaxed);
                    Fuel::CryptoHash(input.len() as u64)
                        .consume(&accessor)
                        .map_err(WasmtimeError::from_anyhow)?;
                    Ok(())
                })
            })?;
        let mut store = runtime.make_store(BUDGET)?;
        store.set_hostcall_fuel(allowance);
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let func = instance.get_func(&mut store, "run").unwrap();
        store.set_fuel(200)?;
        let mut results = [Val::Bool(false)];
        let error = func
            .call_async(
                &mut store,
                &[Val::U32(length as u32), Val::U32(1)],
                &mut results,
            )
            .await
            .unwrap_err();
        if allowance < length {
            assert_eq!(bytes.load(Ordering::Relaxed), 0);
            assert!(!error.is::<Trap>(), "{error:?}");
        } else {
            assert_eq!(bytes.load(Ordering::Relaxed), length);
            assert!(matches!(
                error.downcast_ref::<Trap>(),
                Some(Trap::OutOfFuel)
            ));
        }
        let classified =
            Runtime::decode_result(false, Ok(Err(error)), results.to_vec(), &mut store).await;
        assert!(
            matches!(classified, Err(ExecutionError::Deterministic(_))),
            "{classified:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn record_fields_require_allocation_allowance_and_structural_fuel() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for count in [16, 128, 512] {
        let fields = (0..count)
            .map(|i| format!(r#"(field "field{i:04}" (option u32))"#))
            .collect::<Vec<_>>()
            .join(" ");
        // All cases exceed the async flattening limit. The guest returns the
        // same pointer into zeroed memory, independently of the record's width.
        let wat = format!(
            r#"(component
                (type $inner (record {fields}))
                (export $record "record" (type $inner))
                (core module $memory (memory (export "memory") 1))
                (core instance $memory (instantiate $memory))
                (core func $return
                    (canon task.return (result $record) (memory $memory "memory")))
                (core module $code
                    (import "host" "return" (func $return (param i32)))
                    (func (export "run") (result i32)
                        i32.const 0 call $return i32.const 0)
                    (func (export "callback") (param i32 i32 i32) (result i32)
                        i32.const 0))
                (core instance $code (instantiate $code
                    (with "host" (instance (export "return" (func $return))))))
                (func (export "run") async (result $record)
                    (canon lift (core func $code "run") async
                        (memory $memory "memory") (callback (func $code "callback")))))"#
        );
        let component = Component::new(&runtime.engine, wat)?;
        let mut store = runtime.make_store(BUDGET)?;
        store.set_hostcall_fuel(0);
        let instance = Linker::new(&runtime.engine)
            .instantiate_async(&mut store, &component)
            .await?;
        let func = instance.get_func(&mut store, "run").unwrap();
        let mut results = [Val::Bool(false)];
        let error = func
            .call_async(&mut store, &[], &mut results)
            .await
            .unwrap_err();
        assert_eq!(error.root_cause().to_string(), ALLOCATION_ERROR);

        let mut store = runtime.make_store(BUDGET)?;
        store.set_hostcall_fuel(BUDGET as usize);
        let instance = Linker::new(&runtime.engine)
            .instantiate_async(&mut store, &component)
            .await?;
        let func = instance.get_func(&mut store, "run").unwrap();
        let mut results = [Val::Bool(false)];
        func.call_async(&mut store, &[], &mut results).await?;
        let Val::Record(fields) = &results[0] else {
            panic!("expected a record");
        };
        assert_eq!(fields.len(), count);
        assert!(fields.iter().all(|(_, value)| *value == Val::Option(None)));
        let labels: usize = fields.iter().map(|(name, _)| name.len()).sum();
        assert_eq!(labels, count * 9);
        let expected = "{:}";
        let ty = func.ty(&store).results().next().unwrap();
        assert_eq!(Val::from_wave(&ty, expected)?, results[0]);
        let budget = Fuel::Result.cost() + Fuel::ResultBytes(expected.len() as u64).cost();
        store.set_fuel(budget)?;
        let result = Runtime::decode_result(false, Ok(Ok(())), results.to_vec(), &mut store).await;
        assert!(
            matches!(result, Err(ExecutionError::Deterministic(ref error))
            if matches!(error.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)))
        );
        let budget = budget + (count as u64 + 1) * Fuel::WaveValue.cost();
        store.set_fuel(budget)?;
        assert_eq!(
            Runtime::decode_result(false, Ok(Ok(())), results.to_vec(), &mut store).await?,
            expected
        );
        assert_eq!(store.get_fuel()?, 0);
        println!(
            "ABI omitted record: fields={count} labels={labels} output_bytes={} output_fuel={budget}",
            expected.len()
        );
    }
    Ok(())
}
