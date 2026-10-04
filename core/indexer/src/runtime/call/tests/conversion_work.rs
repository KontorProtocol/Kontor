use std::mem::{align_of, size_of};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use wasmtime::component::{Component, Linker, ResourceAny, Val};
use wasmtime::{Error as WasmtimeError, Trap};

use crate::runtime::fuel::{Fuel, FuelGauge, record_fuel};
use crate::runtime::{ChallengeInput, ExecutionError, RawFileDescriptor, Runtime};
use crate::test_utils::test_runtime;

const BUDGET: u64 = 10_000_000;
const ALLOCATION_ERROR: &str = "too much data is being copied between the host and the guest: fuel allocated for hostcalls has been exhausted";

#[test]
fn lifting_allowance_layouts_match_supported_node_targets() {
    // These native layouts determine consensus lifting charges. Compiler or
    // dependency upgrades must not change them without a pricing decision.
    assert_eq!(
        [
            size_of::<Val>(),
            size_of::<(Val, Val)>(),
            size_of::<u8>(),
            size_of::<Vec<u8>>(),
            size_of::<(Vec<u8>, u64, u64)>(),
            size_of::<(String, Vec<u8>, u64, u64)>(),
            size_of::<ChallengeInput>(),
            size_of::<RawFileDescriptor>(),
            size_of::<ResourceAny>(),
        ],
        [48, 96, 1, 24, 40, 64, 208, 136, 40],
    );
    assert_eq!(
        [
            align_of::<Val>(),
            align_of::<(Val, Val)>(),
            align_of::<u8>(),
            align_of::<Vec<u8>>(),
            align_of::<(Vec<u8>, u64, u64)>(),
            align_of::<(String, Vec<u8>, u64, u64)>(),
            align_of::<ChallengeInput>(),
            align_of::<RawFileDescriptor>(),
            align_of::<ResourceAny>(),
        ],
        [8, 8, 1, 8, 8, 8, 8, 8, 8],
    );
}

// Keep engine conversion costs separate from tariffs for work inside imports.
#[tokio::test]
async fn repeated_lifting_spends_store_fuel_in_addition_to_host_work() -> Result<()> {
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
            engine_costs[1] - engine_costs[0],
            u64::from(count) * (8192 - 8),
            "each lifted byte must spend Store fuel even when the allowance resets"
        );
    }
    Ok(())
}

#[tokio::test]
async fn lifting_allowance_and_store_fuel_precede_import_entry() -> Result<()> {
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
            assert_eq!(bytes.load(Ordering::Relaxed), 0);
            assert_eq!(store.get_fuel()?, 0);
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
async fn lifted_results_spend_the_reported_budget_before_serialization() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    for fixture in [
        include_str!("fixtures/abi-string-return.wat"),
        include_str!("fixtures/abi-async-string-return.wat"),
    ] {
        let component = Component::new(&runtime.engine, fixture)?;
        let mut costs = Vec::new();
        for length in [0, 8] {
            let mut store = runtime.make_store(BUDGET)?;
            let instance = Linker::new(&runtime.engine)
                .instantiate_async(&mut store, &component)
                .await?;
            let func = instance.get_func(&mut store, "run").unwrap();
            store.set_fuel(BUDGET)?;
            let mut results = [Val::Bool(false)];
            func.call_async(&mut store, &[Val::U32(0), Val::U32(length)], &mut results)
                .await?;
            assert_eq!(results, [Val::String("abcdefgh"[..length as usize].into())]);
            costs.push(BUDGET - store.get_fuel()?);
        }
        assert_eq!(costs[1] - costs[0], 8);
        // The async fixture runs more guest instructions after returning its
        // result. Use less than the lifting charge itself to force exhaustion.
        for budget in [7, costs[1]] {
            let gauge = FuelGauge::with_profiling();
            runtime.gauge = Some(gauge.clone());
            let mut store = runtime.make_store(BUDGET)?;
            let instance = Linker::new(&runtime.engine)
                .instantiate_async(&mut store, &component)
                .await?;
            let func = instance.get_func(&mut store, "run").unwrap();
            store.set_fuel(budget)?;
            store.data_mut().fuel_checkpoint = budget;
            let mut results = [Val::Bool(false)];
            let result = func
                .call_async(&mut store, &[Val::U32(0), Val::U32(8)], &mut results)
                .await;
            if budget < costs[1] {
                assert_eq!(
                    result.unwrap_err().downcast_ref::<Trap>(),
                    Some(&Trap::OutOfFuel)
                );
            } else {
                result?;
                assert_eq!(results, [Val::String("abcdefgh".into())]);
            }
            assert_eq!(store.get_fuel()?, 0);
            record_fuel(&mut store)?;
            let report = gauge.report()?;
            assert_eq!(report.usage.user_fuel + report.usage.system_fuel, budget);
            assert_eq!(report.profile.unwrap().consumed_host_fuel, 0);
        }
        runtime.gauge = None;
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
