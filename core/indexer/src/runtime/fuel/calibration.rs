use std::env::consts::{ARCH, OS};
use std::hint::black_box;
use std::time::Instant;

use anyhow::{Result, ensure};
use serde_json::{Value, json};
use stdlib::KeyElement;
use wasmtime::component::{Accessor, Resource};
use wasmtime::{Instance, Module, Store};

use crate::runtime::numerics::u64_to_integer;
use crate::runtime::wit::ProcStorage;
use crate::runtime::wit::kontor::built_in::{
    context::{HostProcStorageWithStore as StorageHost, HostStorageRowsWithStore as RowsHost},
    crypto::HostWithStore as CryptoHost,
    numbers::HostWithStore as NumbersHost,
};
use crate::runtime::{Runtime, TransactionContext, hash_bytes};
use crate::test_utils::test_runtime;

const BUDGET: u64 = 1_000_000_000_000;
const SAMPLES: usize = 7;

fn emit(name: &str, input: &Value, sample: usize, iterations: u64, ns: u128, fuel: u64) {
    println!(
        "FUEL_CALIBRATION {}",
        json!({
            "case": name, "input": input, "sample": sample, "iterations": iterations,
            "elapsed_ns": ns, "consumed_fuel": fuel,
        })
    );
}

// One warmup batch, then independent fuel budgets per sample. Profiling stays
// disabled so its mutex and retained events do not dominate small operations.
async fn measure_host<R>(
    store: &mut Store<Runtime>,
    name: &str,
    input: Value,
    iterations: u64,
    mut operation: impl AsyncFnMut(&Accessor<Runtime, Runtime>) -> Result<R>,
) -> Result<()> {
    for sample in 0..=SAMPLES {
        store.set_fuel(BUDGET)?;
        let start = Instant::now();
        store
            .run_concurrent(async |accessor| -> Result<()> {
                let accessor = accessor.with_getter::<Runtime>(|runtime| runtime);
                for _ in 0..iterations {
                    black_box(operation(&accessor).await?);
                }
                Ok(())
            })
            .await??;
        let elapsed = start.elapsed().as_nanos();
        if sample > 0 {
            emit(
                name,
                &input,
                sample - 1,
                iterations,
                elapsed,
                BUDGET - store.get_fuel()?,
            );
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "manual release-mode fuel calibration; run without concurrent benchmarks"]
async fn fuel_calibration() -> Result<()> {
    ensure!(!cfg!(debug_assertions), "calibration requires --release");
    println!(
        "FUEL_CALIBRATION {}",
        json!({"metadata": {"os": OS, "arch": ARCH, "samples": SAMPLES,
        "scope": "host-direct and core-wasm; warm caches; no timing assertions"}})
    );
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    let mut store = runtime.make_store(BUDGET)?;
    measure_host(&mut store, "harness", json!({}), 512, async |_| Ok(())).await?;

    // Separate wrapper setup from the underlying primitive before fitting costs.
    measure_host(
        &mut store,
        "runtime-clone",
        json!({}),
        512,
        async |accessor| Ok(accessor.with(|mut access| access.get().clone())),
    )
    .await?;
    measure_host(
        &mut store,
        "linkers-clone",
        json!({}),
        512,
        async |accessor| Ok(accessor.with(|mut access| access.get().linkers.clone())),
    )
    .await?;

    for bytes in [0, 64, 1024, 16_384, 65_536] {
        let input = vec![0x5a; bytes];
        measure_host(
            &mut store,
            "sha256-primitive",
            json!({"bytes": bytes}),
            512,
            async |_| Ok(hash_bytes(black_box(&input))),
        )
        .await?;
        measure_host(
            &mut store,
            "sha256",
            json!({"bytes": bytes}),
            512,
            async |accessor| {
                <Runtime as CryptoHost<Runtime>>::sha256(accessor, input.clone()).await
            },
        )
        .await?;
        measure_host(
            &mut store,
            "hkdf",
            json!({"ikm_bytes": bytes, "salt_bytes": 0, "info_bytes": 0}),
            512,
            async |accessor| {
                <Runtime as CryptoHost<Runtime>>::hkdf_derive(
                    accessor,
                    input.clone(),
                    vec![],
                    vec![],
                )
                .await
            },
        )
        .await?;
    }
    for operand in [1, u64::MAX] {
        let value = u64_to_integer(operand);
        measure_host(
            &mut store,
            "integer-add",
            json!({"operand": operand}),
            4096,
            async |accessor| {
                let result =
                    <Runtime as NumbersHost<Runtime>>::add_integer(accessor, value, value).await?;
                ensure!(result.is_ok(), "integer addition failed");
                Ok(result)
            },
        )
        .await?;
        measure_host(
            &mut store,
            "integer-sqrt",
            json!({"operand": operand}),
            4096,
            async |accessor| {
                let result =
                    <Runtime as NumbersHost<Runtime>>::sqrt_integer(accessor, value).await?;
                ensure!(result.is_ok(), "integer square root failed");
                Ok(result)
            },
        )
        .await?;
    }

    // A real, non-deposit-exempt contract id exercises storage bookkeeping.
    // No call frame means no payer reservation; collateral is not CPU/IO work.
    let contract_id = runtime.storage.insert_contract("calibration", &[]).await?;
    let handle = store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id })?;
    let rep = handle.rep();
    let mut prefix = Vec::new();
    String::from("entries").encode_to(&mut prefix);
    let mut missing = prefix.clone();
    u64::MAX.encode_to(&mut missing);
    for population in [1_u64, 1024, 16_384] {
        runtime.storage.savepoint().await?;
        for key in 0..population {
            let mut path = prefix.clone();
            key.encode_to(&mut path);
            runtime
                .storage
                .set(
                    contract_id,
                    &path,
                    &indexer_types::serialize(&key)?,
                    None,
                    None,
                )
                .await?;
        }
        // All samples use the same fixture, rolled back after the group.
        let mut present = prefix.clone();
        (population / 2).encode_to(&mut present);
        for (label, path, expected) in [
            ("get-present", &present, Some(population / 2)),
            ("get-missing", &missing, None),
        ] {
            measure_host(
                &mut store,
                label,
                json!({"population": population, "path_bytes": path.len()}),
                128,
                async |accessor| {
                    let result = <Runtime as StorageHost<Runtime>>::get_u64(
                        accessor,
                        Resource::new_borrow(rep),
                        path.clone(),
                    )
                    .await?;
                    ensure!(result == expected, "unexpected storage fixture result");
                    Ok(result)
                },
            )
            .await?;
        }
        measure_host(
            &mut store,
            "scan-all",
            json!({"population": population}),
            4,
            async |accessor| {
                let cursor = <Runtime as StorageHost<Runtime>>::get_storage_rows(
                    accessor,
                    Resource::new_borrow(rep),
                    prefix.clone(),
                    None,
                    None,
                    false,
                )
                .await?;
                let mut count = 0;
                while <Runtime as RowsHost<Runtime>>::next_u64(
                    accessor,
                    Resource::new_borrow(cursor.rep()),
                )
                .await?
                .is_some()
                {
                    count += 1;
                }
                <Runtime as RowsHost<Runtime>>::drop(accessor, cursor).await?;
                ensure!(count == population, "scan omitted fixture rows");
                Ok(count)
            },
        )
        .await?;
        runtime.storage.rollback().await?;
    }

    let mut path = Vec::new();
    String::from("value").encode_to(&mut path);
    for bytes in [0, 64, 1024, 16_384] {
        runtime.storage.savepoint().await?;
        let value = vec![0x5a; bytes];
        runtime
            .storage
            .set(
                contract_id,
                &path,
                &indexer_types::serialize(&value)?,
                None,
                None,
            )
            .await?;
        measure_host(
            &mut store,
            "get-bytes",
            json!({"bytes": bytes}),
            128,
            async |accessor| {
                let result = <Runtime as StorageHost<Runtime>>::get_list_u8(
                    accessor,
                    Resource::new_borrow(rep),
                    path.clone(),
                )
                .await?;
                ensure!(result.as_ref() == Some(&value), "unexpected stored value");
                Ok(result)
            },
        )
        .await?;
        measure_host(
            &mut store,
            "overwrite-bytes",
            json!({"bytes": bytes, "depositor": false}),
            128,
            async |accessor| {
                <Runtime as StorageHost<Runtime>>::set_list_u8(
                    accessor,
                    Resource::new_borrow(rep),
                    path.clone(),
                    value.clone(),
                )
                .await
            },
        )
        .await?;
        runtime.storage.rollback().await?;
    }
    wasm_samples(&runtime).await?;
    Ok(())
}

async fn wasm_samples(runtime: &Runtime) -> Result<()> {
    let module = Module::new(
        &runtime.engine,
        r#"(module
        (memory 2)
        (data (i32.const 0) "x")
        (func (export "integer-loop") (param $n i32) (result i32) (local $x i32)
            (block $done (loop $loop
                (br_if $done (i32.eqz (local.get $n)))
                (local.set $x (i32.xor (i32.rotl (local.get $x) (i32.const 1)) (local.get $n)))
                (local.set $n (i32.sub (local.get $n) (i32.const 1)))
                (br $loop)))
            (local.get $x))
        (func (export "memory-copy") (param $n i32) (result i32)
            (memory.copy (i32.const 65536) (i32.const 0) (local.get $n))
            (i32.load8_u (i32.const 65536))))"#,
    )?;
    let mut store = runtime.make_store(BUDGET)?;
    let instance = Instance::new_async(&mut store, &module, &[]).await?;
    for name in ["integer-loop", "memory-copy"] {
        let function = instance.get_typed_func::<i32, i32>(&mut store, name)?;
        for size in [0, 64, 1024, 65_536] {
            for sample in 0..=SAMPLES {
                store.set_fuel(BUDGET)?;
                let start = Instant::now();
                for _ in 0..128 {
                    black_box(function.call_async(&mut store, black_box(size)).await?);
                }
                let elapsed = start.elapsed().as_nanos();
                if sample > 0 {
                    emit(
                        name,
                        &json!({"size": size}),
                        sample - 1,
                        128,
                        elapsed,
                        BUDGET - store.get_fuel()?,
                    );
                }
            }
        }
    }
    Ok(())
}
