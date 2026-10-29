use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Result, bail, ensure};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use wasmtime::{Linker, Module, Store, Trap};

use super::sweep::persistent_digest;
use crate::runtime::{Runtime, component_policy, resource_diagnostics};
use crate::test_utils::test_runtime_with_engine;

const SAMPLES: [&str; 5] = [
    "active_data_success",
    "active_element_success",
    "active_data_oob",
    "active_element_oob",
    "fuel_failure",
];

struct StoreCloseProbe(Option<Arc<AtomicUsize>>);

impl Drop for StoreCloseProbe {
    fn drop(&mut self) {
        if let Some(closed) = &self.0 {
            closed.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn module_bytes(sample: &str) -> Result<Vec<u8>> {
    let (data, element) = match sample {
        "active_data_success" => (r#"(data (i32.const 0) "x")"#, ""),
        "active_element_success" => ("", "(elem (i32.const 0) func $member)"),
        "active_data_oob" => (r#"(data (i32.const 65536) "x")"#, ""),
        "active_element_oob" => ("", "(elem (i32.const 1) func $member)"),
        "fuel_failure" => (
            r#"(data (i32.const 0) "x")"#,
            "(elem (i32.const 0) func $member)",
        ),
        _ => bail!("unknown generated initialization sample {sample}"),
    };
    let bytes = wat::parse_str(format!(
        r#"(module
            (import "env" "sentinel" (func))
            (memory 1)
            (table 1 funcref)
            (func $member)
            {element}
            {data})"#
    ))?;
    component_policy::validate_no_starts(&bytes)?;
    Ok(bytes)
}

pub(super) async fn run(configuration: &str, process_role: &str) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown generated initialization configuration or role"
    );
    let engine = if configuration == "reduced" {
        Runtime::new_resource_diagnostic_engine()?
    } else {
        Runtime::new_engine()?
    };
    let (runtime, _dir, _name) = test_runtime_with_engine(engine).await?;
    let conn = runtime.get_storage_conn();
    let baseline_digest = persistent_digest(&conn).await?;
    let callback_calls = Arc::new(AtomicUsize::new(0));
    let observed = callback_calls.clone();
    let mut linker = Linker::new(&runtime.engine);
    linker.func_wrap("env", "sentinel", move || {
        observed.fetch_add(1, Ordering::SeqCst);
    })?;
    let mut outcomes = Vec::with_capacity(SAMPLES.len() * 2);
    for sample in SAMPLES {
        let bytes = module_bytes(sample)?;
        let module_sha256 = hex::encode(Sha256::digest(&bytes));
        let module = Module::new(&runtime.engine, &bytes)?;
        for repeat_index in 0..2 {
            resource_diagnostics::record("finite_stack_attempt_start");
            let started = Instant::now();
            let fuel_limit = if sample == "fuel_failure" {
                0
            } else {
                1_000_000
            };
            let closed = Arc::new(AtomicUsize::new(0));
            let mut store = Store::new(
                &runtime.engine,
                StoreCloseProbe((process_role == "target_observed").then(|| closed.clone())),
            );
            store.set_fuel(fuel_limit)?;
            let result = linker.instantiate(&mut store, &module);
            let (outcome, typed_trap) = match result {
                Ok(_) => ("ok", None),
                Err(error) => {
                    let trap = error.downcast_ref::<Trap>();
                    let name = trap.map(|trap| format!("{trap:?}"));
                    let outcome = if trap == Some(&Trap::OutOfFuel) {
                        "out_of_fuel"
                    } else {
                        "deterministic_error"
                    };
                    (outcome, name)
                }
            };
            let (expected_outcome, expected_trap) = match sample {
                "active_data_success" | "active_element_success" => ("ok", None),
                "active_data_oob" => ("deterministic_error", Some("MemoryOutOfBounds")),
                "active_element_oob" => ("deterministic_error", Some("TableOutOfBounds")),
                "fuel_failure" => ("out_of_fuel", Some("OutOfFuel")),
                _ => unreachable!(),
            };
            ensure!(
                outcome == expected_outcome && typed_trap.as_deref() == expected_trap,
                "generated initialization {sample} returned {outcome:?} {typed_trap:?}"
            );
            let remaining = store.get_fuel()?;
            ensure!(remaining <= fuel_limit, "initialization fuel increased");
            let fuel_used = fuel_limit - remaining;
            drop(store);
            let store_close_count = closed.load(Ordering::SeqCst);
            ensure!(
                callback_calls.load(Ordering::SeqCst) == 0
                    && persistent_digest(&conn).await? == baseline_digest
                    && store_close_count == usize::from(process_role == "target_observed"),
                "generated initialization changed host state or called an import"
            );
            let observation = json!({
                "sample_key": sample,
                "outcome": outcome,
                "typed_trap": typed_trap,
                "module_sha256": module_sha256,
                "fuel_limit": fuel_limit,
                "fuel_used": fuel_used,
                "host_callback_count": callback_calls.load(Ordering::SeqCst),
                "state_before_sha256": baseline_digest,
                "state_after_sha256": baseline_digest,
                "store_closed": true,
                "teardown_probe_on": process_role == "target_observed",
                "store_close_count": store_close_count,
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": runtime.engine.get_max_wasm_stack(),
                "async_stack_size": if configuration == "reduced" { 1_048_576 } else { 2_097_152 },
            });
            println!(
                "FINITE_STACK_ATTEMPT:{}",
                json!({
                    "case_id": "generated_initialization",
                    "configuration": configuration,
                    "process_role": process_role,
                    "sample_key": sample,
                    "repeat_index": repeat_index,
                    "pid": process::id(),
                    "observation": observation,
                })
            );
            println!(
                "KONTOR_STACK_TIMING:{}",
                json!({
                    "case_id": "generated_initialization",
                    "sample_key": sample,
                    "repeat_index": repeat_index,
                    "elapsed_ms": started.elapsed().as_millis(),
                })
            );
            resource_diagnostics::record("finite_stack_attempt_end");
            outcomes.push(outcome);
        }
    }
    let summary = json!({
        "case_id": "generated_initialization",
        "configuration": configuration,
        "process_role": process_role,
        "sample_count": outcomes.len(),
        "outcomes": outcomes,
        "complete": true,
    });
    println!("FINITE_STACK_SUMMARY:{summary}");
    Ok(summary)
}
