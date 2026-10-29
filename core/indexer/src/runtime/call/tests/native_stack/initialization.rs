use std::io::Read;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Result, bail, ensure};
use brotli::CompressorReader;
use libsql::Connection;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use wasmtime::Trap;
use wasmtime::component::Component;

use super::sweep::persistent_digest;
use crate::runtime::invocation::{InvocationBudget, ResourceProbePhase, ResourceTeardownRecorder};
use crate::runtime::{
    ContractAddress, ExecutionError, Linkers, Runtime, TransactionContext, component_policy,
    resource_diagnostics,
};
use crate::test_utils::test_runtime_with_engine;

const SAMPLES: [&str; 5] = [
    "active_data_success",
    "active_element_success",
    "active_data_oob",
    "active_element_oob",
    "fuel_failure",
];

fn component_bytes(sample: &str) -> Result<Vec<u8>> {
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
        r#"(component
            (import "kontor:built-in/context" (instance $context
                (export "view-context" (type (sub resource)))))
            (alias export $context "view-context" (type $view-context))
            (import "sentinel" (func $sentinel))
            (core func $drop (canon resource.drop $view-context))
            (core func $sentinel-core (canon lower (func $sentinel)))
            (core module $code
                (import "" "drop" (func $drop (param i32)))
                (import "" "sentinel" (func $sentinel))
                (memory 1)
                (table 1 funcref)
                (func $member)
                {element}
                {data}
                (func (export "run") (param i32)
                    (call $drop (local.get 0))))
            (core instance $code (instantiate $code
                (with "" (instance
                    (export "drop" (func $drop))
                    (export "sentinel" (func $sentinel-core))))))
            (func (export "run") (param "ctx" (borrow $view-context))
                (canon lift (core func $code "run"))))"#
    ))?;
    component_policy::validate_no_starts(&bytes)?;
    Ok(bytes)
}

async fn install_admitted_component(
    runtime: &mut Runtime,
    sample: &str,
    tx_index: u32,
) -> Result<(ContractAddress, String)> {
    let bytes = component_bytes(sample)?;
    let component_sha256 = hex::encode(Sha256::digest(&bytes));
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
    // A plain module cannot encode this component's canonical callbacks. The
    // contract row resolves its address and the admitted cache supplies it.
    let name = format!("generated-{sample}");
    let id = runtime.storage.insert_contract(&name, &compressed).await?;
    runtime
        .component_cache
        .put_admitted(id, component, bytes.len())
        .await;
    runtime.set_context(1, None, None, None).await;
    Ok((
        ContractAddress {
            name,
            height: 1,
            tx_index,
        },
        component_sha256,
    ))
}

async fn receipt_count(conn: &Connection) -> Result<u64> {
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    Ok(rows.next().await?.unwrap().get(0)?)
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
    let (mut runtime, _dir, _name) = test_runtime_with_engine(engine).await?;
    let callback_calls = Arc::new(AtomicUsize::new(0));
    let observed = callback_calls.clone();
    let mut user = runtime.linkers.user.clone();
    user.root().func_wrap("sentinel", move |_, (): ()| {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })?;
    runtime.linkers = Arc::new(Linkers {
        user,
        native: runtime.linkers.native.clone(),
    });
    let conn = runtime.get_storage_conn();
    let default_view_gas_limit = runtime.view_gas_limit;
    let mut outcomes = Vec::with_capacity(SAMPLES.len() * 2);
    for (sample_index, sample) in SAMPLES.into_iter().enumerate() {
        let (address, component_sha256) =
            install_admitted_component(&mut runtime, sample, u32::try_from(sample_index)?).await?;
        let contract_id = runtime.storage.contract_id(&address).await?.unwrap();
        ensure!(
            runtime
                .component_cache
                .get_admitted(&contract_id)
                .await
                .is_some(),
            "generated component was not admitted"
        );
        for repeat_index in 0..2 {
            resource_diagnostics::record("finite_stack_attempt_start");
            let started = Instant::now();
            let recorder = (process_role == "target_observed")
                .then(|| Arc::new(ResourceTeardownRecorder::default()));
            let budget = Arc::new(match recorder.as_ref() {
                Some(recorder) => InvocationBudget::with_teardown_recorder(recorder.clone()),
                None => InvocationBudget::default(),
            });
            runtime.invocation_budget = Some(budget.clone());
            runtime.resource_probe_phase =
                Some(ResourceProbePhase::Target(Arc::new(vec![address.clone()])));
            runtime.view_gas_limit = if sample == "fuel_failure" {
                0
            } else {
                default_view_gas_limit
            };
            let view_fuel_limit = runtime.fuel_limit_for_view()?;
            let state_before_sha256 = persistent_digest(&conn).await?;
            let receipts_before = receipt_count(&conn).await?;
            let resources_before = runtime.table.lock().await.iter_mut().count();
            let previous = runtime.start_usage();
            let result = runtime.execute(None, None, &address, "run()").await;
            let usage = runtime.finish_usage(previous)?;
            let typed_trap = match &result {
                Ok(_) => None,
                Err(ExecutionError::Deterministic(error)) => error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<Trap>())
                    .map(|trap| format!("{trap:?}")),
                Err(error) => {
                    bail!("generated initialization returned a non-deterministic error: {error:?}")
                }
            };
            let outcome = match &result {
                Ok(_) => "ok",
                Err(_) if typed_trap.as_deref() == Some("OutOfFuel") => "out_of_fuel",
                Err(_) => "deterministic_error",
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
                "generated initialization {sample} returned {outcome:?} {typed_trap:?}: {result:?}"
            );
            let state_after_sha256 = persistent_digest(&conn).await?;
            let receipts_after = receipt_count(&conn).await?;
            let resources_after = runtime.table.lock().await.iter_mut().count();
            let stack_empty = runtime.stack.is_empty().await;
            let savepoint_empty = runtime.storage.savepoint_stack.is_empty().await;
            let live_invocations = budget.live();
            let teardown_events = recorder.as_ref().map(|recorder| recorder.events());
            ensure!(
                callback_calls.load(Ordering::SeqCst) == 0
                    && state_after_sha256 == state_before_sha256
                    && receipts_after == receipts_before
                    && resources_after == resources_before
                    && stack_empty
                    && savepoint_empty
                    && live_invocations == 0,
                "generated initialization changed host state or leaked a resource"
            );
            let observation = json!({
                "sample_key": sample,
                "outcome": outcome,
                "typed_trap": typed_trap,
                "result_value": result.ok(),
                "component_sha256": component_sha256,
                "execution_path": "Runtime::execute",
                "admission_path": "admitted_component_cache",
                "published": false,
                "fuel_failure_stage": if sample == "fuel_failure" { Some("input_precharge") } else { None },
                "view_fuel_limit": view_fuel_limit,
                "user_fuel": usage.user_fuel,
                "system_fuel": usage.system_fuel,
                "deposit_fuel": usage.deposit_fuel,
                "host_callback_count": callback_calls.load(Ordering::SeqCst),
                "state_before_sha256": state_before_sha256,
                "state_after_sha256": state_after_sha256,
                "receipts_before": receipts_before,
                "receipts_after": receipts_after,
                "resources_before": resources_before,
                "resources_after": resources_after,
                "stack_empty": stack_empty,
                "savepoint_empty": savepoint_empty,
                "live_invocations": live_invocations,
                "teardown_probe_on": recorder.is_some(),
                "teardown_events": teardown_events,
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": runtime.engine.get_max_wasm_stack(),
                "async_stack_size": runtime.engine.get_async_stack_size(),
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
    runtime.resource_probe_phase = None;
    runtime.view_gas_limit = default_view_gas_limit;
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
