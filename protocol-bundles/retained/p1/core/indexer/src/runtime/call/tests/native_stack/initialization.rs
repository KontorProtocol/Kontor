use std::io::Read;
use std::process;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use brotli::CompressorReader;
use libsql::Connection;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use wasmtime::Trap;
use wit_component::{StringEncoding, embed_component_metadata};
use wit_validator::Validator;

use super::sweep::persistent_digest;
use crate::runtime::fuel::Fuel;
use crate::runtime::invocation::{InvocationBudget, ResourceProbePhase, ResourceTeardownRecorder};
use crate::runtime::wit::Signer;
use crate::runtime::{
    ContractAddress, ExecutionError, Runtime, TransactionContext, native_provenance,
    resource_diagnostics,
};
use crate::test_utils::test_runtime_with_engine;

const WIT: &str =
    include_str!("../../../../../../../test-contracts/canonical-probe/wit/contract.wit");
const WAT: &str = include_str!("../../../../../../../test-contracts/canonical-probe/fixture.wat");
const SAMPLES: [&str; 5] = [
    "active_data_success",
    "active_element_success",
    "active_data_oob",
    "active_element_oob",
    "fuel_failure",
];
const VIEW_EXPRESSION: &str = "view-run(\"\")";

fn fixture_bytes(sample: &str) -> Result<(Vec<u8>, String)> {
    let (data, element) = match sample {
        "active_data_success" => (r#"(data (i32.const 0) "x")"#.to_string(), ""),
        "active_element_success" => (String::new(), "(elem (i32.const 0) func $member)"),
        "active_data_oob" => (r#"(data (i32.const 65536) "x")"#.to_string(), ""),
        "active_element_oob" => (String::new(), "(elem (i32.const 1) func $member)"),
        "fuel_failure" => (
            format!(r#"(data (i32.const 0) "{}")"#, "x".repeat(4096)),
            "",
        ),
        _ => bail!("unknown generated initialization sample {sample}"),
    };
    let (validation, resolve) = Validator::validate_str(WIT)?;
    ensure!(validation.is_valid(), "{validation}");
    let package = resolve
        .packages
        .iter()
        .find_map(|(id, package)| {
            (package.name.namespace == "root" && package.name.name == "component").then_some(id)
        })
        .context("initialization fixture package is missing")?;
    let world = resolve.select_world(&[package], Some("root"))?;
    let wat = WAT
        .replace("@@REALLOC_BODY@@", "i32.const 64")
        .replace("@@POST_LIGHT_BODY@@", "")
        .replace("@@POST_HEAVY_BODY@@", "");
    let marker = "(memory (export \"memory\") 1)";
    ensure!(
        wat.matches(marker).count() == 1,
        "fixture memory layout changed"
    );
    let wat = wat.replacen(
        marker,
        &format!("{marker}\n  (table 1 funcref)\n  (func $member)\n  {element}\n  {data}"),
        1,
    );
    let mut module = wat::parse_str(&wat)?;
    embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8, false)?;
    let module_sha256 = hex::encode(Sha256::digest(&module));
    let mut compressed = Vec::new();
    CompressorReader::new(module.as_slice(), 4096, 5, 22).read_to_end(&mut compressed)?;
    Ok((compressed, module_sha256))
}

async fn receipt_count(conn: &Connection) -> Result<u64> {
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    Ok(rows.next().await?.unwrap().get(0)?)
}

fn trap_name(result: &Result<String, ExecutionError>) -> Result<Option<String>> {
    match result {
        Ok(_) => Ok(None),
        Err(ExecutionError::Deterministic(error)) => Ok(error
            .chain()
            .find_map(|cause| cause.downcast_ref::<Trap>())
            .map(|trap| format!("{trap:?}"))),
        Err(error) => {
            bail!("generated initialization returned a non-deterministic error: {error:?}")
        }
    }
}

async fn sufficient_fuel_control(
    runtime: &mut Runtime,
    address: &ContractAddress,
    module_sha256: &str,
    process_role: &str,
) -> Result<JsonValue> {
    let recorder =
        (process_role == "target_observed").then(|| Arc::new(ResourceTeardownRecorder::default()));
    let budget = Arc::new(match recorder.as_ref() {
        Some(recorder) => InvocationBudget::with_teardown_recorder(recorder.clone()),
        None => InvocationBudget::default(),
    });
    runtime.invocation_budget = Some(budget.clone());
    runtime.resource_probe_phase =
        Some(ResourceProbePhase::Target(Arc::new(vec![address.clone()])));
    let conn = runtime.get_storage_conn();
    let state_before_sha256 = persistent_digest(&conn).await?;
    let receipts_before = receipt_count(&conn).await?;
    let resources_before = runtime.table.lock().await.iter_mut().count();
    let view_fuel_limit = runtime.fuel_limit_for_view()?;
    let previous = runtime.start_usage();
    resource_diagnostics::record("fuel_control_entry");
    let result = runtime.execute(None, None, address, VIEW_EXPRESSION).await;
    resource_diagnostics::record("fuel_control_exit");
    let usage = runtime.finish_usage(previous)?;
    let state_after_sha256 = persistent_digest(&conn).await?;
    let receipts_after = receipt_count(&conn).await?;
    let resources_after = runtime.table.lock().await.iter_mut().count();
    ensure!(
        result.as_ref().is_ok_and(|value| value.is_empty())
            && usage.system_fuel > 1_000
            && usage.user_fuel == 0
            && usage.deposit_fuel == 0
            && state_after_sha256 == state_before_sha256
            && receipts_after == receipts_before
            && resources_after == resources_before
            && budget.live() == 0
            && runtime.stack.is_empty().await
            && runtime.storage.savepoint_stack.is_empty().await,
        "sufficient-fuel initialization control failed: {result:?}"
    );
    Ok(json!({
        "component_address": format!("{}:{}:{}", address.name, address.height, address.tx_index),
        "module_sha256": module_sha256,
        "result_value": result.ok(),
        "view_fuel_limit": view_fuel_limit,
        "system_fuel": usage.system_fuel,
        "state_before_sha256": state_before_sha256,
        "state_after_sha256": state_after_sha256,
        "receipts_before": receipts_before,
        "receipts_after": receipts_after,
        "resources_before": resources_before,
        "resources_after": resources_after,
        "live_invocations": budget.live(),
        "teardown_probe_on": recorder.is_some(),
        "teardown_events": recorder.as_ref().map(|recorder| recorder.events()),
    }))
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
    let signer = Signer::Core(Box::new(Signer::Nobody));
    let payment = runtime.core_payment();
    let conn = runtime.get_storage_conn();
    let default_view_gas_limit = runtime.view_gas_limit;
    let mut outcomes = Vec::with_capacity(SAMPLES.len() * 2);
    for (sample_index, sample) in SAMPLES.into_iter().enumerate() {
        let (module, module_sha256) = fixture_bytes(sample)?;
        let address = ContractAddress {
            name: format!("generated-{}", sample.replace('_', "-")),
            height: 1,
            tx_index: u32::try_from(sample_index)?,
        };
        let expect_publish_failure = matches!(sample, "active_data_oob" | "active_element_oob");
        if !expect_publish_failure {
            runtime.invocation_budget = None;
            runtime.resource_probe_phase = None;
            runtime
                .set_context(
                    1,
                    Some(
                        TransactionContext::builder()
                            .tx_index(address.tx_index)
                            .build(),
                    ),
                    None,
                    None,
                )
                .await;
            resource_diagnostics::record("publication_entry");
            let published = runtime
                .publish(
                    &signer,
                    payment.clone(),
                    &address.name,
                    &module,
                    &native_provenance()?,
                )
                .await;
            resource_diagnostics::record("publication_exit");
            runtime.set_context(1, None, None, None).await;
            ensure!(
                published.is_ok(),
                "generated initialization publication failed: {published:?}"
            );
            ensure!(
                runtime.storage.contract_id(&address).await?.is_some(),
                "published generated component has no contract row"
            );
        }
        let fuel_control = if sample == "fuel_failure" {
            runtime.view_gas_limit = default_view_gas_limit;
            Some(
                sufficient_fuel_control(&mut runtime, &address, &module_sha256, process_role)
                    .await?,
            )
        } else {
            None
        };
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
                1
            } else {
                default_view_gas_limit
            };
            let expression = if expect_publish_failure {
                "init()"
            } else {
                VIEW_EXPRESSION
            };
            let input_precharge_fuel = Fuel::WaveInputBytes(u64::try_from(expression.len())?)
                .cost()
                + Fuel::ContractNameBytes(u64::try_from(address.name.len())?).cost();
            let view_fuel_limit = (!expect_publish_failure)
                .then(|| runtime.fuel_limit_for_view())
                .transpose()?;
            if sample == "fuel_failure" {
                ensure!(
                    view_fuel_limit.unwrap() > input_precharge_fuel
                        && view_fuel_limit.unwrap() < 4096,
                    "fuel failure must pass input precharge and exhaust active data startup"
                );
            }
            let state_before_sha256 = persistent_digest(&conn).await?;
            let receipts_before = receipt_count(&conn).await?;
            let resources_before = runtime.table.lock().await.iter_mut().count();
            if expect_publish_failure {
                runtime
                    .set_context(
                        1,
                        Some(
                            TransactionContext::builder()
                                .tx_index(address.tx_index)
                                .build(),
                        ),
                        None,
                        None,
                    )
                    .await;
            }
            let previous = runtime.start_usage();
            let result = if expect_publish_failure {
                runtime
                    .publish(
                        &signer,
                        payment.clone(),
                        &address.name,
                        &module,
                        &native_provenance()?,
                    )
                    .await
            } else {
                runtime.execute(None, None, &address, expression).await
            };
            let usage = runtime.finish_usage(previous)?;
            if expect_publish_failure {
                runtime.set_context(1, None, None, None).await;
            }
            let typed_trap = trap_name(&result)?;
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
            let published = runtime.storage.contract_id(&address).await?.is_some();
            let state_after_sha256 = persistent_digest(&conn).await?;
            let receipts_after = receipt_count(&conn).await?;
            let resources_after = runtime.table.lock().await.iter_mut().count();
            let stack_empty = runtime.stack.is_empty().await;
            let savepoint_empty = runtime.storage.savepoint_stack.is_empty().await;
            let live_invocations = budget.live();
            let teardown_events = recorder.as_ref().map(|recorder| recorder.events());
            ensure!(
                published == !expect_publish_failure
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
                "module_sha256": module_sha256,
                "component_address": format!("{}:{}:{}", address.name, address.height, address.tx_index),
                "execution_path": if expect_publish_failure { "Runtime::publish/init" } else { "Runtime::execute" },
                "published": published,
                "input_precharge_fuel": input_precharge_fuel,
                "view_fuel_limit": view_fuel_limit,
                "fuel_control": fuel_control.clone(),
                "user_fuel": usage.user_fuel,
                "system_fuel": usage.system_fuel,
                "deposit_fuel": usage.deposit_fuel,
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
    runtime.invocation_budget = None;
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
