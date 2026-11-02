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
use crate::runtime::invocation::{InvocationBudget, ResourceProbePhase, ResourceTeardownRecorder};
use crate::runtime::wit::Signer;
use crate::runtime::{
    ContractAddress, ExecutionError, Runtime, TransactionContext, native_provenance,
    resource_diagnostics,
};
use crate::test_utils::test_runtime_with_engine;

const WIT: &str = include_str!("../../../../../../../test-contracts/type-value/fixture.wit");
const WAT: &str = include_str!("../../../../../../../test-contracts/type-value/fixture.wat");
const SAMPLES: [&str; 6] = [
    "nested_record",
    "nested_variant",
    "list_of_records",
    "large_result",
    "result_depth_64",
    "result_depth_65_rejected",
];

fn expression(sample: &str) -> Result<String> {
    match sample {
        "nested_record" => Ok("view-nested-record({child:{child:17}})".into()),
        "nested_variant" => Ok("view-nested-variant(branch({child:{child:19}}))".into()),
        "list_of_records" => Ok(format!(
            "view-list-of-records([{}])",
            (0..64)
                .map(|value| format!("{{child:{{child:{value}}}}}"))
                .collect::<Vec<_>>()
                .join(",")
        )),
        "large_result" => Ok("view-large-result()".into()),
        "result_depth_64" => Ok("view-result-depth64()".into()),
        "result_depth_65_rejected" => Ok("view-result-depth65()".into()),
        _ => bail!("unknown type/value sample {sample}"),
    }
}

fn expected_result(sample: &str) -> Option<String> {
    match sample {
        "nested_record" => Some("{child: {child: 17}}".into()),
        "nested_variant" => Some("branch({child: {child: 19}})".into()),
        "list_of_records" => Some(format!(
            "[{}]",
            (0..64)
                .map(|value| format!("{{child: {{child: {value}}}}}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        "large_result" => Some(format!("\"{}\"", "x".repeat(16_384))),
        "result_depth_64" => Some(format!("{}7{}", "{child: ".repeat(64), "}".repeat(64))),
        _ => None,
    }
}

fn fixture_bytes() -> Result<(Vec<u8>, String)> {
    let (validation, resolve) = Validator::validate_str(WIT)?;
    ensure!(validation.is_valid(), "{validation}");
    let package = resolve
        .packages
        .iter()
        .find_map(|(id, package)| {
            (package.name.namespace == "root" && package.name.name == "component").then_some(id)
        })
        .context("type/value fixture package is missing")?;
    let world = resolve.select_world(&[package], Some("root"))?;
    let mut module = wat::parse_str(WAT)?;
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

async fn publish_fixture(
    runtime: &mut Runtime,
    signer: &Signer,
    address: &ContractAddress,
    module: &[u8],
) -> Result<String, ExecutionError> {
    let payment = runtime.core_payment();
    let provenance = native_provenance().map_err(ExecutionError::NonDeterministic)?;
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
    let result = runtime
        .publish(signer, payment, &address.name, module, &provenance)
        .await;
    resource_diagnostics::record("publication_exit");
    runtime.set_context(1, None, None, None).await;
    result
}

fn error_kind(
    result: &Result<String, ExecutionError>,
) -> Result<(Option<&'static str>, Option<String>)> {
    match result {
        Ok(_) => Ok((None, None)),
        Err(ExecutionError::Deterministic(error)) => {
            let message = format!("{error:#}");
            let kind = if message.contains("WAVE value nesting is too deep") {
                "result_value_depth"
            } else {
                bail!("type/value call returned an unexpected deterministic error: {error:#}")
            };
            let trap = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<Trap>())
                .map(|trap| format!("{trap:?}"));
            Ok((Some(kind), trap))
        }
        Err(error) => bail!("type/value call returned a non-deterministic error: {error:?}"),
    }
}

pub(super) async fn run(configuration: &str, process_role: &str) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown type/value configuration or role"
    );
    let engine = if configuration == "reduced" {
        Runtime::new_resource_diagnostic_engine()?
    } else {
        Runtime::new_engine()?
    };
    let (mut runtime, _dir, _name) = test_runtime_with_engine(engine).await?;
    let signer = Signer::Core(Box::new(Signer::Nobody));
    let (module, module_sha256) = fixture_bytes()?;
    let address = ContractAddress {
        name: "type-value".into(),
        height: 1,
        tx_index: 0,
    };
    let publication = publish_fixture(&mut runtime, &signer, &address, &module).await;
    ensure!(
        publication.is_ok(),
        "type/value fixture failed publication: {publication:?}"
    );
    let conn = runtime.get_storage_conn();
    let mut outcomes = Vec::with_capacity(SAMPLES.len() * 2);
    for sample in SAMPLES {
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
            let state_before_sha256 = persistent_digest(&conn).await?;
            let receipts_before = receipt_count(&conn).await?;
            let resources_before = runtime.table.lock().await.iter_mut().count();
            let previous = runtime.start_usage();
            let expr = expression(sample)?;
            let result = runtime.execute(None, None, &address, &expr).await;
            let usage = runtime.finish_usage(previous)?;
            let (actual_error_kind, typed_trap) = error_kind(&result)?;
            let expected_error_kind =
                (sample == "result_depth_65_rejected").then_some("result_value_depth");
            let result_value = result.ok();
            ensure!(
                actual_error_kind == expected_error_kind && result_value == expected_result(sample),
                "type/value {sample} returned wrong result or error: \
                 {actual_error_kind:?} {typed_trap:?} {result_value:?}"
            );
            let state_after_sha256 = persistent_digest(&conn).await?;
            let receipts_after = receipt_count(&conn).await?;
            let resources_after = runtime.table.lock().await.iter_mut().count();
            let stack_empty = runtime.stack.is_empty().await;
            let savepoint_empty = runtime.storage.savepoint_stack.is_empty().await;
            let live_invocations = budget.live();
            ensure!(
                state_after_sha256 == state_before_sha256
                    && receipts_after == receipts_before
                    && resources_after == resources_before
                    && stack_empty
                    && savepoint_empty
                    && live_invocations == 0,
                "type/value {sample} leaked state or a Store"
            );
            let observation = json!({
                "sample_key": sample,
                "outcome": if expected_error_kind.is_none() { "ok" } else { "deterministic_error" },
                "error_kind": actual_error_kind,
                "typed_trap": typed_trap,
                "result_value": result_value,
                "expression_sha256": hex::encode(Sha256::digest(expr.as_bytes())),
                "expression_bytes": expr.len(),
                "module_sha256": &module_sha256,
                "address": format!("{}:{}:{}", address.name, address.height, address.tx_index),
                "execution_path": "Runtime::execute/Runtime::invoke",
                "system_fuel": usage.system_fuel,
                "user_fuel": usage.user_fuel,
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
                "teardown_events": recorder.as_ref().map(|recorder| recorder.events()),
                "engine_target": "pulley64-unknown-unknown-elf",
                "max_wasm_stack": runtime.engine.get_max_wasm_stack(),
                "async_stack_size": runtime.engine.get_async_stack_size(),
            });
            println!(
                "FINITE_STACK_ATTEMPT:{}",
                json!({
                    "case_id": "canonical_type_value_recursion",
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
                    "case_id": "canonical_type_value_recursion",
                    "sample_key": sample,
                    "repeat_index": repeat_index,
                    "elapsed_ms": started.elapsed().as_millis(),
                })
            );
            resource_diagnostics::record("finite_stack_attempt_end");
            outcomes.push(if expected_error_kind.is_none() {
                "ok"
            } else {
                "deterministic_error"
            });
        }
    }
    runtime.invocation_budget = None;
    runtime.resource_probe_phase = None;
    let summary = json!({
        "case_id": "canonical_type_value_recursion",
        "configuration": configuration,
        "process_role": process_role,
        "sample_count": outcomes.len(),
        "outcomes": outcomes,
        "complete": true,
    });
    println!("FINITE_STACK_SUMMARY:{summary}");
    Ok(summary)
}
