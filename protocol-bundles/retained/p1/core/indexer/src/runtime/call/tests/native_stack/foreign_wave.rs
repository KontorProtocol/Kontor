use std::io::Read;
use std::process;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use brotli::CompressorReader;
use libsql::Connection;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use stdlib::to_wave_expr;
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

const TARGET_WIT: &str =
    include_str!("../../../../../../../test-contracts/foreign-wave/target.wit");
const TARGET_WAT: &str =
    include_str!("../../../../../../../test-contracts/foreign-wave/target.wat");
const CALLER_WIT: &str =
    include_str!("../../../../../../../test-contracts/foreign-wave/caller.wit");
const CALLER_WAT: &str =
    include_str!("../../../../../../../test-contracts/foreign-wave/caller.wat");
const SAMPLES: [&str; 6] = [
    "depth_64",
    "depth_65_rejected",
    "literal_16384",
    "literal_16385_rejected",
    "print_depth_64",
    "print_depth_65_rejected",
];

fn expression(sample: &str) -> Result<String> {
    match sample {
        "depth_64" => Ok(format!(
            "view-depth({}1{})",
            "{child:".repeat(63),
            "}".repeat(63)
        )),
        "depth_65_rejected" => Ok(format!(
            "view-depth({}1{})",
            "{child:".repeat(64),
            "}".repeat(64)
        )),
        "literal_16384" => Ok(format!("view-literal(\"{}\")", "x".repeat(16_384))),
        "literal_16385_rejected" => Ok(format!("view-literal(\"{}\")", "x".repeat(16_385))),
        "print_depth_64" => Ok("print-depth64()".into()),
        "print_depth_65_rejected" => Ok("print-depth65()".into()),
        _ => bail!("unknown foreign WAVE sample {sample}"),
    }
}

fn expected_result(sample: &str) -> Option<String> {
    let inner = match sample {
        "depth_64" => "1".to_string(),
        "literal_16384" => "16384".to_string(),
        "print_depth_64" => format!("{}7{}", "{child: ".repeat(64), "}".repeat(64)),
        _ => return None,
    };
    Some(to_wave_expr(inner.as_str()))
}

fn caller_wat() -> Result<String> {
    let mut data = String::new();
    let mut branches = String::new();
    let mut offset = 128usize;
    for (index, sample) in SAMPLES.into_iter().enumerate() {
        let expr = expression(sample)?;
        let encoded = expr
            .as_bytes()
            .iter()
            .map(|byte| format!("\\{byte:02x}"))
            .collect::<String>();
        data.push_str(&format!("(data (i32.const {offset}) \"{encoded}\")\n"));
        branches.push_str(&format!(
            "local.get $sample i32.const {index} i32.eq if \
             i32.const {offset} local.set $expr-ptr \
             i32.const {} local.set $expr-len end\n",
            expr.len()
        ));
        offset += expr.len() + 16;
    }
    ensure!(
        offset < 40_000,
        "foreign WAVE expression data overlaps result pointer"
    );
    Ok(CALLER_WAT
        .replace("@@DATA@@", &data)
        .replace("@@BRANCHES@@", &branches))
}

fn fixture_bytes(wit: &str, wat: &str) -> Result<(Vec<u8>, String)> {
    let (validation, resolve) = Validator::validate_str(wit)?;
    ensure!(validation.is_valid(), "{validation}");
    let package = resolve
        .packages
        .iter()
        .find_map(|(id, package)| {
            (package.name.namespace == "root" && package.name.name == "component").then_some(id)
        })
        .context("foreign WAVE fixture package is missing")?;
    let world = resolve.select_world(&[package], Some("root"))?;
    let mut module = wat::parse_str(wat)?;
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
            let kind = if message.contains("call expression nested too deeply") {
                "expression_depth"
            } else if message.contains("call expression string literal too large") {
                "string_literal_bytes"
            } else if message.contains("WAVE value nesting is too deep") {
                "result_value_depth"
            } else {
                bail!("foreign WAVE returned an unexpected deterministic error: {error:#}")
            };
            let trap = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<Trap>())
                .map(|trap| format!("{trap:?}"));
            Ok((Some(kind), trap))
        }
        Err(error) => bail!("foreign WAVE returned a non-deterministic error: {error:?}"),
    }
}

pub(super) async fn run(configuration: &str, process_role: &str) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown foreign WAVE configuration or role"
    );
    let engine = if configuration == "reduced" {
        Runtime::new_resource_diagnostic_engine()?
    } else {
        Runtime::new_engine()?
    };
    let (mut runtime, _dir, _name) = test_runtime_with_engine(engine).await?;
    let signer = Signer::Core(Box::new(Signer::Nobody));
    let (target_module, target_sha256) = fixture_bytes(TARGET_WIT, TARGET_WAT)?;
    let (caller_module, caller_sha256) = fixture_bytes(CALLER_WIT, &caller_wat()?)?;
    let target = ContractAddress {
        name: "wave-target".into(),
        height: 1,
        tx_index: 0,
    };
    let caller = ContractAddress {
        name: "wave-caller".into(),
        height: 1,
        tx_index: 1,
    };
    for (address, module) in [(&target, &target_module), (&caller, &caller_module)] {
        let publication = publish_fixture(&mut runtime, &signer, address, module).await;
        ensure!(
            publication.is_ok(),
            "foreign WAVE fixture failed publication {}: {publication:?}",
            address.name,
        );
    }
    let conn = runtime.get_storage_conn();
    let mut outcomes = Vec::with_capacity(SAMPLES.len() * 2);
    for (sample_index, sample) in SAMPLES.into_iter().enumerate() {
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
            runtime.resource_probe_phase = Some(ResourceProbePhase::Target(Arc::new(vec![
                caller.clone(),
                target.clone(),
            ])));
            let state_before_sha256 = persistent_digest(&conn).await?;
            let receipts_before = receipt_count(&conn).await?;
            let resources_before = runtime.table.lock().await.iter_mut().count();
            let previous = runtime.start_usage();
            let result = runtime
                .execute(None, None, &caller, &format!("run({sample_index})"))
                .await;
            let usage = runtime.finish_usage(previous)?;
            let (actual_error_kind, typed_trap) = error_kind(&result)?;
            let expected_error_kind = match sample {
                "depth_65_rejected" => Some("expression_depth"),
                "literal_16385_rejected" => Some("string_literal_bytes"),
                "print_depth_65_rejected" => Some("result_value_depth"),
                _ => None,
            };
            let result_value = result.ok();
            ensure!(
                actual_error_kind == expected_error_kind && result_value == expected_result(sample),
                "foreign WAVE {sample} returned wrong result or error: \
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
                "foreign WAVE {sample} leaked state or a Store"
            );
            let expr = expression(sample)?;
            let observation = json!({
                "sample_key": sample,
                "outcome": if expected_error_kind.is_none() { "ok" } else { "deterministic_error" },
                "error_kind": actual_error_kind,
                "typed_trap": typed_trap,
                "result_value": result_value,
                "inner_expression_sha256": hex::encode(Sha256::digest(expr.as_bytes())),
                "inner_expression_bytes": expr.len(),
                "caller_module_sha256": &caller_sha256,
                "target_module_sha256": &target_sha256,
                "caller_address": format!("{}:{}:{}", caller.name, caller.height, caller.tx_index),
                "target_address": format!("{}:{}:{}", target.name, target.height, target.tx_index),
                "execution_path": "Runtime::execute/foreign.call/Runtime::invoke",
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
                    "case_id": "foreign_wave_parse_print",
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
                    "case_id": "foreign_wave_parse_print",
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
        "case_id": "foreign_wave_parse_print",
        "configuration": configuration,
        "process_role": process_role,
        "sample_count": outcomes.len(),
        "outcomes": outcomes,
        "complete": true,
    });
    println!("FINITE_STACK_SUMMARY:{summary}");
    Ok(summary)
}
