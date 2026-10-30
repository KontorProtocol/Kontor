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

const WIT: &str =
    include_str!("../../../../../../../test-contracts/resource-lifecycle/wit/contract.wit");
const WAT: &str =
    include_str!("../../../../../../../test-contracts/resource-lifecycle/fixture.wat");

fn fixture_bytes(sample: &str) -> Result<(Vec<u8>, String)> {
    let (validation, resolve) = Validator::validate_str(WIT)?;
    ensure!(validation.is_valid(), "{validation}");
    let package = resolve
        .packages
        .iter()
        .find_map(|(id, package)| {
            (package.name.namespace == "root" && package.name.name == "component").then_some(id)
        })
        .context("lifecycle fixture package is missing")?;
    let world = resolve.select_world(&[package], Some("root"))?;
    let data = match sample {
        "valid" => r#"(data (i32.const 0) "x")"#,
        "failed_init" => r#"(data (i32.const 65536) "x")"#,
        _ => bail!("unknown resource lifecycle fixture {sample}"),
    };
    let mut module = wat::parse_str(WAT.replace("@@DATA@@", data))?;
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

fn trap_name(result: &Result<String, ExecutionError>) -> Result<Option<String>> {
    match result {
        Ok(_) => Ok(None),
        Err(ExecutionError::Deterministic(error)) => Ok(error
            .chain()
            .find_map(|cause| cause.downcast_ref::<Trap>())
            .map(|trap| format!("{trap:?}"))),
        Err(error) => bail!("lifecycle fixture returned non-deterministic error: {error:?}"),
    }
}

pub(super) async fn run(
    case_id: &str,
    configuration: &str,
    process_role: &str,
) -> Result<JsonValue> {
    ensure!(
        matches!(
            case_id,
            "explicit_resource_drop" | "failed_instantiation_cleanup"
        ) && matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown lifecycle case, configuration, or role"
    );
    let engine = if configuration == "reduced" {
        Runtime::new_resource_diagnostic_engine()?
    } else {
        Runtime::new_engine()?
    };
    let (mut runtime, _dir, _name) = test_runtime_with_engine(engine).await?;
    let signer = Signer::Core(Box::new(Signer::Nobody));
    let (valid_module, valid_sha256) = fixture_bytes("valid")?;
    let (invalid_module, invalid_sha256) = fixture_bytes("failed_init")?;
    let (valid_address, invalid_address) = if case_id == "explicit_resource_drop" {
        (
            ContractAddress {
                name: "resource-lifecycle-explicit".into(),
                height: 1,
                tx_index: 0,
            },
            None,
        )
    } else {
        (
            ContractAddress {
                name: "resource-lifecycle-control".into(),
                height: 1,
                tx_index: 1,
            },
            Some(ContractAddress {
                name: "resource-lifecycle-failed".into(),
                height: 1,
                tx_index: 0,
            }),
        )
    };
    if case_id == "explicit_resource_drop" {
        ensure!(
            publish_fixture(&mut runtime, &signer, &valid_address, &valid_module)
                .await
                .is_ok(),
            "explicit resource fixture failed publication"
        );
    }
    let attempts: Vec<(&str, usize)> = if case_id == "explicit_resource_drop" {
        vec![
            ("success_before_trap", 0),
            ("trap", 1),
            ("success_after_trap", 2),
        ]
    } else {
        vec![
            ("failed_init", 0),
            ("failed_init", 1),
            ("valid_control", 0),
            ("valid_control", 1),
        ]
    };
    let conn = runtime.get_storage_conn();
    let mut outcomes = Vec::with_capacity(attempts.len());
    for (sample_key, repeat_index) in attempts {
        if sample_key == "valid_control" && repeat_index == 0 {
            runtime.invocation_budget = None;
            runtime.resource_probe_phase = None;
            ensure!(
                publish_fixture(&mut runtime, &signer, &valid_address, &valid_module)
                    .await
                    .is_ok(),
                "valid lifecycle control failed publication"
            );
        }
        let failed_instantiation = sample_key == "failed_init";
        let address = if failed_instantiation {
            invalid_address.as_ref().unwrap()
        } else {
            &valid_address
        };
        let (module, module_sha256) = match sample_key {
            "failed_init" => (&invalid_module, &invalid_sha256),
            _ => (&valid_module, &valid_sha256),
        };
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
        let result = if failed_instantiation {
            publish_fixture(&mut runtime, &signer, address, module).await
        } else {
            runtime
                .execute(
                    None,
                    None,
                    address,
                    if sample_key == "trap" {
                        "trap()"
                    } else {
                        "success()"
                    },
                )
                .await
        };
        let usage = runtime.finish_usage(previous)?;
        let typed_trap = trap_name(&result)?;
        let outcome = if result.is_ok() {
            "ok"
        } else if sample_key == "trap" {
            "trap"
        } else {
            "deterministic_error"
        };
        let expected_trap = match sample_key {
            "trap" => Some("UnreachableCodeReached"),
            "failed_init" => Some("MemoryOutOfBounds"),
            _ => None,
        };
        ensure!(
            outcome
                == if expected_trap.is_some() {
                    if sample_key == "trap" {
                        "trap"
                    } else {
                        "deterministic_error"
                    }
                } else {
                    "ok"
                }
                && typed_trap.as_deref() == expected_trap
                && (expected_trap.is_some() || result.as_ref().is_ok_and(|value| value == "1")),
            "lifecycle {case_id} {sample_key} returned {outcome:?} {typed_trap:?}: {result:?}"
        );
        let published = runtime.storage.contract_id(address).await?.is_some();
        let state_after_sha256 = persistent_digest(&conn).await?;
        let receipts_after = receipt_count(&conn).await?;
        let resources_after = runtime.table.lock().await.iter_mut().count();
        let stack_empty = runtime.stack.is_empty().await;
        let savepoint_empty = runtime.storage.savepoint_stack.is_empty().await;
        let live_invocations = budget.live();
        ensure!(
            published == !failed_instantiation
                && state_after_sha256 == state_before_sha256
                && receipts_after == receipts_before
                && resources_after == resources_before
                && stack_empty
                && savepoint_empty
                && live_invocations == 0,
            "lifecycle {case_id} {sample_key} leaked state or a Store"
        );
        let observation = json!({
            "sample_key": sample_key,
            "outcome": outcome,
            "typed_trap": typed_trap,
            "result_value": result.ok(),
            "module_sha256": module_sha256,
            "component_address": format!("{}:{}:{}", address.name, address.height, address.tx_index),
            "execution_path": if failed_instantiation { "Runtime::publish/init" } else { "Runtime::execute" },
            "published": published,
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
                "case_id": case_id,
                "configuration": configuration,
                "process_role": process_role,
                "sample_key": sample_key,
                "repeat_index": repeat_index,
                "pid": process::id(),
                "observation": observation,
            })
        );
        println!(
            "KONTOR_STACK_TIMING:{}",
            json!({
                "case_id": case_id,
                "sample_key": sample_key,
                "repeat_index": repeat_index,
                "elapsed_ms": started.elapsed().as_millis(),
            })
        );
        resource_diagnostics::record("finite_stack_attempt_end");
        outcomes.push(outcome);
    }
    runtime.invocation_budget = None;
    runtime.resource_probe_phase = None;
    let summary = json!({
        "case_id": case_id,
        "configuration": configuration,
        "process_role": process_role,
        "sample_count": outcomes.len(),
        "outcomes": outcomes,
        "complete": true,
    });
    println!("FINITE_STACK_SUMMARY:{summary}");
    Ok(summary)
}
