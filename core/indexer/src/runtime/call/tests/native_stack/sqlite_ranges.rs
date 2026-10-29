use std::process;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, ensure};
use libsql::Connection;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use stdlib::to_wave_expr;

use super::sweep::persistent_digest;
use crate::runtime::invocation::{InvocationBudget, ResourceProbePhase, ResourceTeardownRecorder};
use crate::runtime::resource_diagnostics;
use crate::runtime::token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, Runtime, TransactionContext, from_wave_expr, native_provenance,
};
use crate::test_utils::test_runtime_with_engine;

const CASE_ID: &str = "sqlite_ranges";
const ROWS: usize = 1_024;
const PAGE_SIZES: [usize; 3] = [1, 7, 100];
const RANGE_LENGTHS: [usize; 4] = [0, 1, 256, 1_024];
const ACTOR_PUBKEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ACTOR_SIGNER_ID: u64 = 7;
const COMPONENT: &[u8] = include_bytes!("../../../../../../test-contracts/binaries/arith.wasm.br");

async fn receipt_count(conn: &Connection) -> Result<u64> {
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    Ok(rows.next().await?.unwrap().get(0)?)
}

async fn prepare_fixture(runtime: &mut Runtime) -> Result<ContractAddress> {
    let actor = Signer::Id(runtime.get_or_create_identity(ACTOR_PUBKEY).await?);
    ensure!(
        actor.signer_id() == Some(ACTOR_SIGNER_ID),
        "range actor identity changed"
    );
    let core = Signer::Core(Box::new(Signer::Nobody));
    token::api::issue_to(
        runtime,
        &core,
        HolderRef::from(&actor),
        Decimal::from("1000000000"),
    )
    .await??;
    let address = ContractAddress {
        name: "arith".into(),
        height: 1,
        tx_index: 0,
    };
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(0).build()),
            None,
            None,
        )
        .await;
    let provenance = native_provenance()?;
    let payment = runtime.core_payment();
    resource_diagnostics::record("publication_entry");
    let published = runtime
        .publish(&core, payment, &address.name, COMPONENT, &provenance)
        .await;
    resource_diagnostics::record("publication_exit");
    ensure!(
        published? == to_wave_expr(address.clone()),
        "range guest publication returned the wrong address"
    );
    for key in 0..ROWS {
        let expression = format!("put-numbers({key}, \"{}\", \"{key}.5\")", key + 1_000);
        runtime
            .execute_api(Some(&actor), &address, &expression)
            .await?;
    }
    runtime.set_context(1, None, None, None).await;
    Ok(address)
}

fn expected_rows(lower: usize, upper: usize, limit: usize, descending: bool) -> Vec<String> {
    let keys = lower..upper;
    if descending {
        keys.rev()
            .take(limit)
            .map(|key| format!("{key}:{key}.5"))
            .collect()
    } else {
        keys.take(limit)
            .map(|key| format!("{key}:{}", key + 1_000))
            .collect()
    }
}

async fn query_range(
    runtime: &mut Runtime,
    address: &ContractAddress,
    lower: usize,
    upper: usize,
    page_size: usize,
    descending: bool,
) -> Result<Vec<String>> {
    let expression = format!(
        "number-entries(some({lower}), some({upper}), {descending}, {page_size}, {})",
        !descending
    );
    let raw = runtime.execute(None, None, address, &expression).await?;
    let actual: Vec<String> = from_wave_expr(&raw);
    ensure!(
        actual == expected_rows(lower, upper, page_size, descending),
        "range query returned missing, duplicate, out-of-bound, or changed rows"
    );
    Ok(actual)
}

pub(super) async fn run(configuration: &str, process_role: &str) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown range configuration or role"
    );
    let engine = if configuration == "reduced" {
        Runtime::new_resource_diagnostic_engine()?
    } else {
        Runtime::new_engine()?
    };
    resource_diagnostics::record("fixture_preparation_entry");
    let (mut runtime, _dir, _name) = test_runtime_with_engine(engine).await?;
    let address = prepare_fixture(&mut runtime).await?;
    resource_diagnostics::record("fixture_preparation_exit");
    let conn = runtime.get_storage_conn();
    let baseline_digest = persistent_digest(&conn).await?;
    let baseline_receipts = receipt_count(&conn).await?;
    let component_sha256 = hex::encode(Sha256::digest(COMPONENT));
    let mut outcomes = Vec::with_capacity(PAGE_SIZES.len() * RANGE_LENGTHS.len() * 2);
    for page_size in PAGE_SIZES {
        for range_length in RANGE_LENGTHS {
            let lower = (ROWS - range_length) / 2;
            let upper = lower + range_length;
            let sample = format!("page_{page_size}_range_{range_length}");
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
                let ascending =
                    query_range(&mut runtime, &address, lower, upper, page_size, false).await?;
                let descending =
                    query_range(&mut runtime, &address, lower, upper, page_size, true).await?;
                let usage = runtime.finish_usage(previous)?;
                let state_after_sha256 = persistent_digest(&conn).await?;
                let receipts_after = receipt_count(&conn).await?;
                let resources_after = runtime.table.lock().await.iter_mut().count();
                let stack_empty = runtime.stack.is_empty().await;
                let savepoint_empty = runtime.storage.savepoint_stack.is_empty().await;
                let live_invocations = budget.live();
                ensure!(
                    state_before_sha256 == baseline_digest
                        && state_after_sha256 == baseline_digest
                        && receipts_before == baseline_receipts
                        && receipts_after == baseline_receipts
                        && resources_after == resources_before
                        && stack_empty
                        && savepoint_empty
                        && live_invocations == 0,
                    "range {sample} leaked state or a Store"
                );
                let observation = json!({
                    "sample_key": sample,
                    "outcome": "ok",
                    "lower": lower,
                    "upper": upper,
                    "page_size": page_size,
                    "row_count": ROWS,
                    "ascending": ascending,
                    "descending": descending,
                    "ascending_value_type": "integer",
                    "descending_value_type": "decimal",
                    "bound_semantics": "included_lower_excluded_upper",
                    "component_sha256": &component_sha256,
                    "publication_path": "Runtime::publish/native_provenance",
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
                        "case_id": CASE_ID,
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
                        "case_id": CASE_ID,
                        "sample_key": sample,
                        "repeat_index": repeat_index,
                        "elapsed_ms": started.elapsed().as_millis(),
                    })
                );
                resource_diagnostics::record("finite_stack_attempt_end");
                runtime.invocation_budget = None;
                runtime.resource_probe_phase = None;
                outcomes.push("ok");
            }
        }
    }
    let summary = json!({
        "case_id": CASE_ID,
        "configuration": configuration,
        "process_role": process_role,
        "sample_count": outcomes.len(),
        "outcomes": outcomes,
        "complete": true,
    });
    println!("FINITE_STACK_SUMMARY:{summary}");
    Ok(summary)
}
