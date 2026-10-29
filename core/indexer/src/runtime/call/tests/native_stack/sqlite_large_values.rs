use std::process;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, ensure};
use libsql::Connection;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use stdlib::{Wavey, to_wave_expr};

use super::sweep::persistent_digest;
use crate::runtime::invocation::{InvocationBudget, ResourceProbePhase, ResourceTeardownRecorder};
use crate::runtime::resource_diagnostics;
use crate::runtime::token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, Runtime, TransactionContext, from_wave_expr,
    native_provenance,
};
use crate::test_utils::test_runtime_with_engine;

const CASE_ID: &str = "sqlite_large_values";
const ROWS: usize = 101;
const LARGE_INDEX: usize = 50;
const SMALL_VALUE_BYTES: usize = 16;
const VALUE_BYTES: [usize; 2] = [16_384, 1_048_576];
const PAGE_SIZES: [usize; 3] = [1, 7, 100];
const ACTOR_PUBKEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ACTOR_SIGNER_ID: u64 = 7;
const COMPONENT: &[u8] =
    include_bytes!("../../../../../../../test-contracts/binaries/counter.wasm.br");

#[derive(Wavey)]
struct MapEntry {
    key: String,
    value: String,
}

#[derive(Wavey)]
struct MapPage {
    items: Vec<MapEntry>,
    next: Option<String>,
}

async fn receipt_count(conn: &Connection) -> Result<u64> {
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    Ok(rows.next().await?.unwrap().get(0)?)
}

fn row_key(index: usize) -> String {
    format!("k{index:03}")
}

async fn write_entry(
    runtime: &mut Runtime,
    signer: &Signer,
    address: &ContractAddress,
    key: &str,
    value_bytes: usize,
) -> Result<()> {
    runtime
        .execute_api(
            Some(signer),
            address,
            &format!("fill-entry(\"{key}\", {value_bytes})"),
        )
        .await?;
    Ok(())
}

async fn prepare_fixture(runtime: &mut Runtime) -> Result<(ContractAddress, Signer)> {
    let actor = Signer::Id(runtime.get_or_create_identity(ACTOR_PUBKEY).await?);
    ensure!(
        actor.signer_id() == Some(ACTOR_SIGNER_ID),
        "large-value actor identity changed"
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
        name: "counter".into(),
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
    let payment = runtime.core_payment();
    let provenance = native_provenance()?;
    resource_diagnostics::record("publication_entry");
    let published = runtime
        .publish(&core, payment, &address.name, COMPONENT, &provenance)
        .await;
    resource_diagnostics::record("publication_exit");
    ensure!(
        published? == to_wave_expr(address.clone()),
        "large-value guest publication returned the wrong address"
    );
    for index in 0..ROWS {
        write_entry(
            runtime,
            &actor,
            &address,
            &row_key(index),
            SMALL_VALUE_BYTES,
        )
        .await?;
    }
    Ok((address, actor))
}

async fn paid_size_cap_control(
    runtime: &mut Runtime,
    actor: &Signer,
    address: &ContractAddress,
    conn: &Connection,
) -> Result<JsonValue> {
    let before_sha256 = persistent_digest(conn).await?;
    let receipts_before = receipt_count(conn).await?;
    let result = write_entry(runtime, actor, address, "k999", VALUE_BYTES[1]).await;
    let error = match result {
        Err(error) => error,
        Ok(()) => anyhow::bail!("paid 1 MiB storage write unexpectedly succeeded"),
    };
    let execution_error = error.downcast_ref::<ExecutionError>();
    ensure!(
        matches!(execution_error, Some(ExecutionError::Deterministic(_)))
            && format!("{error:#}").contains("storage deposit exceeds the op's gas budget"),
        "paid 1 MiB write failed for an unexpected reason: {error:#}"
    );
    let raw = runtime
        .execute(None, None, address, "entry-page(some(\"k998\"), 1)")
        .await?;
    let page: MapPage = from_wave_expr(&raw);
    let absent = page.items.is_empty() && page.next.is_none();
    ensure!(
        absent
            && runtime.stack.is_empty().await
            && runtime.storage.savepoint_stack.is_empty().await,
        "failed paid write retained a row or live invocation state"
    );
    let after_sha256 = persistent_digest(conn).await?;
    let receipts_after = receipt_count(conn).await?;
    Ok(json!({
        "outcome": "deterministic_error",
        "error": "storage deposit exceeds the op's gas budget",
        "key": "k999",
        "row_absent": absent,
        "state_before_sha256": before_sha256,
        "state_after_sha256": after_sha256,
        "receipts_before": receipts_before,
        "receipts_after": receipts_after,
    }))
}

async fn query_page(
    runtime: &mut Runtime,
    address: &ContractAddress,
    value_bytes: usize,
    page_size: usize,
) -> Result<(Vec<JsonValue>, Option<String>, Option<String>)> {
    let start = match page_size {
        1 => 50,
        7 => 47,
        100 => 0,
        _ => unreachable!("page sizes are frozen"),
    };
    let end = (start + page_size).min(ROWS);
    let after = (start > 0).then(|| row_key(start - 1));
    let cursor = after
        .as_ref()
        .map_or_else(|| "none".to_string(), |key| format!("some(\"{key}\")"));
    let expression = format!("entry-page({cursor}, {page_size})");
    let raw = runtime.execute(None, None, address, &expression).await?;
    let page: MapPage = from_wave_expr(&raw);
    let expected_next = (end < ROWS).then(|| row_key(end - 1));
    ensure!(
        page.items.len() == end - start && page.next == expected_next,
        "large-value page length or continuation changed"
    );
    let mut rows = Vec::with_capacity(page.items.len());
    for (index, item) in (start..end).zip(page.items) {
        let expected_size = if index == LARGE_INDEX {
            value_bytes
        } else {
            SMALL_VALUE_BYTES
        };
        ensure!(
            item.key == row_key(index)
                && item.value.len() == expected_size
                && item.value.as_bytes().iter().all(|byte| *byte == b'a'),
            "large-value page has missing, duplicate, or changed data"
        );
        rows.push(json!({
            "key": item.key,
            "value_bytes": item.value.len(),
            "value_sha256": hex::encode(Sha256::digest(item.value.as_bytes())),
        }));
    }
    Ok((rows, after, expected_next))
}

pub(super) async fn run(configuration: &str, process_role: &str) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown large-value configuration or role"
    );
    let engine = if configuration == "reduced" {
        Runtime::new_resource_diagnostic_engine()?
    } else {
        Runtime::new_engine()?
    };
    resource_diagnostics::record("fixture_preparation_entry");
    let (mut runtime, _dir, _name) = test_runtime_with_engine(engine).await?;
    let (address, actor) = prepare_fixture(&mut runtime).await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    let conn = runtime.get_storage_conn();
    let component_sha256 = hex::encode(Sha256::digest(COMPONENT));
    let mut outcomes = Vec::with_capacity(VALUE_BYTES.len() * PAGE_SIZES.len() * 2);
    for (size_index, value_bytes) in VALUE_BYTES.into_iter().enumerate() {
        if size_index > 0 {
            resource_diagnostics::record("fixture_preparation_entry");
            runtime
                .set_context(
                    1,
                    Some(TransactionContext::builder().tx_index(0).build()),
                    None,
                    None,
                )
                .await;
        }
        let paid_rejection = if size_index > 0 {
            Some(paid_size_cap_control(&mut runtime, &actor, &address, &conn).await?)
        } else {
            None
        };
        let signer = if size_index == 0 { &actor } else { &core };
        write_entry(
            &mut runtime,
            signer,
            &address,
            &row_key(LARGE_INDEX),
            value_bytes,
        )
        .await?;
        runtime.set_context(1, None, None, None).await;
        resource_diagnostics::record("fixture_preparation_exit");
        let baseline_digest = persistent_digest(&conn).await?;
        let baseline_receipts = receipt_count(&conn).await?;
        for page_size in PAGE_SIZES {
            let sample = format!("value_{value_bytes}_page_{page_size}");
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
                let (rows, cursor, next) =
                    query_page(&mut runtime, &address, value_bytes, page_size).await?;
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
                    "large-value {sample} leaked state or a Store"
                );
                let observation = json!({
                    "sample_key": sample,
                    "outcome": "ok",
                    "page_size": page_size,
                    "value_bytes": value_bytes,
                    "row_count": ROWS,
                    "items": rows,
                    "cursor": cursor,
                    "next": next,
                    "large_key": row_key(LARGE_INDEX),
                    "setup_provenance": if size_index == 0 {"paid"} else {"core_after_paid_rejection"},
                    "paid_rejection": &paid_rejection,
                    "address": format!("{}:{}:{}", address.name, address.height, address.tx_index),
                    "component_sha256": &component_sha256,
                    "publication_path": "Runtime::publish/native_provenance",
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
