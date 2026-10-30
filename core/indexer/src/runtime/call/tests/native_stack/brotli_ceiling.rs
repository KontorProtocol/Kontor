use std::io::Read;
use std::process;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use brotli::CompressorReader;
use libsql::{Connection, params};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use stdlib::to_wave_expr;

use super::{COMPONENT, sweep::persistent_digest};
use crate::runtime::invocation::{InvocationBudget, ResourceProbePhase, ResourceTeardownRecorder};
use crate::runtime::wit::Signer;
use crate::runtime::{
    ContractAddress, ExecutionError, Runtime, TransactionContext, native_provenance,
    resource_diagnostics,
};
use crate::test_utils::test_runtime_with_engine;

const CASE_ID: &str = "brotli_raw_ceiling";
const RAW_CEILING: usize = 67_108_864;
const PAD_NAME: &[u8] = b"kontor-native-stack-padding";
const SAMPLES: [(&str, usize, &str); 2] = [
    ("at_ceiling", RAW_CEILING, "ok"),
    (
        "one_byte_over_rejected",
        RAW_CEILING + 1,
        "deterministic_error",
    ),
];

fn uleb128(mut value: u32) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

fn fixture_bytes(raw_size: usize) -> Result<(Vec<u8>, String)> {
    let mut raw = Vec::new();
    brotli::Decompressor::new(COMPONENT, 4096).read_to_end(&mut raw)?;
    let name_len = u8::try_from(PAD_NAME.len())?;
    let mut section = None;
    for size_len in 1..=5 {
        let overhead = raw.len() + 1 + size_len + 1 + PAD_NAME.len();
        let Some(filler_len) = raw_size.checked_sub(overhead) else {
            continue;
        };
        let payload_len = 1 + PAD_NAME.len() + filler_len;
        let encoded = uleb128(u32::try_from(payload_len)?);
        if encoded.len() == size_len {
            section = Some((encoded, filler_len));
            break;
        }
    }
    let (section_len, filler_len) = section.context("cannot size exact raw Brotli fixture")?;
    // The trailing custom section keeps the source module valid while forcing the
    // real decoder to materialize every byte up to the admission boundary.
    raw.push(0);
    raw.extend(section_len);
    raw.push(name_len);
    raw.extend(PAD_NAME);
    raw.extend(std::iter::repeat_n(0, filler_len));
    ensure!(raw.len() == raw_size, "raw Brotli fixture size changed");
    let raw_sha256 = hex::encode(Sha256::digest(&raw));
    let mut compressed = Vec::new();
    CompressorReader::new(raw.as_slice(), 4096, 5, 22).read_to_end(&mut compressed)?;
    ensure!(
        compressed.len() < raw.len(),
        "Brotli fixture did not compress"
    );
    Ok((compressed, raw_sha256))
}

async fn receipt_count(conn: &Connection) -> Result<u64> {
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    Ok(rows
        .next()
        .await?
        .context("missing receipt count")?
        .get(0)?)
}

async fn latest_receipt_id(conn: &Connection) -> Result<u64> {
    let mut rows = conn
        .query("SELECT COALESCE(MAX(id), 0) FROM contract_results", ())
        .await?;
    Ok(rows
        .next()
        .await?
        .context("missing latest receipt id")?
        .get(0)?)
}

async fn new_receipts(conn: &Connection, previous_id: u64) -> Result<Vec<JsonValue>> {
    let mut rows = conn
        .query(
            "SELECT c.name, r.func, r.status, r.gas, r.size, r.value, \
             r.signer_id, r.payer_signer_id, r.height, r.tx_id, \
             r.input_index, r.op_index, r.result_index \
             FROM contract_results r JOIN contracts c ON c.id = r.contract_id \
             WHERE r.id > ? ORDER BY r.id",
            params![previous_id],
        )
        .await?;
    let mut receipts = Vec::new();
    while let Some(row) = rows.next().await? {
        let contract: String = row.get(0)?;
        let function: String = row.get(1)?;
        let status: String = row.get(2)?;
        let gas: u64 = row.get(3)?;
        let size: u64 = row.get(4)?;
        let value: Option<String> = row.get(5)?;
        let signer_id: u64 = row.get(6)?;
        let payer_signer_id: Option<u64> = row.get(7)?;
        let height: u64 = row.get(8)?;
        let tx_id: Option<u64> = row.get(9)?;
        let input_index: Option<u64> = row.get(10)?;
        let op_index: Option<u64> = row.get(11)?;
        let result_index: u64 = row.get(12)?;
        receipts.push(json!({
            "contract": contract, "function": function, "status": status,
            "gas": gas, "size": size, "value": value,
            "signer_id": signer_id, "payer_signer_id": payer_signer_id,
            "height": height, "tx_id": tx_id, "input_index": input_index,
            "op_index": op_index, "result_index": result_index,
        }));
    }
    Ok(receipts)
}

pub(super) async fn run(configuration: &str, process_role: &str) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown Brotli ceiling configuration or role"
    );
    let engine = if configuration == "reduced" {
        Runtime::new_resource_diagnostic_engine()?
    } else {
        Runtime::new_engine()?
    };
    resource_diagnostics::record("fixture_preparation_entry");
    let (mut runtime, _dir, _name) = test_runtime_with_engine(engine).await?;
    resource_diagnostics::record("fixture_preparation_exit");
    let conn = runtime.get_storage_conn();
    let baseline_digest = persistent_digest(&conn).await?;
    let baseline_receipts = receipt_count(&conn).await?;
    let signer = Signer::Core(Box::new(Signer::Nobody));
    let provenance = native_provenance()?;
    let mut outcomes = Vec::with_capacity(SAMPLES.len() * 2);
    for (sample_index, (sample, raw_size, expected)) in SAMPLES.into_iter().enumerate() {
        let (compressed, raw_sha256) = fixture_bytes(raw_size)?;
        let compressed_sha256 = hex::encode(Sha256::digest(&compressed));
        for repeat_index in 0..2 {
            resource_diagnostics::record("finite_stack_attempt_start");
            let started = Instant::now();
            let address = ContractAddress {
                name: format!("brotli-ceiling-{sample_index}"),
                height: 1,
                tx_index: u32::try_from(sample_index)?,
            };
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
            let receipt_before_id = latest_receipt_id(&conn).await?;
            let resources_before = runtime.table.lock().await.iter_mut().count();
            ensure!(
                state_before_sha256 == baseline_digest && receipts_before == baseline_receipts,
                "Brotli ceiling baseline drifted before {sample}"
            );
            runtime.storage.savepoint().await?;
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
            let payment = runtime.core_payment();
            let previous = runtime.start_usage();
            resource_diagnostics::record("publication_entry");
            let result = runtime
                .publish(&signer, payment, &address.name, &compressed, &provenance)
                .await;
            resource_diagnostics::record("publication_exit");
            let usage = runtime.finish_usage(previous)?;
            runtime.set_context(1, None, None, None).await;
            let expected_address = to_wave_expr(address.clone());
            let (outcome, error_kind, result_value) = match result {
                Ok(value) if expected == "ok" => {
                    ensure!(
                        value == expected_address,
                        "Brotli ceiling publication returned a different address"
                    );
                    ("ok", None, Some(value))
                }
                Err(ExecutionError::Deterministic(error)) if expected == "deterministic_error" => {
                    ensure!(
                        format!("{error:#}")
                            .contains("decompressed contract component exceeds maximum size"),
                        "Brotli ceiling rejection had a different cause: {error:#}"
                    );
                    ("deterministic_error", Some("raw_ceiling_exceeded"), None)
                }
                other => bail!("Brotli ceiling {sample} returned unexpected result: {other:?}"),
            };
            ensure!(
                (outcome == "ok" && usage.system_fuel > 0)
                    || (outcome == "deterministic_error" && usage.system_fuel == 0),
                "Brotli ceiling {sample} charged an unexpected system fuel amount"
            );
            let state_after_sha256 = persistent_digest(&conn).await?;
            let receipts_after = receipt_count(&conn).await?;
            let measured_receipts = new_receipts(&conn, receipt_before_id).await?;
            let row_present = runtime.storage.contract_id(&address).await?.is_some();
            ensure!(
                row_present == (outcome == "ok")
                    && (state_after_sha256 != state_before_sha256) == row_present
                    && receipts_after == receipts_before + u64::from(row_present)
                    && measured_receipts.len() == (if row_present { 1 } else { 0 }),
                "Brotli ceiling {sample} publication or rollback state changed"
            );
            if let Some(receipt) = measured_receipts.first() {
                ensure!(
                    receipt["contract"] == address.name
                        && receipt["function"] == "init"
                        && receipt["status"] == "Ok"
                        && receipt["gas"].as_u64().is_some_and(|gas| gas > 0)
                        && receipt["value"] == expected_address
                        && receipt["size"] == expected_address.len() as u64
                        && receipt["signer_id"] == 1
                        && receipt["payer_signer_id"] == 1
                        && receipt["height"] == 1
                        && receipt["tx_id"].is_null()
                        && receipt["input_index"].is_null()
                        && receipt["op_index"].is_null()
                        && receipt["result_index"] == 0,
                    "Brotli ceiling init receipt identity or value changed"
                );
            }
            runtime.storage.rollback().await?;
            runtime.component_cache.clear();
            let state_restored_sha256 = persistent_digest(&conn).await?;
            let receipts_restored = receipt_count(&conn).await?;
            let resources_after = runtime.table.lock().await.iter_mut().count();
            let stack_empty = runtime.stack.is_empty().await;
            let savepoint_empty = runtime.storage.savepoint_stack.is_empty().await;
            let live_invocations = budget.live();
            ensure!(
                state_restored_sha256 == state_before_sha256
                    && receipts_restored == receipts_before
                    && resources_after == resources_before
                    && stack_empty
                    && savepoint_empty
                    && live_invocations == 0,
                "Brotli ceiling {sample} leaked state or a Store"
            );
            let observation = json!({
                "sample_key": sample,
                "outcome": outcome,
                "error_kind": error_kind,
                "result_value": result_value,
                "raw_bytes": raw_size,
                "raw_sha256": raw_sha256,
                "compressed_bytes": compressed.len(),
                "compressed_sha256": compressed_sha256,
                "publication_path": "Runtime::publish/Storage::decode_component_bytes/spawn_blocking",
                "state_before_sha256": state_before_sha256,
                "state_after_sha256": state_after_sha256,
                "state_restored_sha256": state_restored_sha256,
                "receipts_before": receipts_before,
                "receipts_after": receipts_after,
                "measured_receipts": measured_receipts,
                "receipts_restored": receipts_restored,
                "resources_before": resources_before,
                "resources_after": resources_after,
                "system_fuel": usage.system_fuel,
                "user_fuel": usage.user_fuel,
                "deposit_fuel": usage.deposit_fuel,
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
            outcomes.push(outcome);
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
