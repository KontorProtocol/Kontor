use std::io::Read;
use std::process;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use brotli::CompressorReader;
use indexer_types::{Inst, InstKind, Insts, deserialize, serialize};
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

const FUNCTION_BODY_LIMIT: usize = 7_654_321;
const BR_TABLE_BODY_OVERHEAD: usize = 13;
const BR_TABLE_FIXTURE_MAX: usize = FUNCTION_BODY_LIMIT - BR_TABLE_BODY_OVERHEAD;
const CONTROL_DEPTH: usize = 256;
const MAX_SCRIPT_BYTES: usize = 387 * 1024;

#[derive(Clone, Copy)]
enum Fixture {
    LargeFunction(usize),
    ControlNesting(usize),
    BrTable(usize),
}

impl Fixture {
    fn body(self) -> Result<Vec<u8>> {
        let body = match self {
            Self::LargeFunction(size) => {
                ensure!(size >= 3, "large function body is too short");
                let mut bytes = vec![0x01; size];
                bytes[0] = 0x00;
                bytes[1] = 0x00;
                bytes[size - 1] = 0x0b;
                bytes
            }
            Self::ControlNesting(depth) => {
                let mut bytes = Vec::with_capacity(3 * depth + 3);
                bytes.push(0x00);
                for _ in 0..depth {
                    bytes.extend([0x02, 0x40]);
                }
                bytes.push(0x00);
                bytes.extend(std::iter::repeat_n(0x0b, depth + 1));
                bytes
            }
            Self::BrTable(entries) => {
                let mut bytes = Vec::with_capacity(entries + BR_TABLE_BODY_OVERHEAD + 1);
                bytes.extend([0x00, 0x02, 0x40, 0x41, 0x00, 0x0e]);
                bytes.extend(uleb(u32::try_from(entries)?));
                bytes.extend(std::iter::repeat_n(0x00, entries + 1));
                bytes.extend([0x0b, 0x0b]);
                bytes
            }
        };
        Ok(body)
    }

    fn expected_body_len(self) -> Result<usize> {
        Ok(match self {
            Self::LargeFunction(size) => size,
            Self::ControlNesting(depth) => 3 * depth + 3,
            Self::BrTable(entries) => 9 + uleb(u32::try_from(entries)?).len() + entries,
        })
    }
}

fn uleb(mut value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            return bytes;
        }
    }
}

fn read_uleb(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let mut value = 0_u32;
    for shift in (0..=28).step_by(7) {
        let byte = *bytes.get(*cursor).context("truncated Wasm LEB")?;
        *cursor += 1;
        ensure!(shift != 28 || byte <= 0x0f, "oversized Wasm LEB");
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("Wasm LEB exceeds five bytes")
}

fn append_section(output: &mut Vec<u8>, id: u8, payload: &[u8]) -> Result<()> {
    output.push(id);
    output.extend(uleb(u32::try_from(payload.len())?));
    output.extend(payload);
    Ok(())
}

fn append_function(source: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        source.starts_with(b"\0asm\x01\0\0\0"),
        "stack probe is not a core module"
    );
    let mut output = source[..8].to_vec();
    let mut offset = 8;
    let mut saw_type = false;
    let mut saw_function = false;
    let mut saw_code = false;
    let mut function_count = None;
    let mut code_count = None;
    while offset < source.len() {
        let id = source[offset];
        offset += 1;
        let section_len = usize::try_from(read_uleb(source, &mut offset)?)?;
        let end = offset
            .checked_add(section_len)
            .context("Wasm section length overflow")?;
        let payload = source.get(offset..end).context("truncated Wasm section")?;
        if id == 1 {
            let mut type_start = 0;
            let type_count = read_uleb(payload, &mut type_start)?;
            ensure!(
                !saw_type
                    && type_count > 0
                    && payload.get(type_start..type_start + 5)
                        == Some(&[0x60, 0x02, 0x7f, 0x7f, 0x00][..]),
                "stack probe type 0 changed"
            );
            saw_type = true;
            append_section(&mut output, id, payload)?;
        } else if id == 3 || id == 10 {
            let mut count_end = 0;
            let count = read_uleb(payload, &mut count_end)?;
            let mut extended = uleb(count.checked_add(1).context("function count overflow")?);
            extended.extend(&payload[count_end..]);
            if id == 3 {
                ensure!(!saw_function, "duplicate function section");
                // Type 0 of the pinned stack probe is (i32, i32) -> (), so an
                // unexported added body can exercise compilation without ABI edits.
                extended.push(0);
                saw_function = true;
                function_count = Some(count);
            } else {
                ensure!(!saw_code, "duplicate code section");
                extended.extend(uleb(u32::try_from(body.len())?));
                extended.extend(body);
                saw_code = true;
                code_count = Some(count);
            }
            append_section(&mut output, id, &extended)?;
        } else {
            append_section(&mut output, id, payload)?;
        }
        offset = end;
    }
    ensure!(
        saw_type && saw_function && saw_code && function_count == code_count,
        "stack probe type, function, or code section changed"
    );
    Ok(output)
}

fn fixtures(case_id: &str) -> Result<Vec<(&'static str, Fixture, &'static str)>> {
    match case_id {
        "cold_publish_large_function" => Ok(vec![
            (
                "accepted",
                Fixture::LargeFunction(FUNCTION_BODY_LIMIT),
                "ok",
            ),
            (
                "over_limit_rejected",
                Fixture::LargeFunction(FUNCTION_BODY_LIMIT + 1),
                "deterministic_error",
            ),
        ]),
        "cold_publish_control_nesting" => Ok(vec![(
            "accepted",
            Fixture::ControlNesting(CONTROL_DEPTH),
            "ok",
        )]),
        "cold_publish_br_table" => Ok(vec![
            ("accepted", Fixture::BrTable(BR_TABLE_FIXTURE_MAX), "ok"),
            (
                "over_limit_rejected",
                Fixture::BrTable(BR_TABLE_FIXTURE_MAX + 1),
                "deterministic_error",
            ),
        ]),
        _ => bail!("unknown cold publication case {case_id}"),
    }
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
        receipts.push(json!({
            "contract": row.get::<String>(0)?,
            "function": row.get::<String>(1)?,
            "status": row.get::<String>(2)?,
            "gas": row.get::<u64>(3)?,
            "size": row.get::<u64>(4)?,
            "value": row.get::<Option<String>>(5)?,
            "signer_id": row.get::<u64>(6)?,
            "payer_signer_id": row.get::<Option<u64>>(7)?,
            "height": row.get::<u64>(8)?,
            "tx_id": row.get::<Option<u64>>(9)?,
            "input_index": row.get::<Option<u64>>(10)?,
            "op_index": row.get::<Option<u64>>(11)?,
            "result_index": row.get::<u64>(12)?,
        }));
    }
    Ok(receipts)
}

pub(super) async fn run(
    case_id: &str,
    configuration: &str,
    process_role: &str,
) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown cold publication configuration or role"
    );
    let samples = fixtures(case_id)?;
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
    let mut base = Vec::new();
    brotli::Decompressor::new(COMPONENT, 4096).read_to_end(&mut base)?;
    let mut outcomes = Vec::with_capacity(samples.len() * 2);
    for (sample_index, (sample, fixture, expected)) in samples.into_iter().enumerate() {
        let body = fixture.body()?;
        ensure!(
            body.len() == fixture.expected_body_len()?,
            "cold publication body encoding changed"
        );
        let raw = append_function(&base, &body)?;
        let raw_sha256 = hex::encode(Sha256::digest(&raw));
        let mut compressed = Vec::new();
        CompressorReader::new(raw.as_slice(), 4096, 5, 22).read_to_end(&mut compressed)?;
        let compressed_sha256 = hex::encode(Sha256::digest(&compressed));
        let address = ContractAddress {
            name: format!("cold-{}-{sample_index}", case_id.replace('_', "-")),
            height: 1,
            tx_index: u32::try_from(sample_index)?,
        };
        let insts = Insts::single(Inst {
            gas_limit: 100_000,
            kind: InstKind::Publish {
                name: address.name.clone(),
                bytes: compressed.clone(),
                provenance: provenance.clone(),
            },
        });
        let wire = serialize(&insts)?;
        let decoded: Insts = deserialize(&wire)?;
        ensure!(
            decoded == insts && !wire.is_empty() && wire.len() <= MAX_SCRIPT_BYTES,
            "cold publication fixture does not fit serialized instruction admission"
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
            let state_before_sha256 = persistent_digest(&conn).await?;
            let receipts_before = receipt_count(&conn).await?;
            let receipt_before_id = latest_receipt_id(&conn).await?;
            let resources_before = runtime.table.lock().await.iter_mut().count();
            ensure!(
                state_before_sha256 == baseline_digest && receipts_before == baseline_receipts,
                "cold publication baseline drifted before {sample}"
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
            let (outcome, error_kind, error_text, result_value) = match result {
                Ok(value) if expected == "ok" => {
                    ensure!(
                        value == expected_address,
                        "cold publication address changed"
                    );
                    ("ok", None, None, Some(value))
                }
                Err(ExecutionError::Deterministic(error)) if expected == "deterministic_error" => {
                    let text = format!("{error:#}");
                    ensure!(
                        text.contains("function body size count exceeds limit of 7654321"),
                        "cold publication rejection used a different gate: {text}"
                    );
                    (
                        "deterministic_error",
                        Some("function_body_size_exceeded"),
                        Some(text),
                        None,
                    )
                }
                other => bail!("cold publication {sample} returned unexpected result: {other:?}"),
            };
            let accepted = outcome == "ok";
            ensure!(
                (accepted && usage.system_fuel > 0) || (!accepted && usage.system_fuel == 0),
                "cold publication {sample} charged unexpected system fuel"
            );
            let state_after_sha256 = persistent_digest(&conn).await?;
            let receipts_after = receipt_count(&conn).await?;
            let measured_receipts = new_receipts(&conn, receipt_before_id).await?;
            let row_present = runtime.storage.contract_id(&address).await?.is_some();
            ensure!(
                row_present == accepted
                    && (state_after_sha256 != state_before_sha256) == accepted
                    && receipts_after == receipts_before + u64::from(accepted)
                    && measured_receipts.len() == usize::from(accepted),
                "cold publication {sample} state or rollback changed"
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
                        && receipt["input_index"] == 0
                        && receipt["op_index"] == 0
                        && receipt["result_index"] == 0,
                    "cold publication init receipt identity changed"
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
                "cold publication {sample} leaked state or a Store"
            );
            let observation = json!({
                "sample_key": sample,
                "outcome": outcome,
                "error_kind": error_kind,
                "error_text": error_text,
                "result_value": result_value,
                "function_body_bytes": body.len(),
                "function_body_limit_bytes": FUNCTION_BODY_LIMIT,
                "br_table_entries": match fixture { Fixture::BrTable(n) => Some(n), _ => None },
                "br_table_source_limit_entries": match fixture { Fixture::BrTable(_) => Some(FUNCTION_BODY_LIMIT), _ => None },
                "br_table_fixture_max_entries": match fixture { Fixture::BrTable(_) => Some(BR_TABLE_FIXTURE_MAX), _ => None },
                "control_depth": match fixture { Fixture::ControlNesting(n) => Some(n), _ => None },
                "raw_module_bytes": raw.len(),
                "raw_module_sha256": raw_sha256,
                "compressed_bytes": compressed.len(),
                "compressed_sha256": compressed_sha256,
                "serialized_instruction_bytes": wire.len(),
                "publication_path": "Runtime::publish/Storage::decode_component_bytes/ComponentEncoder/Component::from_binary",
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
                    "case_id": case_id,
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
                    "case_id": case_id,
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
