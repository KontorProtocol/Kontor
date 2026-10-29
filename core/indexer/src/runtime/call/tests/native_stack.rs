use std::env;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use indexer_types::Payment;
use libsql::params;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use stdlib::to_wave_expr;
use wasmtime::Trap;

use super::super::SYSTEM_FUEL_CEILING;
use super::funded;
use crate::runtime::invocation::InvocationLimitReached;
use crate::runtime::wit::Signer;
use crate::runtime::{
    ContractAddress, ExecutionError, MAX_UNTRUSTED_GAS_LIMIT, TransactionContext, native_provenance,
};
use crate::test_utils::test_runtime;

const COMPONENT: &[u8] =
    include_bytes!("../../../../../../test-contracts/binaries/stack_probe.wasm.br");
const CRYPTO_COMPONENT: &[u8] =
    include_bytes!("../../../../../../test-contracts/binaries/crypto.wasm.br");

mod canonical;
mod initialization;
mod lifecycle;
mod sweep;

pub(super) use sweep::{assert_receipt_stream_initial_state, persistent_digest};

pub(super) async fn resource_smoke(reduced: bool) -> Result<()> {
    sweep::resource_smoke(reduced).await
}

pub(super) async fn resource_boundary(
    case_id: &str,
    configuration: &str,
    process_role: &str,
    frozen_depths: Option<(u32, u32)>,
) -> Result<JsonValue> {
    sweep::run_resource_boundary(case_id, configuration, process_role, frozen_depths).await
}

pub(super) async fn resource_finite_paid(
    case_id: &str,
    configuration: &str,
    process_role: &str,
) -> Result<JsonValue> {
    sweep::run_resource_finite_paid(case_id, configuration, process_role).await
}

pub(super) async fn resource_canonical(
    case_id: &str,
    configuration: &str,
    process_role: &str,
) -> Result<JsonValue> {
    sweep::run_resource_canonical(case_id, configuration, process_role).await
}

pub(super) async fn resource_pending_host_io(
    configuration: &str,
    process_role: &str,
) -> Result<JsonValue> {
    sweep::run_resource_pending_host_io(configuration, process_role).await
}

pub(super) async fn resource_generated_initialization(
    configuration: &str,
    process_role: &str,
) -> Result<JsonValue> {
    initialization::run(configuration, process_role).await
}

pub(super) async fn resource_lifecycle(
    case_id: &str,
    configuration: &str,
    process_role: &str,
) -> Result<JsonValue> {
    lifecycle::run(case_id, configuration, process_role).await
}

#[tokio::test]
#[ignore = "run through the bounded resource child driver"]
async fn pending_host_io_diagnostic() -> Result<()> {
    resource_pending_host_io("production", "target_observed").await?;
    Ok(())
}

#[tokio::test]
#[ignore = "run through tools/native-stack/qualify.py so process aborts are observable"]
async fn qualification_probe() -> Result<()> {
    if let Ok(mode) = env::var("KONTOR_STACK_MODE") {
        return sweep::run(&mode).await;
    }
    let total_start = Instant::now();
    let kind = env::var("KONTOR_STACK_KIND").context("KONTOR_STACK_KIND is required")?;
    let depth = env::var("KONTOR_STACK_DEPTH")
        .context("KONTOR_STACK_DEPTH is required")?
        .parse::<u32>()?;
    let setup_start = Instant::now();
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let setup_ms = setup_start.elapsed().as_millis();
    let funding_start = Instant::now();
    let signer = funded(&mut runtime).await?;
    let funding_ms = funding_start.elapsed().as_millis();
    let publication_start = Instant::now();
    let payment = Payment {
        signer_id: signer.signer_id().unwrap(),
        gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
    };
    let contract_count = if kind == "paid_reenter" {
        depth.checked_add(1).context("reentry depth overflow")?
    } else {
        1
    };
    for tx_index in 0..contract_count {
        runtime
            .set_context(
                1,
                Some(TransactionContext::builder().tx_index(tx_index).build()),
                None,
                None,
            )
            .await;
        runtime
            .publish(
                &signer,
                payment.clone(),
                "stack-probe",
                COMPONENT,
                &native_provenance()?,
            )
            .await
            .context("fixture must pass real publish, component policy, and WIT validation")?;
    }
    runtime.set_context(1, None, None, None).await;
    let publication_ms = publication_start.elapsed().as_millis();
    let pre_execution_start = Instant::now();
    let address = ContractAddress {
        name: "stack-probe".into(),
        height: 1,
        tx_index: 0,
    };
    let expression = match kind.as_str() {
        "paid_recurse" | "system_recurse" | "view_recurse" | "core_recurse" => {
            let function = match kind.as_str() {
                "paid_recurse" => "recurse",
                "core_recurse" => "core-recurse",
                _ => "view-recurse",
            };
            format!("{function}({depth})")
        }
        "paid_wide" | "system_wide" | "view_wide" | "core_wide" => {
            let function = match kind.as_str() {
                "paid_wide" => "wide-recurse",
                "core_wide" => "core-wide-recurse",
                _ => "view-wide-recurse",
            };
            let data = to_wave_expr((0..32u64).collect::<Vec<_>>());
            format!("{function}({depth}, {data})")
        }
        "paid_huge" => {
            let data = to_wave_expr((0..256u64).collect::<Vec<_>>());
            format!("huge-frame({data})")
        }
        "paid_reenter" => format!(
            "reenter({}, {depth})",
            to_wave_expr(ContractAddress {
                tx_index: 1,
                ..address.clone()
            })
        ),
        _ => bail!("unknown probe kind {kind}"),
    };
    let max_wasm_stack = runtime.engine.get_max_wasm_stack();
    let async_stack_size = runtime.engine.get_async_stack_size();
    let view_gas_limit = runtime.view_gas_limit;
    let view_fuel_limit = runtime.fuel_limit_for_view()?;
    let system = kind.starts_with("system_");
    let core = kind.starts_with("core_");
    let view = kind.starts_with("view_");
    let contract_id = runtime.storage.contract_id(&address).await?.unwrap();
    let conn = runtime.get_storage_conn();
    let previous_result_id = {
        let mut rows = conn
            .query(
                "SELECT COALESCE(MAX(id), 0) FROM contract_results WHERE contract_id = ?",
                params![contract_id],
            )
            .await?;
        rows.next().await?.unwrap().get::<u64>(0)?
    };
    let previous = runtime.start_usage();
    let pre_execution_ms = pre_execution_start.elapsed().as_millis();
    let execution_start = Instant::now();
    let result = if system {
        runtime.execute_system_view(&address, &expression).await
    } else if core {
        let core_signer = Signer::Core(Box::new(signer.clone()));
        let core_payment = Payment {
            signer_id: signer.signer_id().unwrap(),
            gas_limit: u64::MAX,
        };
        runtime
            .execute(
                Some(&core_signer),
                Some(core_payment),
                &address,
                &expression,
            )
            .await
    } else if view {
        runtime.execute(None, None, &address, &expression).await
    } else {
        runtime
            .execute(Some(&signer), Some(payment), &address, &expression)
            .await
    };
    let execution_ms = execution_start.elapsed().as_millis();
    let postcall_start = Instant::now();
    let usage = runtime.finish_usage(previous)?;
    let (outcome, error_message, value) = match result {
        Ok(value) => ("ok", None, Some(value)),
        Err(ExecutionError::Deterministic(error)) => {
            let trap = error.chain().find_map(|cause| cause.downcast_ref::<Trap>());
            let outcome = if error
                .chain()
                .any(|cause| cause.downcast_ref::<InvocationLimitReached>().is_some())
            {
                assert!(trap.is_none());
                "invocation_limit"
            } else {
                match trap {
                    Some(Trap::StackOverflow) => "stack_overflow",
                    Some(Trap::OutOfFuel) => "out_of_fuel",
                    Some(_) => "other_trap",
                    None => "other_deterministic",
                }
            };
            (outcome, Some(format!("{error:#}")), None)
        }
        Err(ExecutionError::NonDeterministic(error)) => {
            ("non_deterministic", Some(format!("{error:#}")), None)
        }
    };
    let mut rows = conn
        .query(
            "SELECT status, gas FROM contract_results WHERE contract_id = ? AND id > ? ORDER BY id DESC LIMIT 1",
            params![contract_id, previous_result_id],
        )
        .await?;
    let receipt = if let Some(row) = rows.next().await? {
        Some(json!({
            "status": row.get::<String>(0)?,
            "gas": row.get::<u64>(1)?,
        }))
    } else {
        None
    };
    let last_depth = runtime
        .execute(None, None, &address, "last-depth()")
        .await?
        .parse::<u32>()?;
    let mut child_markers = Vec::new();
    if kind == "paid_reenter" {
        for tx_index in 1..contract_count {
            let child = ContractAddress {
                tx_index,
                ..address.clone()
            };
            child_markers.push(
                runtime
                    .execute(None, None, &child, "last-depth()")
                    .await?
                    .parse::<u32>()?,
            );
        }
    }
    let rolled_back = if matches!(
        outcome,
        "stack_overflow" | "out_of_fuel" | "other_trap" | "invocation_limit"
    ) {
        last_depth == 0 && child_markers.iter().all(|marker| *marker == 0)
    } else {
        false
    };
    let expected_receipt = if system || view {
        None
    } else {
        Some(match outcome {
            "ok" => "Ok",
            "out_of_fuel" => "OutOfFuel",
            "stack_overflow" | "other_trap" => "Trap",
            "invocation_limit" => "Other",
            _ => bail!("unexpected outcome {outcome}: {error_message:?}"),
        })
    };
    assert_eq!(
        receipt.as_ref().map(|row| row["status"].as_str().unwrap()),
        expected_receipt,
        "persisted contract result does not match the execution outcome"
    );
    let report = json!({
        "kind": kind,
        "depth": depth,
        "outcome": outcome,
        "error": error_message,
        "value": value,
        "receipt": receipt,
        "last_depth": last_depth,
        "child_markers": child_markers,
        "rolled_back": rolled_back,
        "fuel": {
            "user": usage.user_fuel,
            "system": usage.system_fuel,
            "deposit": usage.deposit_fuel,
        },
        "gas_limit": MAX_UNTRUSTED_GAS_LIMIT,
        "paid_fuel_limit": MAX_UNTRUSTED_GAS_LIMIT * runtime.gas_to_fuel_multiplier,
        "view_gas_limit": view_gas_limit,
        "view_fuel_limit": view_fuel_limit,
        "system_fuel_ceiling": SYSTEM_FUEL_CEILING,
        "gas_to_fuel_multiplier": runtime.gas_to_fuel_multiplier,
        "max_wasm_stack": max_wasm_stack,
        "async_stack_size": async_stack_size,
        "engine_target": runtime.engine.get_target(),
        "component_sha256": hex::encode(Sha256::digest(COMPONENT)),
        "target_os": env::consts::OS,
        "target_arch": env::consts::ARCH,
    });
    println!("KONTOR_STACK_REPORT:{report}");
    assert!(runtime.stack.is_empty().await);
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    if matches!(
        outcome,
        "stack_overflow" | "out_of_fuel" | "other_trap" | "invocation_limit"
    ) {
        assert!(rolled_back, "failed paid call changed contract state");
    }
    println!(
        "KONTOR_STACK_TIMING:{}",
        json!({
            "kind": kind,
            "depth": depth,
            "setup_ms": setup_ms,
            "funding_ms": funding_ms,
            "publication_ms": publication_ms,
            "pre_execution_ms": pre_execution_ms,
            "execution_ms": execution_ms,
            "postcall_ms": postcall_start.elapsed().as_millis(),
            "total_ms": total_start.elapsed().as_millis(),
        })
    );
    Ok(())
}
