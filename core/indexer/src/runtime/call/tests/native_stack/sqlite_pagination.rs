use std::process;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, ensure};
use built_in_types::pagination::CursorRequest;
use libsql::Connection;
use serde_json::{Value as JsonValue, json};

use super::sweep::persistent_digest;
use crate::runtime::invocation::{InvocationBudget, ResourceProbePhase, ResourceTeardownRecorder};
use crate::runtime::nft;
use crate::runtime::resource_diagnostics;
use crate::runtime::token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ContractAddress, Decimal, Runtime};
use crate::test_utils::{make_descriptor, test_runtime_with_engine};

const CASE_ID: &str = "sqlite_pagination";
const ACTOR_PUBKEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ROWS: usize = 1_024;
const PAGE_SIZES: [usize; 3] = [1, 7, 100];
const POSITIONS: [&str; 3] = ["first", "middle", "final"];

async fn receipt_count(conn: &Connection) -> Result<u64> {
    let mut rows = conn
        .query("SELECT COUNT(*) FROM contract_results", ())
        .await?;
    Ok(rows.next().await?.unwrap().get(0)?)
}

fn start_index(page_size: usize, position: &str) -> usize {
    match position {
        "first" => 0,
        "middle" => ROWS / 2,
        "final" => ROWS - page_size.div_ceil(2),
        _ => unreachable!("positions are frozen"),
    }
}

async fn populate_token(runtime: &mut Runtime) -> Result<(Signer, Vec<(String, Decimal)>)> {
    let signer = Signer::Id(runtime.get_or_create_identity(ACTOR_PUBKEY).await?);
    ensure!(
        signer.signer_id() == Some(2),
        "pagination actor identity changed"
    );
    let holder = HolderRef::from(&signer);
    let core = Signer::Core(Box::new(Signer::Nobody));
    let actor_amount = Decimal::from("1000000000");
    token::api::issue_to(runtime, &core, holder.clone(), actor_amount).await??;
    let mut balances = vec![(holder.to_string(), actor_amount)];
    for id in 10_000..10_000 + (ROWS - 1) as u64 {
        let holder = HolderRef::SignerId(id);
        let amount = Decimal::from("1");
        token::api::issue_to(runtime, &core, holder.clone(), amount).await??;
        balances.push((holder.to_string(), amount));
    }
    balances.sort_by(|left, right| left.0.cmp(&right.0));
    ensure!(
        balances.len() == ROWS,
        "pagination token fixture size changed"
    );

    Ok((signer, balances))
}

async fn populate_nfts(runtime: &mut Runtime, signer: &Signer) -> Result<Vec<String>> {
    let holder = HolderRef::from(signer);
    let mut nft_ids = Vec::with_capacity(ROWS);
    for index in 0..ROWS {
        let nft_id = format!("nft-{index:04}");
        let agreement_id = format!("file-{index:04}");
        let minted = nft::api::mint(
            runtime,
            signer,
            &nft_id,
            vec![],
            make_descriptor(agreement_id.clone(), vec![1; 32], 16, 10, "file.txt".into()),
        )
        .await??;
        ensure!(
            minted.nft_id == nft_id
                && minted.owner == holder
                && minted.creator == holder
                && minted.agreement_id == agreement_id,
            "pagination NFT fixture mint changed at {index}"
        );
        nft_ids.push(nft_id);
    }
    Ok(nft_ids)
}

async fn query_page(
    runtime: &mut Runtime,
    source: &str,
    page_size: usize,
    after: Option<&str>,
    expected_token: &[(String, Decimal)],
    expected_nft: &[String],
    start: usize,
) -> Result<JsonValue> {
    let end = (start + page_size).min(ROWS);
    let expected_next = (end < ROWS).then(|| {
        if source == "token" {
            expected_token[end - 1].0.clone()
        } else {
            expected_nft[end - 1].clone()
        }
    });
    let request = CursorRequest {
        after: after.map(str::to_owned),
        limit: Some(page_size as u64),
    };
    // The generated cursor builder has a non-Send future. Its generated WAVE
    // functions preserve the same request and result contract on Tokio workers.
    if source == "token" {
        let expression = token::api::wave::balances_call_expr(request);
        let raw = runtime
            .execute_api(None, &token::address(), &expression)
            .await?;
        let page = token::api::wave::balances_parse_return_expr(&raw)?;
        ensure!(
            page.next == expected_next,
            "token page continuation changed"
        );
        ensure!(page.items.len() == end - start, "token page length changed");
        let mut rows = Vec::with_capacity(page.items.len());
        for (item, (account, amount)) in page.items.iter().zip(&expected_token[start..end]) {
            ensure!(
                item.acc.to_string() == *account && item.amt == *amount,
                "token page has a missing, duplicated, or changed row"
            );
            rows.push(json!({"acc": item.acc.to_string(), "amt": item.amt.to_string()}));
        }
        Ok(json!({"items": rows, "next": page.next}))
    } else {
        let expression = nft::api::wave::list_nfts_call_expr(request);
        let raw = runtime
            .execute_api(None, &nft::address(), &expression)
            .await?;
        let page = nft::api::wave::list_nfts_parse_return_expr(&raw);
        ensure!(page.next == expected_next, "NFT page continuation changed");
        ensure!(page.items.len() == end - start, "NFT page length changed");
        let mut rows = Vec::with_capacity(page.items.len());
        for (item, nft_id) in page.items.iter().zip(&expected_nft[start..end]) {
            let index: usize = nft_id[4..].parse()?;
            let agreement_id = format!("file-{index:04}");
            ensure!(
                item.nft_id == *nft_id
                    && item.agreement_id == agreement_id
                    && item.owner == HolderRef::SignerId(2)
                    && item.creator == HolderRef::SignerId(2),
                "NFT page has a missing, duplicated, or changed row"
            );
            rows.push(json!({
                "nft_id": item.nft_id,
                "agreement_id": item.agreement_id,
                "owner": item.owner.to_string(),
                "creator": item.creator.to_string(),
            }));
        }
        Ok(json!({"items": rows, "next": page.next}))
    }
}

pub(super) async fn run(configuration: &str, process_role: &str) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production")
            && matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown pagination configuration or role"
    );
    let engine = if configuration == "reduced" {
        Runtime::new_resource_diagnostic_engine()?
    } else {
        Runtime::new_engine()?
    };
    resource_diagnostics::record("fixture_preparation_entry");
    let (mut runtime, _dir, _name) = test_runtime_with_engine(engine).await?;
    let (signer, expected_token) = populate_token(&mut runtime).await?;
    resource_diagnostics::record("fixture_preparation_exit");
    let conn = runtime.get_storage_conn();
    let mut expected_nft = Vec::new();
    let mut outcomes = Vec::with_capacity(2 * 3 * 3 * 2);
    for source in ["token", "nft"] {
        if source == "nft" {
            runtime.invocation_budget = None;
            runtime.resource_probe_phase = None;
            resource_diagnostics::record("fixture_preparation_entry");
            expected_nft = populate_nfts(&mut runtime, &signer).await?;
            resource_diagnostics::record("fixture_preparation_exit");
        }
        let baseline_digest = persistent_digest(&conn).await?;
        let baseline_receipts = receipt_count(&conn).await?;
        let address: ContractAddress = if source == "token" {
            token::address()
        } else {
            nft::address()
        };
        for page_size in PAGE_SIZES {
            for position in POSITIONS {
                let start = start_index(page_size, position);
                let after = (start > 0).then(|| {
                    if source == "token" {
                        expected_token[start - 1].0.as_str()
                    } else {
                        expected_nft[start - 1].as_str()
                    }
                });
                let sample = format!("{source}_{page_size}_{position}");
                for repeat_index in 0..2 {
                    resource_diagnostics::record("finite_stack_attempt_start");
                    let started = Instant::now();
                    let recorder = (process_role == "target_observed")
                        .then(|| Arc::new(ResourceTeardownRecorder::default()));
                    let budget = Arc::new(match recorder.as_ref() {
                        Some(recorder) => {
                            InvocationBudget::with_teardown_recorder(recorder.clone())
                        }
                        None => InvocationBudget::default(),
                    });
                    runtime.invocation_budget = Some(budget.clone());
                    runtime.resource_probe_phase =
                        Some(ResourceProbePhase::Target(Arc::new(vec![address.clone()])));
                    let state_before_sha256 = persistent_digest(&conn).await?;
                    let receipts_before = receipt_count(&conn).await?;
                    let resources_before = runtime.table.lock().await.iter_mut().count();
                    let previous = runtime.start_usage();
                    let result = query_page(
                        &mut runtime,
                        source,
                        page_size,
                        after,
                        &expected_token,
                        &expected_nft,
                        start,
                    )
                    .await?;
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
                        "pagination {sample} leaked state or a Store"
                    );
                    let observation = json!({
                        "sample_key": sample,
                        "outcome": "ok",
                        "page": result,
                        "cursor": after,
                        "page_size": page_size,
                        "row_count": ROWS,
                        "address": format!("{}:{}:{}", address.name, address.height, address.tx_index),
                        "execution_path": "Runtime::execute_api/Runtime::invoke",
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
    }
    runtime.invocation_budget = None;
    runtime.resource_probe_phase = None;
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
