use std::collections::HashMap;
use std::env;
use std::future::{Future, poll_fn};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use indexer_types::Payment;
use libsql::{Connection, Value as SqlValue, params};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use stdlib::{KeyPath, from_wave_expr, to_wave_expr};
use tempfile::TempDir;
use tokio::sync::Notify;
use tokio::time::timeout;
use wasmtime::component::Access;
use wasmtime::{AsContextMut, Error as WasmtimeError, Trap};

use super::super::balance;
use super::{COMPONENT, CRYPTO_COMPONENT, SYSTEM_FUEL_CEILING, canonical};
use crate::database::queries::live_deposit_gas_sum;
use crate::runtime::invocation::{
    InvocationBudget, InvocationLimitReached, ResourceProbePhase, ResourceTeardownRecorder,
};
use crate::runtime::pricing::Pricing;
use crate::runtime::resource_diagnostics;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, Linkers, MAX_UNTRUSTED_GAS_LIMIT, Runtime,
    TransactionContext, native_provenance,
};
use crate::test_utils::test_runtime_with_engine;

const ACTOR_PUBKEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

struct Sample {
    depth: u32,
    outcome: String,
    id: String,
}

struct Fixture {
    runtime: Runtime,
    _dir: TempDir,
    kind: String,
    component_sha256: String,
    signer: Signer,
    payment: Payment,
    address: ContractAddress,
    fixture_contracts: u32,
    budget: Arc<InvocationBudget>,
    baseline_digest: String,
    baseline_resources: usize,
    baseline_balance: Decimal,
    baseline_burner: Decimal,
    baseline_floor: Decimal,
    baseline_live_deposit_gas: u64,
    baseline_supply: Decimal,
    setup_ms: u128,
    funding_ms: u128,
    publication_ms: u128,
    samples: Vec<Sample>,
    resource_probe: Option<bool>,
    last_report: Option<JsonValue>,
}

impl Fixture {
    async fn new(kind: String, reduced: bool) -> Result<Self> {
        resource_diagnostics::record("fixture_preparation_entry");
        let setup_start = Instant::now();
        let engine = if reduced {
            Runtime::new_resource_diagnostic_engine()?
        } else {
            Runtime::new_engine()?
        };
        let (mut runtime, dir, _name) = test_runtime_with_engine(engine).await?;
        ensure!(
            runtime.pricing.storage_deposit_gas(1) == Some(1)
                && Pricing::collateral_unit_price() == Decimal::from("1e-9")
                && KeyPath::new().push_interned(0).len() == 2,
            "boundary fixture storage pricing or path encoding changed"
        );
        for (value, bytes) in [(0_u64, 1), (127, 1), (128, 2), (16383, 2), (16384, 3)] {
            ensure!(
                postcard::to_allocvec(&value)?.len() == bytes,
                "boundary fixture Postcard integer encoding changed"
            );
        }
        let setup_ms = setup_start.elapsed().as_millis();
        let funding_start = Instant::now();
        let signer = Signer::Id(runtime.get_or_create_identity(ACTOR_PUBKEY).await?);
        token::issue_to(
            &mut runtime,
            &Signer::Core(Box::new(Signer::Nobody)),
            HolderRef::from(&signer),
            Decimal::from("100"),
        )
        .await??;
        let funding_ms = funding_start.elapsed().as_millis();
        let payment = Payment {
            signer_id: signer.signer_id().unwrap(),
            gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
        };
        let fixture_contracts = if kind == "paid_reenter" { 65 } else { 1 };
        let (name, component) = if kind == "view_crypto" {
            ("crypto", CRYPTO_COMPONENT.to_vec())
        } else if kind.contains("_canonical_") {
            ("canonical-probe", canonical::fixture_bytes_for_kind(&kind)?)
        } else {
            ("stack-probe", COMPONENT.to_vec())
        };
        let component_sha256 = hex::encode(Sha256::digest(&component));
        let publication_start = Instant::now();
        resource_diagnostics::record("publication_entry");
        for tx_index in 0..fixture_contracts {
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
                    name,
                    &component,
                    &native_provenance()?,
                )
                .await
                .context("fixture must pass real publish, component policy, and WIT validation")?;
        }
        resource_diagnostics::record("publication_exit");
        runtime.set_context(1, None, None, None).await;
        let publication_ms = publication_start.elapsed().as_millis();
        let address = ContractAddress {
            name: name.into(),
            height: 1,
            tx_index: 0,
        };
        let budget = Arc::new(InvocationBudget::default());
        runtime.invocation_budget = Some(budget.clone());
        ensure!(
            runtime.conversion_probe.is_none(),
            "fixture installed a call hook"
        );
        let baseline_resources = runtime.table.lock().await.iter_mut().count();
        ensure!(runtime.stack.is_empty().await, "fixture left call frames");
        ensure!(
            runtime.storage.savepoint_stack.is_empty().await,
            "fixture left savepoints"
        );
        let baseline_balance = balance(&mut runtime, HolderRef::from(&signer)).await?;
        let baseline_burner = balance(&mut runtime, HolderRef::Burner).await?;
        let baseline_floor = token::floor(&mut runtime, HolderRef::from(&signer)).await?;
        let conn = runtime.get_storage_conn();
        let baseline_live_deposit_gas =
            live_deposit_gas_sum(&conn, signer.signer_id().unwrap()).await?;
        ensure!(
            (if kind == "view_crypto" {
                baseline_live_deposit_gas > 0
            } else if kind.contains("_canonical_") {
                baseline_live_deposit_gas == 0
            } else {
                baseline_live_deposit_gas == 3 * u64::from(fixture_contracts)
            }) && baseline_floor == Pricing::storage_collateral(baseline_live_deposit_gas)?,
            "boundary fixture baseline storage deposit changed: kind={kind} live={baseline_live_deposit_gas} floor={baseline_floor} expected={}",
            Pricing::storage_collateral(baseline_live_deposit_gas)?
        );
        let baseline_supply = token::total_supply(&mut runtime).await?;
        ensure!(budget.live() == 0, "fixture left live invocation Stores");
        assert_receipt_stream_initial_state(&conn).await?;
        let baseline_digest = persistent_digest(&conn).await?;
        resource_diagnostics::record("fixture_preparation_exit");
        Ok(Self {
            runtime,
            _dir: dir,
            kind,
            component_sha256,
            signer,
            payment,
            address,
            fixture_contracts,
            budget,
            baseline_digest,
            baseline_resources,
            baseline_balance,
            baseline_burner,
            baseline_floor,
            baseline_live_deposit_gas,
            baseline_supply,
            setup_ms,
            funding_ms,
            publication_ms,
            samples: Vec::new(),
            resource_probe: None,
            last_report: None,
        })
    }

    async fn observe(&mut self, depth: u32, role: &str) -> Result<String> {
        resource_diagnostics::record("sample_preparation_entry");
        let sample_index = self.samples.len();
        let sample_id = format!("{role}:{}:{sample_index:04}", self.kind);
        let teardown_recorder = (self.resource_probe == Some(true))
            .then(|| Arc::new(ResourceTeardownRecorder::default()));
        if let Some(probe) = self.resource_probe {
            self.budget = Arc::new(match teardown_recorder.as_ref() {
                Some(recorder) => InvocationBudget::with_teardown_recorder(recorder.clone()),
                None => InvocationBudget::default(),
            });
            self.runtime.invocation_budget = Some(self.budget.clone());
            self.runtime.resource_probe_phase = Some(ResourceProbePhase::PreObservation);
            ensure!(
                probe == teardown_recorder.is_some(),
                "teardown probe mode differs"
            );
        }
        let state_before_sha256 = if self.resource_probe.is_some() {
            let conn = self.runtime.get_storage_conn();
            assert_receipt_stream_initial_state(&conn).await?;
            let before = persistent_digest(&conn).await?;
            ensure!(
                before == self.baseline_digest,
                "pretrial persistent state drift"
            );
            Some(before)
        } else {
            None
        };
        // conversion_probe is the only call-hook install site in this runtime.
        // Reaudit this sentinel if another install path is added.
        let call_hook_installed = self.runtime.conversion_probe.is_some();
        ensure!(!call_hook_installed, "call hook installed in {sample_id}");
        let total_start = Instant::now();
        self.runtime.storage.savepoint().await?;
        let outer_savepoint = self.runtime.storage.savepoint_stack.peek().await;
        let conn = self.runtime.get_storage_conn();
        let contract_id = self
            .runtime
            .storage
            .contract_id(&self.address)
            .await?
            .unwrap();
        let mut rows = conn
            .query(
                "SELECT COALESCE(MAX(id), 0) FROM contract_results WHERE contract_id = ?",
                params![contract_id],
            )
            .await?;
        let previous_result_id: u64 = rows.next().await?.unwrap().get(0)?;
        let live_deposit_gas_before = if self.resource_probe.is_some() {
            let gas = live_deposit_gas_sum(&conn, self.signer.signer_id().unwrap()).await?;
            ensure!(
                gas == self.baseline_live_deposit_gas,
                "pretrial storage deposit drift in {sample_id}"
            );
            Some(gas)
        } else {
            None
        };
        let expression = expression(&self.kind, depth, &self.address)?;
        let previous = self.runtime.start_usage();
        let execution_start = Instant::now();
        resource_diagnostics::record("sample_preparation_exit");
        resource_diagnostics::record("operation_entry");
        if self.resource_probe.is_some() {
            self.runtime.resource_probe_phase = Some(ResourceProbePhase::Target(Arc::new(vec![
                self.address.clone(),
            ])));
        }
        let result = if self.kind.starts_with("system_") {
            self.runtime
                .execute_system_view(&self.address, &expression)
                .await
        } else if self.kind.starts_with("core_") {
            let core_signer = Signer::Core(Box::new(self.signer.clone()));
            self.runtime
                .execute(
                    Some(&core_signer),
                    Some(Payment {
                        signer_id: self.signer.signer_id().unwrap(),
                        gas_limit: u64::MAX,
                    }),
                    &self.address,
                    &expression,
                )
                .await
        } else if self.kind.starts_with("view_") {
            self.runtime
                .execute(None, None, &self.address, &expression)
                .await
        } else {
            self.runtime
                .execute(
                    Some(&self.signer),
                    Some(self.payment.clone()),
                    &self.address,
                    &expression,
                )
                .await
        };
        resource_diagnostics::record("operation_exit");
        if self.resource_probe.is_some() {
            self.runtime.resource_probe_phase =
                Some(ResourceProbePhase::PostObservation(self.address.clone()));
        }
        let execution_ms = execution_start.elapsed().as_millis();
        let postcall_start = Instant::now();
        resource_diagnostics::record("postcall_observation_entry");
        // Observe the tested call before diagnostic views can touch its context.
        let pre_live = self.budget.live();
        let pre_stack_empty = self.runtime.stack.is_empty().await;
        let pre_savepoint_intact =
            self.runtime.storage.savepoint_stack.peek().await == outer_savepoint;
        let pre_resources = self.runtime.table.lock().await.iter_mut().count();
        ensure!(pre_live == 0, "live Store leak in {sample_id}: {pre_live}");
        ensure!(pre_stack_empty, "call frame leak in {sample_id}");
        ensure!(pre_savepoint_intact, "nested savepoint leak in {sample_id}");
        ensure!(
            pre_resources == self.baseline_resources,
            "resource leak in {sample_id}"
        );
        ensure!(
            self.runtime.deposit.take().await == 0,
            "deposit accounting leak in {sample_id}"
        );
        let usage = self.runtime.finish_usage(previous)?;
        let (outcome, error_message, value, typed_trap) = match result {
            Ok(value) => ("ok", None, Some(value), None),
            Err(ExecutionError::Deterministic(error)) => {
                let trap = error.chain().find_map(|cause| cause.downcast_ref::<Trap>());
                let outcome = if error
                    .chain()
                    .any(|cause| cause.downcast_ref::<InvocationLimitReached>().is_some())
                {
                    "invocation_limit"
                } else {
                    match trap {
                        Some(Trap::StackOverflow) => "stack_overflow",
                        Some(Trap::OutOfFuel) => "out_of_fuel",
                        Some(_) => "other_trap",
                        None => "other_deterministic",
                    }
                };
                (
                    outcome,
                    Some(format!("{error:#}")),
                    None,
                    trap.map(|trap| format!("{trap:?}")),
                )
            }
            Err(ExecutionError::NonDeterministic(error)) => {
                bail!("infrastructure failure in {sample_id}: {error:#}")
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
        let last_depth = if self.kind == "view_crypto" || self.kind.contains("_canonical_") {
            0
        } else {
            self.runtime
                .execute(None, None, &self.address, "last-depth()")
                .await?
                .parse::<u32>()?
        };
        let live_deposit_gas_after = if self.resource_probe.is_some() {
            Some(live_deposit_gas_sum(&conn, self.signer.signer_id().unwrap()).await?)
        } else {
            None
        };
        let after_amounts = if self.resource_probe.is_some() {
            Some((
                balance(&mut self.runtime, HolderRef::from(&self.signer)).await?,
                balance(&mut self.runtime, HolderRef::Burner).await?,
                token::floor(&mut self.runtime, HolderRef::from(&self.signer)).await?,
                token::total_supply(&mut self.runtime).await?,
            ))
        } else {
            None
        };
        let mut child_markers = Vec::new();
        if self.kind == "paid_reenter" {
            for tx_index in 1..self.fixture_contracts {
                let child = ContractAddress {
                    tx_index,
                    ..self.address.clone()
                };
                child_markers.push(
                    self.runtime
                        .execute(None, None, &child, "last-depth()")
                        .await?
                        .parse::<u32>()?,
                );
            }
        }
        let failed = matches!(
            outcome,
            "stack_overflow" | "out_of_fuel" | "other_trap" | "invocation_limit"
        );
        let failure_rolled_back = if failed {
            Some(last_depth == 0 && child_markers.iter().all(|marker| *marker == 0))
        } else {
            None
        };
        let expected_receipt = if self.kind.starts_with("system_") || self.kind.starts_with("view_")
        {
            None
        } else {
            Some(match outcome {
                "ok" => "Ok",
                "out_of_fuel" => "OutOfFuel",
                "stack_overflow" | "other_trap" => "Trap",
                "invocation_limit" => "Other",
                _ => bail!("unexpected outcome {outcome} in {sample_id}: {error_message:?}"),
            })
        };
        ensure!(
            receipt.as_ref().map(|row| row["status"].as_str().unwrap()) == expected_receipt,
            "receipt mismatch in {sample_id}"
        );
        ensure!(
            failure_rolled_back != Some(false),
            "failed call changed state in {sample_id}"
        );
        resource_diagnostics::record("postcall_observation_exit");

        resource_diagnostics::record("teardown_entry");
        if self.resource_probe.is_some() {
            self.runtime.resource_probe_phase = Some(ResourceProbePhase::RollbackObservation(
                self.address.clone(),
            ));
        }
        self.runtime.storage.rollback().await?;
        self.runtime.set_context(1, None, None, None).await;
        ensure!(
            self.runtime.id_generation_counter.get().await == 0
                && self.runtime.result_id_counter.get().await == 0
                && self.runtime.gauge.is_none(),
            "execution accounting did not reset in {sample_id}"
        );
        let balance_restored = balance(&mut self.runtime, HolderRef::from(&self.signer)).await?;
        let burned_restored = balance(&mut self.runtime, HolderRef::Burner).await?;
        let floor_restored_amount =
            token::floor(&mut self.runtime, HolderRef::from(&self.signer)).await?;
        let live_deposit_gas_restored = if self.resource_probe.is_some() {
            Some(live_deposit_gas_sum(&conn, self.signer.signer_id().unwrap()).await?)
        } else {
            None
        };
        let supply_restored_amount = token::total_supply(&mut self.runtime).await?;
        let balances_restored =
            balance_restored == self.baseline_balance && burned_restored == self.baseline_burner;
        let floor_restored = floor_restored_amount == self.baseline_floor;
        let supply_restored = supply_restored_amount == self.baseline_supply;
        assert_receipt_stream_initial_state(&conn).await?;
        let post_digest = persistent_digest(&conn).await?;
        let digest_matches = post_digest == self.baseline_digest;
        let post_live = self.budget.live();
        let post_stack_empty = self.runtime.stack.is_empty().await;
        let post_savepoint_restored = self.runtime.storage.savepoint_stack.is_empty().await;
        let post_resources = self.runtime.table.lock().await.iter_mut().count();
        ensure!(
            digest_matches,
            "persistent state did not reset in {sample_id}"
        );
        ensure!(post_live == 0, "Store lease survived reset in {sample_id}");
        ensure!(
            post_stack_empty && post_savepoint_restored,
            "execution context did not reset in {sample_id}"
        );
        ensure!(
            post_resources == self.baseline_resources,
            "resource count did not reset in {sample_id}"
        );
        ensure!(
            balances_restored && floor_restored && supply_restored,
            "accounting did not reset in {sample_id}"
        );
        resource_diagnostics::record("teardown_exit");
        let teardown_events = teardown_recorder.as_ref().map(|recorder| recorder.events());
        self.runtime.resource_probe_phase = None;

        let mut report = json!({
            "role": role,
            "sample_index": sample_index,
            "sample_id": sample_id,
            "cache_mode": "warm_compiled_cache",
            "call_hook_installed": call_hook_installed,
            "fixture_contracts": self.fixture_contracts,
            "kind": self.kind,
            "depth": depth,
            "outcome": outcome,
            "error": error_message,
            "value": value,
            "receipt": receipt,
            "last_depth": last_depth,
            "child_markers": child_markers,
            "rolled_back": failure_rolled_back.unwrap_or(false),
            "fuel": {
                "user": usage.user_fuel,
                "system": usage.system_fuel,
                "deposit": usage.deposit_fuel,
            },
            "gas_limit": MAX_UNTRUSTED_GAS_LIMIT,
            "paid_fuel_limit": MAX_UNTRUSTED_GAS_LIMIT * self.runtime.gas_to_fuel_multiplier,
            "view_gas_limit": self.runtime.view_gas_limit,
            "view_fuel_limit": self.runtime.fuel_limit_for_view()?,
            "system_fuel_ceiling": SYSTEM_FUEL_CEILING,
            "gas_to_fuel_multiplier": self.runtime.gas_to_fuel_multiplier,
            "max_wasm_stack": self.runtime.engine.get_max_wasm_stack(),
            "async_stack_size": self.runtime.engine.get_async_stack_size(),
            "engine_target": self.runtime.engine.get_target(),
            "component_sha256": self.component_sha256,
            "target_os": env::consts::OS,
            "target_arch": env::consts::ARCH,
            "reset": {
                "pre": {
                    "live_invocations": pre_live,
                    "stack_empty": pre_stack_empty,
                    "savepoint_intact": pre_savepoint_intact,
                    "resource_count": pre_resources,
                    "baseline_resource_count": self.baseline_resources,
                    "failure_rolled_back": failure_rolled_back,
                },
                "post": {
                    "persistent_digest_sha256": post_digest,
                    "baseline_digest_sha256": self.baseline_digest,
                    "digest_matches": digest_matches,
                    "live_invocations": post_live,
                    "stack_empty": post_stack_empty,
                    "savepoint_restored": post_savepoint_restored,
                    "resource_count": post_resources,
                    "balances_restored": balances_restored,
                    "floor_restored": floor_restored,
                    "supply_restored": supply_restored,
                },
            },
        });
        if self.resource_probe.is_some() {
            let (balance_after, burned_after, floor_after, supply_after) =
                after_amounts.context("resource balance observations are missing")?;
            let transitions = json!({
                "before": self.baseline_balance.to_string(),
                "after": balance_after.to_string(),
                "restored": balance_restored.to_string(),
                "burned_before": self.baseline_burner.to_string(),
                "burned_after": burned_after.to_string(),
                "supply_before": self.baseline_supply.to_string(),
                "supply_after": supply_after.to_string(),
                "floor_before": self.baseline_floor.to_string(),
                "floor_after": floor_after.to_string(),
                "floor_restored": floor_restored_amount.to_string(),
            });
            let live_deposit_gas = json!({
                "before": live_deposit_gas_before.context("missing pretrial live deposit")?,
                "after": live_deposit_gas_after.context("missing postcall live deposit")?,
                "restored": live_deposit_gas_restored.context("missing restored live deposit")?,
            });
            report["balance_transitions_sha256"] = json!(hex::encode(Sha256::digest(
                serde_json::to_vec(&transitions)?
            )));
            report["balance_transitions"] = transitions;
            report["live_deposit_gas_sha256"] = json!(hex::encode(Sha256::digest(
                serde_json::to_vec(&live_deposit_gas)?
            )));
            report["live_deposit_gas"] = live_deposit_gas;
            report["state_before_sha256"] = json!(state_before_sha256);
            report["teardown_events"] = json!(teardown_events);
            report["teardown_probe_on"] = json!(self.resource_probe == Some(true));
            report["live_store_peak"] = json!(self.budget.peak());
            report["error_class"] = json!((outcome != "ok").then_some("deterministic"));
            report["typed_trap"] = json!(typed_trap);
        }
        self.last_report = Some(report.clone());
        if self.resource_probe.is_none() {
            println!("KONTOR_STACK_REPORT:{report}");
        }
        println!(
            "KONTOR_STACK_TIMING:{}",
            json!({
                "role": role,
                "kind": self.kind,
                "sample_index": sample_index,
                "setup_ms": self.setup_ms,
                "funding_ms": self.funding_ms,
                "publication_ms": self.publication_ms,
                "execution_ms": execution_ms,
                "postcall_ms": postcall_start.elapsed().as_millis(),
                "total_sample_ms": total_start.elapsed().as_millis(),
            })
        );
        self.samples.push(Sample {
            depth,
            outcome: outcome.to_string(),
            id: sample_id,
        });
        Ok(outcome.to_string())
    }
}

fn expression(kind: &str, depth: u32, address: &ContractAddress) -> Result<String> {
    Ok(match kind {
        "paid_recurse" | "system_recurse" | "view_recurse" | "core_recurse" => {
            let function = match kind {
                "paid_recurse" => "recurse",
                "core_recurse" => "core-recurse",
                _ => "view-recurse",
            };
            format!("{function}({depth})")
        }
        "paid_leaf_host" => format!("leaf-host-recurse({depth})"),
        "paid_wide" | "system_wide" | "view_wide" | "core_wide" => {
            let function = match kind {
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
        "view_crypto" => format!("sha256({})", to_wave_expr(b"native-stack-pending".to_vec())),
        "view_canonical_echo" => {
            format!("view-echo({})", to_wave_expr("x".repeat(16_384)))
        }
        "view_canonical_realloc_trap" | "view_canonical_realloc_import" => {
            format!("view-run({})", to_wave_expr("x".repeat(16_384)))
        }
        "paid_canonical_post_light" => "paid-light()".to_owned(),
        "paid_canonical_post_heavy" => "paid-heavy()".to_owned(),
        _ => bail!("unknown probe kind {kind}"),
    })
}

pub(super) async fn resource_smoke(reduced: bool) -> Result<()> {
    let mut fixture = Fixture::new("paid_huge".to_string(), reduced).await?;
    ensure!(
        fixture.observe(0, "resource_smoke").await? == "ok",
        "large-frame paid contract call failed on the Tokio worker"
    );
    Ok(())
}

pub(super) async fn run_resource_finite_paid(
    case_id: &str,
    configuration: &str,
    process_role: &str,
) -> Result<JsonValue> {
    let repeats = match case_id {
        "large_frame_paid" => 3,
        "max_gas_paid" => 2,
        _ => bail!("unknown finite paid stack case"),
    };
    ensure!(
        matches!(configuration, "reduced" | "production"),
        "unknown finite paid stack configuration"
    );
    ensure!(
        matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown finite paid stack role"
    );
    let mut fixture = Fixture::new("paid_huge".to_string(), configuration == "reduced").await?;
    fixture.resource_probe = Some(process_role == "target_observed");
    let mut observations = Vec::with_capacity(repeats);
    for repeat_index in 0..repeats {
        resource_diagnostics::record("finite_stack_attempt_start");
        ensure!(
            fixture.observe(0, process_role).await? == "ok",
            "finite paid stack sample failed"
        );
        resource_diagnostics::record("finite_stack_attempt_end");
        let observation = fixture
            .last_report
            .take()
            .context("finite paid stack sample lacks semantic evidence")?;
        ensure!(
            observation["gas_limit"] == MAX_UNTRUSTED_GAS_LIMIT,
            "finite paid stack sample did not use the maximum paid gas limit"
        );
        println!(
            "FINITE_STACK_ATTEMPT:{}",
            json!({
                "case_id": case_id,
                "configuration": configuration,
                "process_role": process_role,
                "sample_key": "target",
                "repeat_index": repeat_index,
                "pid": process::id(),
                "observation": observation,
            })
        );
        observations.push(observation);
    }
    let summary = json!({
        "case_id": case_id,
        "configuration": configuration,
        "process_role": process_role,
        "sample_count": observations.len(),
        "outcomes": observations.iter().map(|value| value["outcome"].clone()).collect::<Vec<_>>(),
        "complete": true,
    });
    println!("FINITE_STACK_SUMMARY:{summary}");
    Ok(summary)
}

pub(super) async fn run_resource_canonical(
    case_id: &str,
    configuration: &str,
    process_role: &str,
) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production"),
        "unknown canonical stack configuration"
    );
    ensure!(
        matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown canonical stack role"
    );
    let samples: &[(&str, &str, &str, Option<&str>)] = match case_id {
        "canonical_lift_lower" => &[
            ("success", "view_canonical_echo", "ok", None),
            (
                "failure",
                "view_canonical_realloc_import",
                "other_trap",
                Some("CannotLeaveComponent"),
            ),
        ],
        "canonical_realloc" => &[
            ("success_lowering", "view_canonical_echo", "ok", None),
            (
                "realloc_trap",
                "view_canonical_realloc_trap",
                "other_trap",
                Some("UnreachableCodeReached"),
            ),
            (
                "forbidden_import",
                "view_canonical_realloc_import",
                "other_trap",
                Some("CannotLeaveComponent"),
            ),
        ],
        "canonical_post_return" => &[
            (
                "light",
                "paid_canonical_post_light",
                "other_trap",
                Some("CannotLeaveComponent"),
            ),
            (
                "heavy",
                "paid_canonical_post_heavy",
                "other_trap",
                Some("CannotLeaveComponent"),
            ),
        ],
        _ => bail!("unknown canonical stack case {case_id}"),
    };
    let mut observations = Vec::with_capacity(samples.len() * 2);
    for (sample_key, kind, expected_outcome, expected_trap) in samples {
        let mut fixture = Fixture::new((*kind).to_owned(), configuration == "reduced").await?;
        fixture.resource_probe = Some(process_role == "target_observed");
        for repeat_index in 0..2 {
            resource_diagnostics::record("finite_stack_attempt_start");
            let outcome = fixture.observe(0, process_role).await?;
            resource_diagnostics::record("finite_stack_attempt_end");
            let observation = fixture
                .last_report
                .take()
                .context("canonical sample lacks semantic observation")?;
            ensure!(
                outcome == *expected_outcome
                    && observation["typed_trap"].as_str() == *expected_trap,
                "canonical {sample_key} returned {outcome}: {observation}"
            );
            if *expected_outcome == "ok" {
                ensure!(
                    observation["value"] == to_wave_expr("x".repeat(16_384)),
                    "canonical string lowering or lifting changed"
                );
            }
            println!(
                "CANONICAL_STACK_ATTEMPT:{}",
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
            observations.push(((*sample_key).to_owned(), observation));
        }
    }
    if case_id == "canonical_post_return" {
        let light = observations[0].1["fuel"]["user"]
            .as_u64()
            .context("canonical light user fuel is missing")?;
        let heavy = observations[2].1["fuel"]["user"]
            .as_u64()
            .context("canonical heavy user fuel is missing")?;
        ensure!(
            heavy >= light + 16_384,
            "canonical post-return loop was not charged"
        );
    }
    let summary = json!({
        "case_id": case_id,
        "configuration": configuration,
        "process_role": process_role,
        "sample_count": observations.len(),
        "sample_keys": samples.iter().map(|(key, ..)| *key).collect::<Vec<_>>(),
        "outcomes": observations.iter().map(|(_, value)| value["outcome"].clone()).collect::<Vec<_>>(),
        "complete": true,
    });
    println!("CANONICAL_STACK_SUMMARY:{summary}");
    Ok(summary)
}

pub(super) async fn run_resource_pending_host_io(
    configuration: &str,
    process_role: &str,
) -> Result<JsonValue> {
    ensure!(
        matches!(configuration, "reduced" | "production"),
        "unknown pending host I/O configuration"
    );
    ensure!(
        matches!(process_role, "target_observed" | "probe_off_control"),
        "unknown pending host I/O role"
    );
    let mut current = Fixture::new("view_crypto".to_owned(), configuration == "reduced").await?;
    current.resource_probe = Some(process_role == "target_observed");
    let gate = LeafGate {
        entered: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let pending_polls = Arc::new(AtomicUsize::new(0));
    let production_linkers = current.runtime.linkers.clone();
    let mut user = current.runtime.linkers.user.clone();
    user.allow_shadowing(true)
        .instance("kontor:built-in/crypto")?
        .func_wrap_async("sha256", {
            let entered = gate.entered.clone();
            let release = gate.release.clone();
            let calls = calls.clone();
            let pending_polls = pending_polls.clone();
            move |mut store, (input,): (Vec<u8>,)| {
                let entered = entered.clone();
                let release = release.clone();
                let calls = calls.clone();
                let pending_polls = pending_polls.clone();
                Box::new(async move {
                    if input != b"native-stack-pending" {
                        return Err(WasmtimeError::msg("unexpected pending host input"));
                    }
                    calls.fetch_add(1, Ordering::SeqCst);
                    let wait = release.notified();
                    tokio::pin!(wait);
                    let mut signaled = false;
                    poll_fn(|cx| match wait.as_mut().poll(cx) {
                        Poll::Pending => {
                            // Signal only after the host future really returns Pending.
                            if !signaled {
                                pending_polls.fetch_add(1, Ordering::SeqCst);
                                entered.notify_one();
                                signaled = true;
                            }
                            Poll::Pending
                        }
                        Poll::Ready(()) => Poll::Ready(()),
                    })
                    .await;
                    let mut access =
                        Access::<Runtime, Runtime>::new(store.as_context_mut(), |runtime| runtime);
                    let runtime = access.get().clone();
                    let digest = runtime
                        ._sha256(&mut access, input)
                        .await
                        .map_err(WasmtimeError::from_anyhow)?;
                    Ok((digest,))
                })
            }
        })?;
    current.runtime.linkers = Arc::new(Linkers {
        user,
        native: current.runtime.linkers.native.clone(),
    });
    let suspended_linkers = current.runtime.linkers.clone();
    let mut fixture = Some(current);
    for repeat_index in 0..2 {
        resource_diagnostics::record("finite_stack_attempt_start");
        let mut current = fixture
            .take()
            .context("pending host fixture was consumed")?;
        let role = process_role.to_owned();
        let mut task = tokio::spawn(async move {
            let outcome = current.observe(0, &role).await?;
            Ok::<_, anyhow::Error>((current, outcome))
        });
        tokio::select! {
            () = gate.entered.notified() => {},
            result = &mut task => {
                let _ = result??;
                bail!("pending host call completed before suspension");
            },
            () = tokio::time::sleep(Duration::from_secs(30)) => bail!("pending host import did not enter"),
        }
        ensure!(
            !task.is_finished()
                && calls.load(Ordering::SeqCst) == repeat_index + 1
                && pending_polls.load(Ordering::SeqCst) == repeat_index + 1,
            "guest was not suspended at exactly one production host import"
        );
        ensure!(
            tokio::spawn(async { 42 }).await? == 42,
            "Tokio executor did not progress while guest was suspended"
        );
        println!(
            "PENDING_HOST_IO_ATTEMPT:{}",
            json!({
                "case_id": "pending_host_io",
                "configuration": configuration,
                "process_role": process_role,
                "sample_key": "suspended",
                "repeat_index": repeat_index,
                "pid": process::id(),
                "host_import": "kontor:built-in/crypto.sha256",
                "host_entered": true,
                "host_poll_pending_count": pending_polls.load(Ordering::SeqCst),
                "guest_task_pending": true,
                "other_task_progressed": true,
                "observation": JsonValue::Null,
            })
        );
        gate.release.notify_one();
        let (mut current, outcome) = timeout(Duration::from_secs(30), task).await???;
        ensure!(outcome == "ok", "pending host call failed: {outcome}");
        let observation = current
            .last_report
            .take()
            .context("resumed host call lacks semantic observation")?;
        let value = observation["value"]
            .as_str()
            .context("missing crypto view value")?;
        ensure!(
            from_wave_expr::<Vec<u8>>(value) == Sha256::digest(b"native-stack-pending").to_vec(),
            "resumed host result differs from production SHA-256"
        );
        println!(
            "PENDING_HOST_IO_ATTEMPT:{}",
            json!({
                "case_id": "pending_host_io",
                "configuration": configuration,
                "process_role": process_role,
                "sample_key": "resumed",
                "repeat_index": repeat_index,
                "pid": process::id(),
                "host_import": "kontor:built-in/crypto.sha256",
                "host_entered": true,
                "host_poll_pending_count": pending_polls.load(Ordering::SeqCst),
                "guest_task_pending": false,
                "other_task_progressed": true,
                "observation": observation.clone(),
            })
        );
        resource_diagnostics::record("finite_stack_attempt_end");
        current.runtime.linkers = production_linkers.clone();
        resource_diagnostics::record("finite_stack_attempt_start");
        ensure!(
            current.observe(0, process_role).await? == "ok",
            "unshadowed production host control failed"
        );
        resource_diagnostics::record("finite_stack_attempt_end");
        let control = current
            .last_report
            .take()
            .context("unshadowed host control lacks semantic observation")?;
        ensure!(
            control["value"] == observation["value"]
                && control["fuel"] == observation["fuel"]
                && control["receipt"] == observation["receipt"]
                && control["balance_transitions"] == observation["balance_transitions"]
                && control["state_before_sha256"] == observation["state_before_sha256"]
                && control["reset"]["post"]["persistent_digest_sha256"]
                    == observation["reset"]["post"]["persistent_digest_sha256"],
            "unshadowed production host semantics differ from suspended host call"
        );
        println!(
            "PENDING_HOST_IO_CONTROL:{}",
            json!({
                "case_id": "pending_host_io",
                "configuration": configuration,
                "process_role": process_role,
                "sample_key": "unshadowed_control",
                "repeat_index": repeat_index,
                "pid": process::id(),
                "host_import": "kontor:built-in/crypto.sha256",
                "linker": "production",
                "observation": control,
            })
        );
        current.runtime.linkers = suspended_linkers.clone();
        fixture = Some(current);
    }
    let summary = json!({
        "case_id": "pending_host_io",
        "configuration": configuration,
        "process_role": process_role,
        "sample_count": 4,
        "control_count": 2,
        "host_calls": calls.load(Ordering::SeqCst),
        "host_poll_pending_count": pending_polls.load(Ordering::SeqCst),
        "complete": true,
    });
    println!("PENDING_HOST_IO_SUMMARY:{summary}");
    Ok(summary)
}

pub(crate) async fn persistent_digest(conn: &Connection) -> Result<String> {
    let mut rows = conn
        .query(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
            (),
        )
        .await?;
    let mut tables = Vec::new();
    while let Some(row) = rows.next().await? {
        tables.push(row.get::<String>(0)?);
    }
    drop(rows);
    let mut digest = Sha256::new();
    digest.update(b"kontor-persistent-rows-v2\0");
    for table in tables {
        let quoted = table.replace('"', "\"\"");
        let mut rows = conn
            .query(&format!("SELECT * FROM \"{quoted}\""), ())
            .await?;
        let mut row_hashes: Vec<[u8; 32]> = Vec::new();
        while let Some(row) = rows.next().await? {
            let mut row_digest = Sha256::new();
            row_digest.update(row.column_count().to_le_bytes());
            for column in 0..row.column_count() {
                let value = row.get_value(column)?;
                if table == "receipt_stream_state" && row.column_name(column) == Some("epoch") {
                    let SqlValue::Text(epoch) = &value else {
                        bail!("receipt stream epoch is not text");
                    };
                    ensure!(
                        epoch.len() == 64 && epoch.bytes().all(|byte| byte.is_ascii_hexdigit()),
                        "receipt stream epoch is malformed"
                    );
                    // The epoch identifies this local database, not replicated protocol state.
                    hash_sql_value(&mut row_digest, &SqlValue::Text("<local-epoch>".into()));
                } else {
                    hash_sql_value(&mut row_digest, &value);
                }
            }
            row_hashes.push(row_digest.finalize().into());
        }
        // SQLite may visit rows in different plans; the row multiset is the state.
        row_hashes.sort_unstable();
        digest.update((table.len() as u64).to_le_bytes());
        digest.update(table.as_bytes());
        digest.update((row_hashes.len() as u64).to_le_bytes());
        for hash in row_hashes {
            digest.update(hash);
        }
    }
    digest.update(b"\0logical-sqlite-schema-v1\0");
    // SQLite generates these bookkeeping definitions; their table rows remain hashed above.
    let mut rows = conn
        .query(
            "SELECT type, name, tbl_name, sql FROM sqlite_master \
             WHERE name != 'sqlite_sequence' AND name NOT GLOB 'sqlite_stat*' \
             ORDER BY type, name",
            (),
        )
        .await?;
    let mut schema = Vec::new();
    while let Some(row) = rows.next().await? {
        let sql = row.get_value(3)?;
        ensure!(
            matches!(&sql, SqlValue::Null | SqlValue::Text(_)),
            "logical schema SQL has an unexpected type"
        );
        schema.push((
            row.get::<String>(0)?,
            row.get::<String>(1)?,
            row.get::<String>(2)?,
            sql,
        ));
    }
    digest.update((schema.len() as u64).to_le_bytes());
    for (kind, name, table, sql) in schema {
        for value in [
            SqlValue::Text(kind),
            SqlValue::Text(name),
            SqlValue::Text(table),
            sql,
        ] {
            hash_sql_value(&mut digest, &value);
        }
    }
    Ok(hex::encode(digest.finalize()))
}

pub(crate) async fn assert_receipt_stream_initial_state(conn: &Connection) -> Result<()> {
    let mut rows = conn
        .query(
            "SELECT singleton, generation, unsupported FROM receipt_stream_state",
            (),
        )
        .await?;
    let state = rows
        .next()
        .await?
        .context("missing receipt stream singleton")?;
    ensure!(
        state.get::<i64>(0)? == 1 && state.get::<i64>(1)? == 0 && state.get::<i64>(2)? == 0,
        "receipt stream fixture is not at generation zero with supported IDs"
    );
    ensure!(
        rows.next().await?.is_none(),
        "duplicate receipt stream singleton"
    );
    drop(rows);
    let mut rollback_rows = conn
        .query("SELECT 1 FROM receipt_stream_rollbacks", ())
        .await?;
    ensure!(
        rollback_rows.next().await?.is_none(),
        "receipt stream fixture has rollback history"
    );
    Ok(())
}

fn hash_sql_value(digest: &mut Sha256, value: &SqlValue) {
    match value {
        SqlValue::Null => digest.update([0]),
        SqlValue::Integer(value) => {
            digest.update([1]);
            digest.update(value.to_le_bytes());
        }
        SqlValue::Real(value) => {
            digest.update([2]);
            digest.update(value.to_bits().to_le_bytes());
        }
        SqlValue::Text(value) => {
            digest.update([3]);
            digest.update((value.len() as u64).to_le_bytes());
            digest.update(value.as_bytes());
        }
        SqlValue::Blob(value) => {
            digest.update([4]);
            digest.update((value.len() as u64).to_le_bytes());
            digest.update(value);
        }
    }
}

async fn worker_boundary(
    fixture: &mut Fixture,
    max_depth: u32,
    initial_depth: u32,
) -> Result<JsonValue> {
    ensure!(
        max_depth > 0 && initial_depth > 0,
        "invalid adaptive depth bounds"
    );
    ensure!(
        fixture.observe(0, "worker").await? == "ok",
        "probe failed at depth zero"
    );
    let mut last_success = 0;
    let mut first_failure = None;
    let mut depth = initial_depth.min(max_depth);
    loop {
        let outcome = fixture.observe(depth, "worker").await?;
        if outcome != "ok" {
            first_failure = Some((depth, outcome));
            break;
        }
        last_success = depth;
        if depth == max_depth {
            break;
        }
        depth = depth.saturating_mul(2).min(max_depth);
    }
    let (mut first_failure, _) =
        first_failure.context("no failure found within the depth bound")?;
    while first_failure - last_success > 1 {
        let midpoint = last_success + (first_failure - last_success) / 2;
        if fixture.observe(midpoint, "worker").await? == "ok" {
            last_success = midpoint;
        } else {
            first_failure = midpoint;
        }
    }
    for repeated_depth in [
        last_success,
        first_failure,
        first_failure,
        last_success,
        last_success,
        first_failure,
    ] {
        let outcome = fixture.observe(repeated_depth, "worker").await?;
        ensure!(
            (repeated_depth == last_success && outcome == "ok")
                || (repeated_depth == first_failure && outcome != "ok"),
            "boundary changed at depth {repeated_depth}: {outcome}"
        );
    }
    let mut counts = HashMap::new();
    for sample in &fixture.samples {
        *counts.entry(sample.depth).or_insert(0_u32) += 1;
    }
    ensure!(
        counts[&last_success] >= 3 && counts[&first_failure] >= 3,
        "missing boundary repeats"
    );
    let first_failure_outcome = fixture
        .samples
        .iter()
        .rev()
        .find(|sample| sample.depth == first_failure)
        .unwrap()
        .outcome
        .clone();
    ensure!(
        fixture
            .samples
            .iter()
            .filter(|sample| sample.depth == first_failure)
            .all(|sample| sample.outcome == first_failure_outcome),
        "boundary outcome changed across repeats"
    );
    Ok(json!({
        "last_success": last_success,
        "first_failure": first_failure,
        "first_failure_outcome": first_failure_outcome,
    }))
}

struct LeafGate {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

async fn resource_attempt(
    fixture: &mut Option<Fixture>,
    depth: u32,
    case_id: &str,
    process_role: &str,
    configuration: &str,
    sample_key: &str,
    repeat_index: usize,
    leaf_gate: Option<&LeafGate>,
) -> Result<String> {
    resource_diagnostics::record("boundary_attempt_start");
    let mut current = fixture.take().context("resource fixture was consumed")?;
    let (returned, outcome, host_io_suspended, host_import_phase) = if let Some(gate) = leaf_gate {
        let task_role = process_role.to_owned();
        let mut task = tokio::spawn(async move {
            let outcome = current.observe(depth, &task_role).await?;
            Ok::<_, anyhow::Error>((current, outcome))
        });
        let entered = gate.entered.notified();
        tokio::pin!(entered);
        let completed = tokio::select! {
            result = &mut task => Some(result),
            () = &mut entered => None,
            () = tokio::time::sleep(Duration::from_secs(30)) => {
                bail!("leaf host import neither entered nor trapped within 30 seconds");
            }
        };
        if let Some(result) = completed {
            let (current, outcome) = result??;
            ensure!(
                outcome == "stack_overflow",
                "leaf completed without entering its host import: {outcome}"
            );
            (current, outcome, false, "before_import")
        } else {
            ensure!(
                !task.is_finished(),
                "leaf host import did not suspend the guest"
            );
            ensure!(
                tokio::spawn(async { 42 }).await? == 42,
                "Tokio worker did not progress while the host import was pending"
            );
            gate.release.notify_one();
            let (current, outcome) = timeout(Duration::from_secs(30), task).await???;
            if outcome != "ok" && outcome != "stack_overflow" {
                println!(
                    "BOUNDARY_LEAF_FAILURE_DIAGNOSTIC:{}",
                    json!({
                        "case_id": case_id,
                        "depth": depth,
                        "process_role": process_role,
                        "configuration": configuration,
                        "phase": "after_host_release",
                        "host_import_entered": true,
                        "host_import_released": true,
                        "second_tokio_task_progressed": true,
                        "guest_task_completed": true,
                        "outcome": outcome.as_str(),
                        "observation": current.last_report.as_ref(),
                    })
                );
            }
            ensure!(
                outcome == "ok"
                    || (outcome == "stack_overflow"
                        && (process_role == "discovery_production_observed"
                            || sample_key == "first_failure")),
                "leaf trapped after its host import entered: {outcome}"
            );
            (current, outcome, true, "after_host_release")
        }
    } else {
        let outcome = current.observe(depth, process_role).await?;
        (current, outcome, false, "not_applicable")
    };
    let mut observation = returned
        .last_report
        .clone()
        .context("resource observation was not emitted")?;
    observation["host_io_suspended"] = json!(host_io_suspended);
    observation["leaf_callback_seen"] = json!(host_io_suspended);
    observation["host_import_phase"] = json!(host_import_phase);
    let probe_on = returned.resource_probe == Some(true);
    *fixture = Some(returned);
    resource_diagnostics::record("boundary_attempt_end");
    println!(
        "BOUNDARY_PROBE_ATTEMPT:{}",
        json!({
            "case_id": case_id,
            "process_role": process_role,
            "configuration": configuration,
            "probe_on": probe_on,
            "pid": process::id(),
            "sample_key": sample_key,
            "repeat_index": repeat_index,
            "depth": depth,
            "complete": true,
            "observation": observation,
        })
    );
    Ok(outcome)
}

pub(super) async fn run_resource_boundary(
    case_id: &str,
    configuration: &str,
    process_role: &str,
    frozen_depths: Option<(u32, u32)>,
) -> Result<JsonValue> {
    let (shape, mode) = if case_id == "deepest_frame_host_call" {
        ("leaf", "paid")
    } else {
        let remainder = case_id
            .strip_prefix("pulley_")
            .context("unknown resource boundary case")?;
        let (shape, mode) = remainder
            .split_once('_')
            .context("malformed resource boundary case")?;
        ensure!(
            matches!(shape, "plain" | "wide")
                && matches!(mode, "paid" | "view" | "system" | "core"),
            "unsupported boundary shape or call mode"
        );
        (shape, mode)
    };
    ensure!(
        matches!(configuration, "reduced" | "production"),
        "invalid resource configuration"
    );
    ensure!(
        matches!(
            process_role,
            "discovery_production_observed" | "target_observed" | "probe_off_control"
        ),
        "invalid boundary process role"
    );
    let discovery = process_role == "discovery_production_observed";
    ensure!(
        !discovery || configuration == "production",
        "discovery requires a production Pulley boundary"
    );
    ensure!(
        discovery == frozen_depths.is_none(),
        "frozen depths must be present only for replay"
    );
    let probe_on = process_role != "probe_off_control";
    let kind = match (shape, mode) {
        ("plain", "paid") => "paid_recurse",
        ("plain", "view") => "view_recurse",
        ("plain", "system") => "system_recurse",
        ("plain", "core") => "core_recurse",
        ("wide", "paid") => "paid_wide",
        ("wide", "view") => "view_wide",
        ("wide", "system") => "system_wide",
        ("wide", "core") => "core_wide",
        ("leaf", "paid") => "paid_leaf_host",
        _ => bail!("unknown Pulley boundary case"),
    };
    let mut current = Fixture::new(kind.to_string(), configuration == "reduced").await?;
    current.resource_probe = Some(probe_on);
    let leaf_gate = if shape == "leaf" {
        let gate = LeafGate {
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        let mut user = current.runtime.linkers.user.clone();
        user.allow_shadowing(true)
            .instance("kontor:built-in/testing")?
            .func_wrap_async("host-error", {
                let entered = gate.entered.clone();
                let release = gate.release.clone();
                move |_, (): ()| {
                    let entered = entered.clone();
                    let release = release.clone();
                    Box::new(async move {
                        entered.notify_one();
                        release.notified().await;
                        Ok((String::new(),))
                    })
                }
            })?;
        current.runtime.linkers = Arc::new(Linkers {
            user,
            native: current.runtime.linkers.native.clone(),
        });
        Some(gate)
    } else {
        None
    };
    let mut fixture = Some(current);
    let mut attempts = 0_usize;
    let depths = if discovery {
        let outcome = resource_attempt(
            &mut fixture,
            0,
            case_id,
            process_role,
            configuration,
            "calibration",
            attempts,
            leaf_gate.as_ref(),
        )
        .await?;
        ensure!(outcome == "ok", "Pulley depth zero failed");
        attempts += 1;
        let mut last_success = 0;
        let mut depth = 1024_u32;
        let mut first_failure = loop {
            let outcome = resource_attempt(
                &mut fixture,
                depth,
                case_id,
                process_role,
                configuration,
                "calibration",
                attempts,
                leaf_gate.as_ref(),
            )
            .await?;
            attempts += 1;
            if outcome != "ok" {
                ensure!(
                    outcome == "stack_overflow",
                    "wrong boundary trap: {outcome}"
                );
                break depth;
            }
            last_success = depth;
            ensure!(depth < 32768, "no Pulley stack overflow by depth 32768");
            depth = depth.saturating_mul(2).min(32768);
        };
        while first_failure - last_success > 1 {
            let midpoint = last_success + (first_failure - last_success) / 2;
            let outcome = resource_attempt(
                &mut fixture,
                midpoint,
                case_id,
                process_role,
                configuration,
                "calibration",
                attempts,
                leaf_gate.as_ref(),
            )
            .await?;
            attempts += 1;
            if outcome == "ok" {
                last_success = midpoint;
            } else {
                ensure!(
                    outcome == "stack_overflow",
                    "wrong boundary trap: {outcome}"
                );
                first_failure = midpoint;
            }
        }
        (last_success, first_failure)
    } else {
        let (last_success, first_failure) = frozen_depths.context("missing frozen depths")?;
        ensure!(
            last_success > 0 && first_failure == last_success + 1,
            "frozen Pulley depths are not adjacent"
        );
        if shape == "leaf" {
            let order = [
                ("last_success", last_success, 0, "ok"),
                ("first_failure", first_failure, 0, "stack_overflow"),
                ("last_success", last_success, 1, "ok"),
                ("first_failure", first_failure, 1, "stack_overflow"),
            ];
            for (sample_key, depth, repeat_index, expected) in order {
                let outcome = resource_attempt(
                    &mut fixture,
                    depth,
                    case_id,
                    process_role,
                    configuration,
                    sample_key,
                    repeat_index,
                    leaf_gate.as_ref(),
                )
                .await?;
                ensure!(
                    outcome == expected,
                    "deepest leaf boundary changed: {outcome}"
                );
                attempts += 1;
            }
        } else {
            let order = [
                ("last_success", last_success, 0),
                ("first_failure", first_failure, 0),
                ("first_failure", first_failure, 1),
                ("last_success", last_success, 1),
                ("last_success", last_success, 2),
                ("first_failure", first_failure, 2),
            ];
            for (sample_key, depth, repeat_index) in order {
                let outcome = resource_attempt(
                    &mut fixture,
                    depth,
                    case_id,
                    process_role,
                    configuration,
                    sample_key,
                    repeat_index,
                    None,
                )
                .await?;
                ensure!(
                    (sample_key == "last_success" && outcome == "ok")
                        || (sample_key == "first_failure" && outcome == "stack_overflow"),
                    "frozen Pulley boundary changed at depth {depth}: {outcome}"
                );
                attempts += 1;
            }
        }
        (last_success, first_failure)
    };
    let current = fixture.context("resource fixture was not returned")?;
    Ok(json!({
        "case_id": case_id,
        "process_role": process_role,
        "configuration": configuration,
        "probe_on": probe_on,
        "pid": process::id(),
        "discovery": discovery,
        "last_success": depths.0,
        "first_failure": depths.1,
        "attempt_count": attempts,
        "component_sha256": hex::encode(Sha256::digest(COMPONENT)),
        "engine_target": current.runtime.engine.get_target(),
        "max_wasm_stack": current.runtime.engine.get_max_wasm_stack(),
        "async_stack_size": current.runtime.engine.get_async_stack_size(),
        "cache_mode": "warm_compiled_cache",
        "complete": true,
    }))
}

pub(super) async fn run(role: &str) -> Result<()> {
    ensure!(
        matches!(role, "worker" | "control"),
        "unknown sweep role {role}"
    );
    let kind = env::var("KONTOR_STACK_KIND").context("KONTOR_STACK_KIND is required")?;
    let mut fixture = Fixture::new(kind.clone(), false).await?;
    let boundaries = if role == "worker" {
        if kind == "paid_huge" {
            ensure!(
                fixture.observe(0, role).await? == "ok",
                "large frame failed"
            );
            json!({"bounded_depth": 0})
        } else if kind == "paid_reenter" {
            for depth in [62, 63, 64, 64, 63, 62, 62, 63, 64] {
                let outcome = fixture.observe(depth, role).await?;
                ensure!(
                    (depth < 64 && outcome == "ok")
                        || (depth == 64 && outcome == "invocation_limit"),
                    "unexpected reentry result at depth {depth}: {outcome}"
                );
            }
            json!({"last_success": 63, "first_failure": 64, "first_failure_outcome": "invocation_limit"})
        } else {
            let max_depth = env::var("KONTOR_STACK_MAX_DEPTH")
                .context("KONTOR_STACK_MAX_DEPTH is required")?
                .parse::<u32>()?;
            let initial_depth = env::var("KONTOR_STACK_INITIAL_DEPTH")
                .context("KONTOR_STACK_INITIAL_DEPTH is required")?
                .parse::<u32>()?;
            worker_boundary(&mut fixture, max_depth, initial_depth).await?
        }
    } else {
        let raw = env::var("KONTOR_STACK_CONTROL_DEPTHS")
            .context("KONTOR_STACK_CONTROL_DEPTHS is required")?;
        let depths = raw
            .split(',')
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if kind == "paid_huge" {
            ensure!(depths == [0], "large-frame control must use depth zero");
            ensure!(
                fixture.observe(0, role).await? == "ok",
                "large-frame control failed"
            );
            json!({"bounded_depth": 0})
        } else {
            ensure!(
                depths.len() == 2 && depths[1] == depths[0] + 1,
                "control depths must be adjacent"
            );
            if kind == "paid_reenter" {
                ensure!(depths == [63, 64], "reentry control depths must be 63,64");
            }
            let success = fixture.observe(depths[0], role).await?;
            let failure = fixture.observe(depths[1], role).await?;
            ensure!(
                success == "ok" && failure != "ok",
                "control boundary did not reproduce"
            );
            json!({"last_success": depths[0], "first_failure": depths[1], "first_failure_outcome": failure})
        }
    };
    let summary = json!({
        "role": role,
        "kind": kind,
        "cache_mode": "warm_compiled_cache",
        "fixture_contracts": fixture.fixture_contracts,
        "boundaries": boundaries,
        "ordered_sample_indices": (0..fixture.samples.len()).collect::<Vec<_>>(),
        "ordered_sample_ids": fixture.samples.iter().map(|sample| sample.id.clone()).collect::<Vec<_>>(),
        "baseline_digest_sha256": fixture.baseline_digest,
    });
    println!("KONTOR_STACK_SWEEP_SUMMARY:{summary}");
    Ok(())
}

#[cfg(test)]
mod persistent_digest_tests {
    use anyhow::Result;
    use libsql::Builder;
    use tempfile::TempDir;

    use super::{assert_receipt_stream_initial_state, persistent_digest};

    #[tokio::test]
    async fn digest_projects_only_local_epoch_and_captures_logical_schema() -> Result<()> {
        let dir = TempDir::new()?;
        let db = Builder::new_local(dir.path().join("digest.db"))
            .build()
            .await?;
        let conn = db.connect()?;
        conn.execute_batch(
            "CREATE TABLE receipt_stream_state \
               (singleton INTEGER PRIMARY KEY, epoch TEXT NOT NULL, \
                generation INTEGER NOT NULL, unsupported INTEGER NOT NULL); \
             CREATE TABLE receipt_stream_rollbacks \
               (generation INTEGER PRIMARY KEY, surviving_height INTEGER NOT NULL); \
             CREATE TABLE contract_results \
               (id INTEGER PRIMARY KEY, confirmed_bitcoin_tx_index INTEGER NOT NULL); \
             CREATE TABLE unique_control (code TEXT UNIQUE); \
             CREATE TABLE auto_counter (id INTEGER PRIMARY KEY AUTOINCREMENT); \
             INSERT INTO receipt_stream_state VALUES \
               (1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0, 0); \
             INSERT INTO contract_results VALUES (1, 0); \
             INSERT INTO auto_counter VALUES (1);",
        )
        .await?;
        assert_receipt_stream_initial_state(&conn).await?;
        let baseline = persistent_digest(&conn).await?;

        conn.execute(
            "UPDATE receipt_stream_state SET epoch = \
             'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
            (),
        )
        .await?;
        assert_eq!(persistent_digest(&conn).await?, baseline);

        conn.execute("UPDATE receipt_stream_state SET generation = 1", ())
            .await?;
        assert!(assert_receipt_stream_initial_state(&conn).await.is_err());
        conn.execute("UPDATE receipt_stream_state SET generation = 0", ())
            .await?;
        conn.execute("INSERT INTO receipt_stream_rollbacks VALUES (1, 0)", ())
            .await?;
        assert!(assert_receipt_stream_initial_state(&conn).await.is_err());
        conn.execute("DELETE FROM receipt_stream_rollbacks", ())
            .await?;
        conn.execute("UPDATE receipt_stream_state SET unsupported = 1", ())
            .await?;
        assert!(assert_receipt_stream_initial_state(&conn).await.is_err());
        conn.execute("UPDATE receipt_stream_state SET unsupported = 0", ())
            .await?;
        assert_receipt_stream_initial_state(&conn).await?;
        conn.execute(
            "INSERT INTO receipt_stream_state VALUES \
             (2, 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 0, 0)",
            (),
        )
        .await?;
        assert!(assert_receipt_stream_initial_state(&conn).await.is_err());
        conn.execute("DELETE FROM receipt_stream_state WHERE singleton = 2", ())
            .await?;

        for (change, restore) in [
            (
                "UPDATE receipt_stream_state SET generation = 1",
                "UPDATE receipt_stream_state SET generation = 0",
            ),
            (
                "UPDATE receipt_stream_state SET unsupported = 1",
                "UPDATE receipt_stream_state SET unsupported = 0",
            ),
            (
                "INSERT INTO receipt_stream_rollbacks VALUES (1, 0)",
                "DELETE FROM receipt_stream_rollbacks",
            ),
            (
                "UPDATE contract_results SET confirmed_bitcoin_tx_index = 1",
                "UPDATE contract_results SET confirmed_bitcoin_tx_index = 0",
            ),
            (
                "UPDATE sqlite_sequence SET seq = 2 WHERE name = 'auto_counter'",
                "UPDATE sqlite_sequence SET seq = 1 WHERE name = 'auto_counter'",
            ),
            (
                "CREATE INDEX receipt_confirmation_idx ON contract_results(confirmed_bitcoin_tx_index)",
                "DROP INDEX receipt_confirmation_idx",
            ),
            (
                "CREATE TRIGGER receipt_confirmation_trigger AFTER INSERT ON contract_results \
              BEGIN SELECT 1; END",
                "DROP TRIGGER receipt_confirmation_trigger",
            ),
        ] {
            conn.execute_batch(change).await?;
            assert_ne!(persistent_digest(&conn).await?, baseline, "{change}");
            conn.execute_batch(restore).await?;
            assert_eq!(persistent_digest(&conn).await?, baseline, "{restore}");
        }
        conn.execute("UPDATE receipt_stream_state SET epoch = 'bad'", ())
            .await?;
        assert!(persistent_digest(&conn).await.is_err());
        Ok(())
    }
}
