use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use indexer_types::Payment;
use libsql::{Connection, Value as SqlValue, params};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use stdlib::to_wave_expr;
use tempfile::TempDir;
use wasmtime::Trap;

use super::super::balance;
use super::{COMPONENT, SYSTEM_FUEL_CEILING};
use crate::runtime::invocation::{InvocationBudget, InvocationLimitReached};
use crate::runtime::resource_diagnostics;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, MAX_UNTRUSTED_GAS_LIMIT, Runtime, TransactionContext,
    native_provenance,
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
    baseline_supply: Decimal,
    setup_ms: u128,
    funding_ms: u128,
    publication_ms: u128,
    samples: Vec<Sample>,
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
                    "stack-probe",
                    COMPONENT,
                    &native_provenance()?,
                )
                .await
                .context("fixture must pass real publish, component policy, and WIT validation")?;
        }
        resource_diagnostics::record("publication_exit");
        runtime.set_context(1, None, None, None).await;
        let publication_ms = publication_start.elapsed().as_millis();
        let address = ContractAddress {
            name: "stack-probe".into(),
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
        let baseline_supply = token::total_supply(&mut runtime).await?;
        ensure!(budget.live() == 0, "fixture left live invocation Stores");
        let conn = runtime.get_storage_conn();
        assert_receipt_stream_initial_state(&conn).await?;
        let baseline_digest = persistent_digest(&conn).await?;
        resource_diagnostics::record("fixture_preparation_exit");
        Ok(Self {
            runtime,
            _dir: dir,
            kind,
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
            baseline_supply,
            setup_ms,
            funding_ms,
            publication_ms,
            samples: Vec::new(),
        })
    }

    async fn observe(&mut self, depth: u32, role: &str) -> Result<String> {
        resource_diagnostics::record("sample_preparation_entry");
        let sample_index = self.samples.len();
        let sample_id = format!("{role}:{}:{sample_index:04}", self.kind);
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
        let expression = expression(&self.kind, depth, &self.address)?;
        let previous = self.runtime.start_usage();
        let execution_start = Instant::now();
        resource_diagnostics::record("sample_preparation_exit");
        resource_diagnostics::record("operation_entry");
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
        let (outcome, error_message, value) = match result {
            Ok(value) => ("ok", None, Some(value)),
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
                (outcome, Some(format!("{error:#}")), None)
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
        let last_depth = self
            .runtime
            .execute(None, None, &self.address, "last-depth()")
            .await?
            .parse::<u32>()?;
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
        self.runtime.storage.rollback().await?;
        self.runtime.set_context(1, None, None, None).await;
        ensure!(
            self.runtime.id_generation_counter.get().await == 0
                && self.runtime.result_id_counter.get().await == 0
                && self.runtime.gauge.is_none(),
            "execution accounting did not reset in {sample_id}"
        );
        let balances_restored = balance(&mut self.runtime, HolderRef::from(&self.signer)).await?
            == self.baseline_balance
            && balance(&mut self.runtime, HolderRef::Burner).await? == self.baseline_burner;
        let floor_restored = token::floor(&mut self.runtime, HolderRef::from(&self.signer)).await?
            == self.baseline_floor;
        let supply_restored = token::total_supply(&mut self.runtime).await? == self.baseline_supply;
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

        let report = json!({
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
            "component_sha256": hex::encode(Sha256::digest(COMPONENT)),
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
        println!("KONTOR_STACK_REPORT:{report}");
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
