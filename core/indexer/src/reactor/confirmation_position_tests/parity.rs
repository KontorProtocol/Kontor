use crate::protocol::coordinator::selection::ApplicationPosition;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::slice;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use bitcoin::Transaction;
use bitcoin::consensus::{deserialize, serialize};
use libsql::{Connection, Value, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::time::timeout;

use super::{StopEngine, fixture, raw_confirmation_block, reactor};
use crate::block::filter_map;
use crate::built_info::GIT_COMMIT_HASH;
use crate::consensus::Height;
use crate::database::connection::new_connection;
use crate::reactor::executor::Executor;
use crate::runtime::{ComponentCache, Runtime, Storage};
use crate::test_utils::new_mock_block_hash;

#[derive(Debug, Deserialize, Serialize)]
struct Inputs {
    source: String,
    database_sha256: String,
    transaction_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Report {
    source: String,
    states: BTreeMap<String, Json>,
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn checksum(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn prepare(path: &Path, source: &str) -> Result<()> {
    fs::create_dir(path)?;
    let (runtime, _dir, _address, raw) = fixture().await?;
    // VACUUM captures a consistent database, including WAL content. Both runs
    // reopen this seed so neither republishes native contracts at its own commit.
    runtime
        .get_storage_conn()
        .execute(
            "VACUUM INTO ?",
            params![path.join("seed.db").to_str().context("UTF-8 seed path")?],
        )
        .await?;
    let bytes = serialize(&raw);
    write_new(&path.join("transaction.bin"), &bytes)?;
    let inputs = Inputs {
        source: source.into(),
        database_sha256: checksum(&fs::read(path.join("seed.db"))?),
        transaction_sha256: checksum(&bytes),
    };
    write_new(
        &path.join("inputs.json"),
        &serde_json::to_vec_pretty(&inputs)?,
    )
}

async fn state(conn: &Connection) -> Result<Json> {
    let mut names = conn
        .query(
            "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name",
            (),
        )
        .await?;
    let mut result = BTreeMap::new();
    while let Some(table) = names.next().await? {
        let name: String = table.get(0)?;
        let quoted = name.replace('"', "\"\"");
        let mut rows = conn
            .query(&format!("SELECT * FROM \"{quoted}\""), ())
            .await?;
        let count = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            let mut fields = Vec::new();
            for column in 0..count {
                fields.push(match row.get_value(column)? {
                    Value::Null => json!(["null"]),
                    Value::Integer(value) => json!(["integer", value]),
                    Value::Real(value) => json!(["real_bits", value.to_bits()]),
                    Value::Text(value) => json!(["text", value]),
                    Value::Blob(value) => json!(["blob", hex::encode(value)]),
                });
            }
            values.push(serde_json::to_string(&fields)?);
        }
        values.sort();
        result.insert(name, values);
    }
    Ok(serde_json::to_value(result)?)
}

async fn scenario(path: &Path, batched: bool, report: &mut Report) -> Result<()> {
    let label = if batched { "batched" } else { "unbatched" };
    let dir = TempDir::new()?;
    fs::copy(path.join("seed.db"), dir.path().join("replay.db"))?;
    let conn = new_connection(dir.path(), "replay.db").await?;
    let runtime = Runtime::new(
        ComponentCache::new(),
        Storage::builder().height(1).conn(conn.clone()).build(),
    )
    .await?;
    let raw: Transaction = deserialize(&fs::read(path.join("transaction.bin"))?)?;
    let mut reactor = reactor(runtime, &dir).await?;
    let cleanup = StopEngine(reactor.consensus.engine_handle.actor.clone());
    let result = async {
        let initial = state(&conn).await?;
        report
            .states
            .insert(format!("{label}/initial"), initial.clone());
        let recognized = filter_map((0, raw.clone())).context("recognized signed fixture")?;
        report.states.insert(
            format!("{label}/recognition"),
            serde_json::to_value(&recognized)?,
        );
        let mut unrelated = raw.clone();
        unrelated.input[0].witness.clear();
        ensure!(reactor.simulate_raw(serialize(&unrelated)).await?.is_err());
        ensure!(
            state(&conn).await? == initial,
            "unrecognized input changed persisted state"
        );
        let simulated = reactor
            .simulate_raw(serialize(&raw))
            .await?
            .map_err(anyhow::Error::msg)
            .context("recognized simulation")?;
        report.states.insert(
            format!("{label}/simulation"),
            serde_json::to_value(simulated)?,
        );
        ensure!(
            state(&conn).await? == initial,
            "simulation changed persisted state"
        );

        if batched {
            reactor
                .process_decided_batch(
                    1,
                    new_mock_block_hash(1),
                    Height::new(1),
                    &[],
                    slice::from_ref(&raw),
                    None,
                )
                .await?;
            report
                .states
                .insert(format!("{label}/executed"), state(&conn).await?);
        }
        let block = reactor.execution.executor
            .prepare_block(
                &reactor.execution.recognizer,
                &reactor.preparation_selection().await?,
                raw_confirmation_block(&raw, 2)?,
            )
            .await?;
        let (count, ops, errors) = reactor.execution.execute_block_unit(
                &reactor
                    .select_executor(ApplicationPosition::Block {
                        height: block.height,
                        hash: block.hash,
                        consensus_height: 0,
                    })
                    .await?,
                &block,
            )
            .await?;
        ensure!(count == usize::from(!batched) && ops == u64::from(!batched));
        ensure!(errors.iter().flatten().flatten().all(Option::is_none));
        report
            .states
            .insert(format!("{label}/confirmed"), state(&conn).await?);

        if batched {
            reactor.rollback(1).await?;
            report
                .states
                .insert(format!("{label}/rollback"), state(&conn).await?);
            let replacement = reactor.execution.executor
                .prepare_block(
                    &reactor.execution.recognizer,
                    &reactor.preparation_selection().await?,
                    raw_confirmation_block(&raw, 4)?,
                )
                .await?;
            let (count, ops, _) = reactor.execution.execute_block_unit(
                    &reactor
                        .select_executor(ApplicationPosition::Block {
                            height: replacement.height,
                            hash: replacement.hash,
                            consensus_height: 0,
                        })
                        .await?,
                    &replacement,
                )
                .await?;
            ensure!(
                (count, ops) == (0, 0),
                "reconfirmation executed or charged again"
            );
            report
                .states
                .insert(format!("{label}/reconfirmed"), state(&conn).await?);
        }
        Ok(())
    }
    .await;
    cleanup.0.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut reactor.consensus.engine_handle.handle,
    )
    .await??;
    result
}

// Run record on the pre-dispatch source, then compare on the candidate. Keeping
// the oracle on disk prevents a changed dispatcher from defining both answers.
#[tokio::test]
#[ignore = "explicit cross-revision executor comparison using a preserved seed"]
async fn retained_executor_matches_baseline() -> Result<()> {
    let path = env::var_os("KONTOR_EXECUTOR_PARITY_DIR").context("KONTOR_EXECUTOR_PARITY_DIR")?;
    let path = Path::new(&path);
    let source = GIT_COMMIT_HASH.context("comparison requires source commit metadata")?;
    let mode = env::var("KONTOR_EXECUTOR_PARITY_MODE")?;
    ensure!(path.is_absolute(), "use an absolute archive path");
    match mode.as_str() {
        "record" => prepare(path, source).await?,
        "compare" => {}
        _ => bail!("mode must be record or compare"),
    }
    let inputs: Inputs = serde_json::from_slice(&fs::read(path.join("inputs.json"))?)?;
    ensure!(checksum(&fs::read(path.join("seed.db"))?) == inputs.database_sha256);
    ensure!(checksum(&fs::read(path.join("transaction.bin"))?) == inputs.transaction_sha256);
    let mut report = Report {
        source: source.into(),
        states: BTreeMap::new(),
    };
    scenario(path, false, &mut report).await?;
    scenario(path, true, &mut report).await?;
    if mode == "record" {
        ensure!(inputs.source == source);
        write_new(
            &path.join("baseline.json"),
            &serde_json::to_vec_pretty(&report)?,
        )?;
    } else {
        let expected: Report = serde_json::from_slice(&fs::read(path.join("baseline.json"))?)?;
        ensure!(expected.source == inputs.source);
        let output = env::var_os("KONTOR_EXECUTOR_PARITY_OUTPUT")
            .context("KONTOR_EXECUTOR_PARITY_OUTPUT")?;
        write_new(Path::new(&output), &serde_json::to_vec_pretty(&report)?)?;
        ensure!(
            report.states.keys().eq(expected.states.keys()),
            "comparison stage set changed"
        );
        for (stage, value) in &report.states {
            ensure!(
                Some(value) == expected.states.get(stage),
                "execution differs at {stage}"
            );
        }
    }
    Ok(())
}
