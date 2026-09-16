use std::hint::black_box;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use indexer_types::serialize;
use libsql::{Connection, params};
use serde_json::{Value, json};
use stdlib::{KeyElement, subtree_end};
use wasmtime::Store;
use wasmtime::component::Resource;

use super::{BUDGET, KeysHost, RowsHost, StorageHost, host};
use crate::runtime::Runtime;
use crate::runtime::wit::ProcStorage;
use crate::test_utils::test_runtime;

const KEYS: u64 = 100;
const LIMIT: usize = 20;

fn path(root: &str, key: Option<u64>) -> Vec<u8> {
    let mut path = root.to_string().encode();
    if let Some(key) = key {
        key.encode_to(&mut path);
    }
    path
}

async fn seed(conn: &Connection, versions: u64) -> Result<()> {
    conn.execute_batch("BEGIN; CREATE TEMP TABLE history_paths (path BLOB PRIMARY KEY, removed INTEGER); CREATE TEMP TABLE history_versions (height INTEGER PRIMARY KEY, value BLOB);").await?;
    let paths = conn
        .prepare("INSERT INTO history_paths VALUES (?, ?)")
        .await?;
    for root in [
        "history-live",
        "history-dead",
        "history-sparse",
        "history-variant",
    ] {
        for key in 0..KEYS {
            let mut key_path = path(root, None);
            if root == "history-variant" {
                "some".to_string().encode_to(&mut key_path);
            }
            key.encode_to(&mut key_path);
            let removed = root == "history-dead" || (root == "history-sparse" && key < 90);
            paths.execute(params![key_path, removed]).await?;
            paths.reset();
        }
    }
    let heights = conn
        .prepare("INSERT INTO history_versions VALUES (?, ?)")
        .await?;
    for height in 2..=versions + 1 {
        let mut value = vec![42u8; 32];
        value[..8].copy_from_slice(&height.to_be_bytes());
        heights.execute(params![height, serialize(&value)?]).await?;
        heights.reset();
    }
    conn.execute_batch(&format!(
        r#"
        INSERT INTO blocks SELECT height, printf('%064x', height), 1 FROM history_versions;
        INSERT INTO contract_state (contract_id,height,size,path,value,deleted)
        SELECT 1, h.height, length(h.value), p.path, h.value,
            h.height = {} AND p.removed
        FROM history_versions h CROSS JOIN history_paths p ORDER BY h.height, p.path;
        DROP TABLE history_paths;
        DROP TABLE history_versions;
        COMMIT;
    "#,
        versions + 1
    ))
    .await?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    Point,
    Exists,
    Keys(bool),
    Rows(bool),
    Variant,
}

fn expected_result(root: &str, op: Operation, height: u64) -> Value {
    let mut value = vec![42u8; 32];
    value[..8].copy_from_slice(&height.to_be_bytes());
    let mut keys: Vec<u64> = match root {
        "history-live" => (0..KEYS).collect(),
        "history-sparse" => (90..KEYS).collect(),
        _ => Vec::new(),
    };
    match op {
        Operation::Point => {
            if root == "history-live" {
                json!(value)
            } else {
                Value::Null
            }
        }
        Operation::Exists => json!(!keys.is_empty()),
        Operation::Variant => json!(1),
        Operation::Keys(descending) | Operation::Rows(descending) => {
            if descending {
                keys.reverse();
            }
            keys.truncate(LIMIT);
            if matches!(op, Operation::Keys(_)) {
                json!(keys.into_iter().map(|key| key.encode()).collect::<Vec<_>>())
            } else {
                json!(
                    keys.into_iter()
                        .map(|key| (key.encode(), value.clone()))
                        .collect::<Vec<_>>()
                )
            }
        }
    }
}

async fn print_plans(conn: &Connection, versions: u64) -> Result<()> {
    let root = path("history-live", None);
    for (name, sql) in [
        (
            "live_scan",
            "SELECT cs.path FROM contract_state cs WHERE cs.contract_id=1 AND cs.path > ?1 AND cs.path < ?2 AND cs.deleted=0 AND NOT EXISTS (SELECT 1 FROM contract_state n WHERE n.contract_id=cs.contract_id AND n.path=cs.path AND n.height>cs.height) ORDER BY cs.path",
        ),
        (
            "variant",
            "SELECT path, deleted FROM contract_state WHERE contract_id=1 AND path >= ?1 AND path < ?2 ORDER BY height DESC, rowid DESC LIMIT 1",
        ),
    ] {
        let mut rows = conn
            .query(
                &format!("EXPLAIN QUERY PLAN {sql}"),
                params![root.clone(), subtree_end(&root)],
            )
            .await?;
        let mut plan = Vec::new();
        while let Some(row) = rows.next().await? {
            plan.push(row.get::<String>(3)?);
        }
        println!(
            "HISTORY_PLAN {}",
            json!({"versions":versions,"query":name,"sql":sql,"plan":plan})
        );
    }
    Ok(())
}

async fn call(
    store: &mut Store<Runtime>,
    rep: u32,
    root: &str,
    op: Operation,
) -> Result<(Value, u64)> {
    store.set_fuel(BUDGET)?;
    let result = match op {
        Operation::Point => json!(
            host(store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::get_list_u8(
                    accessor,
                    Resource::new_borrow(rep),
                    path(root, Some(0)),
                )
                .await
            })
            .await?
        ),
        Operation::Exists => json!(
            host(store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::exists(
                    accessor,
                    Resource::new_borrow(rep),
                    path(root, None),
                )
                .await
            })
            .await?
        ),
        Operation::Variant => json!(
            host(store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::extend_path_with_match(
                    accessor,
                    Resource::new_borrow(rep),
                    path(root, None),
                    vec!["none".to_string().encode(), "some".to_string().encode()],
                )
                .await
            })
            .await?
        ),
        Operation::Keys(descending) => {
            let cursor = host(store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::get_keys(
                    accessor,
                    Resource::new_borrow(rep),
                    path(root, None),
                    None,
                    None,
                    descending,
                )
                .await
            })
            .await?;
            let mut results = Vec::new();
            for _ in 0..LIMIT {
                let next = host(store, async |accessor| {
                    <Runtime as KeysHost<Runtime>>::next(
                        accessor,
                        Resource::new_borrow(cursor.rep()),
                    )
                    .await
                })
                .await?;
                let Some(key) = next else { break };
                results.push(key);
            }
            store.data().table.lock().await.delete(cursor)?;
            json!(results)
        }
        Operation::Rows(descending) => {
            let cursor = host(store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::get_storage_rows(
                    accessor,
                    Resource::new_borrow(rep),
                    path(root, None),
                    None,
                    None,
                    descending,
                )
                .await
            })
            .await?;
            let mut results = Vec::new();
            for _ in 0..LIMIT {
                let next = host(store, async |accessor| {
                    <Runtime as RowsHost<Runtime>>::next_list_u8(
                        accessor,
                        Resource::new_borrow(cursor.rep()),
                    )
                    .await
                })
                .await?;
                let Some(row) = next else { break };
                results.push(row);
            }
            store.data().table.lock().await.delete(cursor)?;
            json!(results)
        }
    };
    Ok((result, BUDGET - store.get_fuel()?))
}

async fn measure(
    store: &mut Store<Runtime>,
    rep: u32,
    root: &str,
    op: Operation,
) -> Result<(f64, Value, u64)> {
    let expected = call(store, rep, root, op).await?;
    let mut samples = Vec::new();
    for trial in 0..9 {
        let start = Instant::now();
        for _ in 0..4 {
            ensure!(black_box(call(store, rep, root, op).await?) == expected);
        }
        if trial >= 2 {
            samples.push(start.elapsed().as_secs_f64() * 1e6 / 4.0);
        }
    }
    samples.sort_by(f64::total_cmp);
    Ok((samples[samples.len() / 2], expected.0, expected.1))
}

async fn checkpoint(conn: &Connection) -> Result<String> {
    Ok(conn
        .query(
            "SELECT hash FROM checkpoints ORDER BY height DESC LIMIT 1",
            (),
        )
        .await?
        .next()
        .await?
        .context("checkpoint")?
        .get(0)?)
}

#[tokio::test]
#[ignore = "storage history timings and fuel parity; run explicitly in release mode"]
async fn benchmark_storage_history() -> Result<()> {
    let depths = std::env::var("KONTOR_HISTORY_DEPTHS").unwrap_or_else(|_| "1,10,100,1000".into());
    for versions in depths.split(',').map(str::parse::<u64>) {
        let versions = versions?;
        ensure!(versions > 0);
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let conn = runtime.storage.conn.clone();
        seed(&conn, versions).await?;
        print_plans(&conn, versions).await?;
        let tip = versions + 1;
        runtime.storage.height = tip;
        let before_checkpoint = checkpoint(&conn).await?;
        let mut store = runtime.make_store(BUDGET)?;
        let rep = store
            .data()
            .table
            .lock()
            .await
            .push(ProcStorage { contract_id: 1 })?
            .rep();
        let mut expected = Vec::new();
        let mut watermark = 0;
        for (state, target) in [
            ("archive", 0),
            ("retained_8", tip.saturating_sub(8)),
            ("finalized", tip),
        ] {
            if target > watermark {
                runtime.storage.prune(watermark, target).await?;
                watermark = target;
            }
            ensure!(checkpoint(&conn).await? == before_checkpoint);
            let physical: i64 = conn
                .query(
                    "SELECT COUNT(*) FROM contract_state WHERE contract_id=1",
                    (),
                )
                .await?
                .next()
                .await?
                .context("row count")?
                .get(0)?;
            let mut observations = Vec::new();
            for root in [
                "history-live",
                "history-dead",
                "history-sparse",
                "history-absent",
            ] {
                for op in [
                    Operation::Point,
                    Operation::Exists,
                    Operation::Keys(false),
                    Operation::Keys(true),
                    Operation::Rows(false),
                    Operation::Rows(true),
                ] {
                    let (us, result, fuel) = measure(&mut store, rep, root, op).await?;
                    ensure!(
                        result == expected_result(root, op, tip),
                        "incorrect result for {root}, {op:?}"
                    );
                    println!(
                        "HISTORY_BENCH {}",
                        json!({"versions":versions,"keys":KEYS,"state":state,"stored_rows":physical,"root":root,"operation":format!("{op:?}"),"us":us,"fuel":fuel,"returned":result.as_array().map(Vec::len)})
                    );
                    observations.push((result, fuel));
                }
            }
            let (us, result, fuel) =
                measure(&mut store, rep, "history-variant", Operation::Variant).await?;
            ensure!(result == json!(1));
            println!(
                "HISTORY_BENCH {}",
                json!({"versions":versions,"keys":KEYS,"state":state,"stored_rows":physical,"root":"history-variant","operation":"Variant","us":us,"fuel":fuel})
            );
            observations.push((result, fuel));
            if state == "archive" {
                expected = observations;
            } else {
                ensure!(
                    observations == expected,
                    "results/fuel changed after pruning at depth {versions}, {state}"
                );
            }
        }
    }
    Ok(())
}
