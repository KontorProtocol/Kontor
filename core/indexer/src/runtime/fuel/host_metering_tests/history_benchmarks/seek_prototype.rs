use std::hint::black_box;
use std::time::Instant;

use anyhow::{Result, ensure};
use futures_util::TryStreamExt;
use libsql::{Connection, params};
use serde_json::json;
use stdlib::{KeyElement, subtree_end};

use super::{LIMIT, path, seed};
use crate::database::queries::path_prefix_filter_contract_state;
use crate::test_utils::test_runtime;

#[derive(Clone, Copy, Debug)]
enum Strategy {
    Current,
    PreparedSeek,
    RecursiveSeek,
    StreamingSeek,
}

async fn streaming_seek(
    conn: &Connection,
    prefix: Vec<u8>,
    descending: bool,
) -> Result<Vec<Vec<u8>>> {
    let (cmp, order, bound, mut start, end) = if descending {
        ("<", "DESC", ">", subtree_end(&prefix), prefix.clone())
    } else {
        (">", "ASC", "<", prefix.clone(), subtree_end(&prefix))
    };
    let statement = conn
        .prepare(&format!(
            "SELECT cs.path, head.deleted FROM contract_state cs
             JOIN contract_state head ON head.rowid = (
                 SELECT n.rowid FROM contract_state n
                 WHERE n.contract_id = cs.contract_id AND n.path = cs.path
                 ORDER BY n.height DESC LIMIT 1)
             WHERE cs.contract_id = 1 AND cs.path {cmp} ?1 AND cs.path {bound} ?2
             ORDER BY cs.path {order}"
        ))
        .await?;
    let mut rows = statement.query(params![start.clone(), end.clone()]).await?;
    let mut last = None;
    let mut output = Vec::new();
    while output.len() < LIMIT {
        let Some(row) = rows.next().await? else {
            break;
        };
        let full: Vec<u8> = row.get(0)?;
        if last.as_ref() == Some(&full) {
            // A second version signals history. Seek past the whole path instead
            // of consuming the remaining versions; one-version paths keep streaming.
            start = full;
            drop(rows);
            statement.reset();
            rows = statement.query(params![start.clone(), end.clone()]).await?;
            continue;
        }
        last = Some(full.clone());
        if !row.get::<bool>(1)? {
            output.push(full[prefix.len()..].to_vec());
        }
    }
    Ok(output)
}

fn seek_sql(descending: bool, recursive: bool) -> String {
    let (cmp, order, bound) = if descending {
        ("<", "DESC", "p.path > ?2")
    } else {
        (">", "ASC", "p.path < ?2")
    };
    // Resolve the next distinct path before selecting its newest version. Reversing
    // the path index directly would otherwise put the oldest version first.
    let rowid = |start: &str| {
        format!(
            "SELECT n.rowid FROM contract_state n WHERE n.contract_id = 1 AND n.path = (
                SELECT p.path FROM contract_state p
                WHERE p.contract_id = 1 AND p.path {cmp} {start} AND {bound}
                ORDER BY p.path {order} LIMIT 1
            ) ORDER BY n.height DESC LIMIT 1"
        )
    };
    let first = rowid("?1");
    if !recursive {
        return format!(
            "SELECT cs.path, cs.deleted FROM contract_state cs WHERE cs.rowid = ({first})"
        );
    }
    let next = rowid("heads.path");
    // Each recursive step has at most one successor. Stop at the first live path;
    // there is at most one output, so ordering does not rely on CTE traversal order.
    format!(
        "WITH RECURSIVE heads(path, deleted) AS (
            SELECT cs.path, cs.deleted FROM contract_state cs WHERE cs.rowid = ({first})
            UNION ALL
            SELECT cs.path, cs.deleted FROM heads JOIN contract_state cs
                ON cs.rowid = ({next}) WHERE heads.deleted = 1
        ) SELECT path, deleted FROM heads WHERE deleted = 0"
    )
}

async fn scan(
    conn: &Connection,
    root: &str,
    descending: bool,
    strategy: Strategy,
) -> Result<Vec<Vec<u8>>> {
    let prefix = path(root, None);
    if matches!(strategy, Strategy::StreamingSeek) {
        return streaming_seek(conn, prefix, descending).await;
    }
    if matches!(strategy, Strategy::Current) {
        let mut stream = Box::pin(
            path_prefix_filter_contract_state(conn, 1, prefix, None, None, descending).await?,
        );
        let mut output = Vec::new();
        for _ in 0..LIMIT {
            let Some(key) = stream.try_next().await? else {
                break;
            };
            output.push(key);
        }
        return Ok(output);
    }
    let statement = conn
        .prepare(&seek_sql(
            descending,
            matches!(strategy, Strategy::RecursiveSeek),
        ))
        .await?;
    let end = subtree_end(&prefix);
    let (mut start, bound) = if descending {
        (end, prefix.clone())
    } else {
        (prefix.clone(), end)
    };
    let mut output = Vec::new();
    while output.len() < LIMIT {
        statement.reset();
        let mut rows = statement.query(params![start, bound.clone()]).await?;
        let Some(row) = rows.next().await? else {
            break;
        };
        let full: Vec<u8> = row.get(0)?;
        if !row.get::<bool>(1)? {
            output.push(full[prefix.len()..].to_vec());
        }
        start = full;
    }
    Ok(output)
}

async fn measure(
    conn: &Connection,
    root: &str,
    descending: bool,
    strategy: Strategy,
    expected: &[Vec<u8>],
) -> Result<f64> {
    let mut samples = Vec::new();
    for trial in 0..6 {
        let start = Instant::now();
        for _ in 0..2 {
            ensure!(black_box(scan(conn, root, descending, strategy).await?) == expected);
        }
        if trial > 0 {
            samples.push(start.elapsed().as_secs_f64() * 1e6 / 2.0);
        }
    }
    samples.sort_by(f64::total_cmp);
    Ok(samples[samples.len() / 2])
}

#[tokio::test]
#[ignore = "distinct-path seek experiment; run explicitly in release mode"]
async fn benchmark_storage_seeks() -> Result<()> {
    let cases = std::env::var("KONTOR_SEEK_CASES").unwrap_or_else(|_| {
        "100:1,100:10,100:100,100:1000,1000:1,1000:100,10000:1,10000:10".into()
    });
    for case in cases.split(',') {
        let (keys, versions) = case.split_once(':').expect("keys:versions");
        let keys = keys.parse::<u64>()?;
        let versions = versions.parse::<u64>()?;
        ensure!(keys > 0 && versions > 0);
        let (runtime, _dir, _name) = test_runtime().await?;
        let conn = &runtime.storage.conn;
        seed(conn, versions, keys).await?;
        for (state, watermark) in [("archive", 0), ("finalized", versions + 1)] {
            if watermark > 0 {
                runtime.storage.prune(0, watermark).await?;
            }
            for root in ["history-live", "history-dead", "history-sparse"] {
                for descending in [false, true] {
                    let mut expected: Vec<u64> = match root {
                        "history-live" => (0..keys).collect(),
                        "history-sparse" => (keys * 9 / 10..keys).collect(),
                        _ => Vec::new(),
                    };
                    if descending {
                        expected.reverse();
                    }
                    let expected: Vec<Vec<u8>> = expected
                        .into_iter()
                        .take(LIMIT)
                        .map(|key| key.encode())
                        .collect();
                    for strategy in [
                        Strategy::Current,
                        Strategy::PreparedSeek,
                        Strategy::RecursiveSeek,
                        Strategy::StreamingSeek,
                    ] {
                        let us = measure(conn, root, descending, strategy, &expected).await?;
                        println!(
                            "SEEK_BENCH {}",
                            json!({"keys":keys,"versions":versions,"state":state,
                                "root":root,"descending":descending,
                                "strategy":format!("{strategy:?}"),"us":us})
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
