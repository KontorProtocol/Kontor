use std::hint::black_box;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use indexer_types::serialize;
use libsql::{Connection, Value, params};
use serde_json::json;
use stdlib::subtree_end;

use super::{LIMIT, checkpoint, path, seed_sized};
use crate::database::queries::{get_latest_contract_state_value, rollback_to_height};
use crate::test_utils::test_runtime;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Layout {
    History,
    Pointer,
    Values,
    RowValues,
}

impl Layout {
    fn columns(self) -> &'static str {
        match self {
            Self::Values | Self::RowValues => "contract_id, path, height, size, value",
            _ => "contract_id, path, height, size",
        }
    }

    fn projection(self, alias: &str) -> String {
        let tail = if matches!(self, Self::Values | Self::RowValues) {
            format!(", {alias}.size, {alias}.value")
        } else {
            format!(", {alias}.size")
        };
        format!("{alias}.contract_id, {alias}.path, {alias}.height{tail}")
    }
}

async fn install(conn: &Connection, layout: Layout) -> Result<()> {
    if layout == Layout::History {
        return Ok(());
    }
    // Logical version references survive database compaction. These triggers cover
    // ascending/same-height writes; reorgs repair affected keys explicitly.
    let columns = layout.columns();
    let table_options = if layout == Layout::RowValues {
        ""
    } else {
        "WITHOUT ROWID"
    };
    let extra = if matches!(layout, Layout::Values | Layout::RowValues) {
        ", size INTEGER NOT NULL, value BLOB NOT NULL"
    } else {
        ", size INTEGER NOT NULL"
    };
    let update = if matches!(layout, Layout::Values | Layout::RowValues) {
        ", size=excluded.size, value=excluded.value"
    } else {
        ", size=excluded.size"
    };
    conn.execute_batch(&format!(
        "BEGIN;
         CREATE TABLE bench_current (
             contract_id INTEGER NOT NULL, path BLOB NOT NULL, height INTEGER NOT NULL{extra},
             PRIMARY KEY (contract_id, path),
             FOREIGN KEY (height) REFERENCES blocks(height) ON DELETE CASCADE
         ) {table_options};
         CREATE INDEX bench_current_height ON bench_current(height);
         INSERT INTO bench_current ({columns})
         SELECT {} FROM contract_state s WHERE s.deleted=0 AND NOT EXISTS (
             SELECT 1 FROM contract_state n WHERE n.contract_id=s.contract_id
             AND n.path=s.path AND n.height>s.height);
         CREATE TRIGGER bench_head_live AFTER INSERT ON contract_state WHEN NEW.deleted=0 BEGIN
             INSERT INTO bench_current ({columns}) SELECT {}
             ON CONFLICT (contract_id, path) DO UPDATE SET height=excluded.height{update};
         END;
         CREATE TRIGGER bench_head_dead AFTER INSERT ON contract_state WHEN NEW.deleted=1 BEGIN
             DELETE FROM bench_current WHERE contract_id=NEW.contract_id AND path=NEW.path;
         END;
         CREATE TEMP TABLE bench_affected (
             contract_id INTEGER NOT NULL, path BLOB NOT NULL,
             PRIMARY KEY (contract_id, path)
         ) WITHOUT ROWID;
         COMMIT;",
        layout.projection("s"),
        layout.projection("NEW")
    ))
    .await?;
    for (name, sql) in [
        (
            "capture",
            "INSERT OR IGNORE INTO bench_affected SELECT contract_id,path FROM contract_state WHERE height>1 AND height<=(SELECT MAX(height) FROM blocks)",
        ),
        ("cascade", "DELETE FROM bench_current WHERE height=2"),
        (
            "restore",
            "SELECT s.height FROM bench_affected a JOIN contract_state s ON s.rowid=(SELECT n.rowid FROM contract_state n WHERE n.contract_id=a.contract_id AND n.path=a.path ORDER BY n.height DESC LIMIT 1) WHERE s.deleted=0",
        ),
    ] {
        let mut rows = conn.query(&format!("EXPLAIN QUERY PLAN {sql}"), ()).await?;
        let mut plan = Vec::new();
        while let Some(row) = rows.next().await? {
            plan.push(row.get::<String>(3)?);
        }
        println!(
            "CURRENT_PLAN {}",
            json!({"layout":format!("{layout:?}"),"query":name,"plan":plan})
        );
    }
    Ok(())
}

async fn scalar(conn: &Connection, sql: &str) -> Result<u64> {
    Ok(conn
        .query(sql, ())
        .await?
        .next()
        .await?
        .with_context(|| sql.to_owned())?
        .get(0)?)
}

async fn allocated_bytes(conn: &Connection) -> Result<u64> {
    let pages = scalar(conn, "PRAGMA page_count").await?;
    let free = scalar(conn, "PRAGMA freelist_count").await?;
    Ok((pages - free) * scalar(conn, "PRAGMA page_size").await?)
}

#[derive(Clone, Copy, Debug)]
enum Read {
    Keys,
    Values,
    Exists,
    Point,
}

type Entries = Vec<(Vec<u8>, Vec<u8>)>;

async fn read(
    conn: &Connection,
    layout: Layout,
    seek: bool,
    root: &str,
    descending: bool,
    operation: Read,
) -> Result<Entries> {
    let prefix = path(root, None);
    let with_values = matches!(operation, Read::Values | Read::Point);
    if matches!(operation, Read::Point) && layout == Layout::History {
        let key = path(root, Some(0));
        return Ok(get_latest_contract_state_value(conn, u64::MAX, 1, &key)
            .await?
            .map(|value| vec![(key, value)])
            .unwrap_or_default());
    }
    let (cmp, bound, order, start, end) = if descending {
        ("<", ">", "DESC", subtree_end(&prefix), prefix.clone())
    } else {
        (">", "<", "ASC", prefix.clone(), subtree_end(&prefix))
    };
    let range = if matches!(operation, Read::Point) {
        "cs.path = ?1".to_string()
    } else {
        format!("cs.path {cmp} ?1 AND cs.path {bound} ?2")
    };
    let (projection, table, filter) = match layout {
        Layout::History if seek => (
            "cs.path, head.rowid, head.deleted, head.size",
            "contract_state cs JOIN contract_state head ON head.rowid = (
                SELECT n.rowid FROM contract_state n WHERE n.contract_id=cs.contract_id
                AND n.path=cs.path ORDER BY n.height DESC LIMIT 1)",
            "",
        ),
        Layout::History => (
            "cs.path, cs.rowid, cs.deleted, cs.size",
            "contract_state cs",
            " AND cs.deleted=0 AND NOT EXISTS (SELECT 1 FROM contract_state n
                WHERE n.contract_id=cs.contract_id AND n.path=cs.path AND n.height>cs.height)",
        ),
        _ => ("cs.path, cs.height, 0, cs.size", "bench_current cs", ""),
    };
    let sql = format!(
        "SELECT {projection} FROM {table} WHERE cs.contract_id=1 AND {range}{filter}
         ORDER BY cs.path {order}"
    );
    let statement = conn.prepare(&sql).await?;
    let mut rows = if matches!(operation, Read::Point) {
        statement.query(params![path(root, Some(0))]).await?
    } else {
        statement.query(params![start, end.clone()]).await?
    };
    let values = if with_values {
        Some(
            conn.prepare(match layout {
                Layout::Values | Layout::RowValues => {
                    "SELECT value FROM bench_current WHERE contract_id=1 AND path=?"
                }
                Layout::Pointer => {
                    "SELECT value FROM contract_state WHERE contract_id=1 AND height=?1 AND path=?2"
                }
                Layout::History => "SELECT value FROM contract_state WHERE rowid=?",
            })
            .await?,
        )
    } else {
        None
    };
    let limit = if matches!(operation, Read::Exists | Read::Point) {
        1
    } else {
        LIMIT
    };
    let mut last = None;
    let mut output = Vec::new();
    while output.len() < limit {
        let Some(row) = rows.next().await? else { break };
        let full: Vec<u8> = row.get(0)?;
        if seek && last.as_ref() == Some(&full) {
            drop(rows);
            statement.reset();
            rows = statement.query(params![full, end.clone()]).await?;
            continue;
        }
        last = Some(full.clone());
        if row.get::<bool>(2)? {
            continue;
        }
        let value = if let Some(values) = &values {
            values.reset();
            let params = match layout {
                Layout::Values | Layout::RowValues => vec![Value::Blob(full.clone())],
                Layout::Pointer => vec![Value::Integer(row.get(1)?), Value::Blob(full.clone())],
                Layout::History => vec![Value::Integer(row.get(1)?)],
            };
            values
                .query(params)
                .await?
                .next()
                .await?
                .context("current value")?
                .get(0)?
        } else {
            Vec::new()
        };
        if with_values {
            ensure!(value.len() as u64 == row.get::<u64>(3)?);
        }
        output.push((full, value));
    }
    Ok(output)
}

fn encoded_value(height: u64, bytes: usize) -> Result<Vec<u8>> {
    let mut value = vec![42u8; bytes];
    value[..8].copy_from_slice(&height.to_be_bytes());
    serialize(&value)
}

async fn reads(
    conn: &Connection,
    layout: Layout,
    keys: u64,
    versions: u64,
    bytes: usize,
    state: &str,
) -> Result<()> {
    for seek in [false, true] {
        if seek && layout != Layout::History {
            continue;
        }
        for root in [
            "history-live",
            "history-dead",
            "history-sparse",
            "history-absent",
        ] {
            for operation in [Read::Keys, Read::Values, Read::Exists, Read::Point] {
                for descending in [false, true] {
                    if descending && matches!(operation, Read::Exists | Read::Point) {
                        continue;
                    }
                    let mut candidates: Vec<u64> = match root {
                        "history-live" => (0..keys).collect(),
                        "history-sparse" => (keys * 9 / 10..keys).collect(),
                        _ => Vec::new(),
                    };
                    if descending {
                        candidates.reverse();
                    }
                    if matches!(operation, Read::Point) {
                        candidates.retain(|key| *key == 0);
                    }
                    let limit = if matches!(operation, Read::Exists | Read::Point) {
                        1
                    } else {
                        LIMIT
                    };
                    let value = if matches!(operation, Read::Values | Read::Point) {
                        encoded_value(versions + 1, bytes)?
                    } else {
                        Vec::new()
                    };
                    let expected: Entries = candidates
                        .into_iter()
                        .take(limit)
                        .map(|key| (path(root, Some(key)), value.clone()))
                        .collect();
                    let mut timings = Vec::new();
                    for trial in 0..6 {
                        let start = Instant::now();
                        ensure!(
                            black_box(read(conn, layout, seek, root, descending, operation).await?)
                                == expected,
                            "{layout:?} {seek} {root} {operation:?} {descending}"
                        );
                        if trial > 0 {
                            timings.push(start.elapsed().as_secs_f64() * 1e6);
                        }
                    }
                    timings.sort_by(f64::total_cmp);
                    println!(
                        "CURRENT_READ {}",
                        json!({"layout":format!("{layout:?}"),"seek":seek,
                        "keys":keys,"versions":versions,"bytes":bytes,"state":state,"root":root,
                        "operation":format!("{operation:?}"),"descending":descending,"us":timings[2]})
                    );
                }
            }
        }
    }
    Ok(())
}

async fn verify_current(conn: &Connection, layout: Layout) -> Result<()> {
    if layout == Layout::History {
        return Ok(());
    }
    let live =
        "SELECT s.contract_id, s.path, s.height, s.size FROM contract_state s WHERE s.deleted=0
        AND NOT EXISTS (SELECT 1 FROM contract_state n WHERE n.contract_id=s.contract_id
        AND n.path=s.path AND n.height>s.height)";
    for sql in [
        format!(
            "SELECT COUNT(*) FROM ({live} EXCEPT SELECT contract_id,path,height,size FROM bench_current)"
        ),
        format!(
            "SELECT COUNT(*) FROM (SELECT contract_id,path,height,size FROM bench_current EXCEPT {live})"
        ),
    ] {
        ensure!(scalar(conn, &sql).await? == 0, "current rows diverged");
    }
    if matches!(layout, Layout::Values | Layout::RowValues) {
        ensure!(
            scalar(
                conn,
                "SELECT COUNT(*) FROM bench_current c JOIN contract_state s ON s.contract_id=c.contract_id AND s.path=c.path AND s.height=c.height
            WHERE c.value != s.value OR c.size != s.size"
            )
            .await?
                == 0
        );
    }
    Ok(())
}

async fn repair(conn: &Connection, layout: Layout) -> Result<()> {
    conn.execute_batch(&format!(
        "INSERT INTO bench_current ({}) SELECT {} FROM bench_affected a
         JOIN contract_state s ON s.rowid = (SELECT n.rowid FROM contract_state n
             WHERE n.contract_id=a.contract_id AND n.path=a.path ORDER BY n.height DESC LIMIT 1)
         WHERE s.deleted=0;",
        layout.columns(),
        layout.projection("s")
    ))
    .await?;
    Ok(())
}

async fn rollback(conn: &Connection, layout: Layout, target: u64) -> Result<(f64, f64, f64, u64)> {
    let start = Instant::now();
    let mut affected = 0;
    if layout != Layout::History {
        conn.execute_batch("DELETE FROM bench_affected").await?;
        conn.execute(
            "INSERT OR IGNORE INTO bench_affected SELECT contract_id,path FROM contract_state
            WHERE height > ? AND height <= (SELECT MAX(height) FROM blocks)",
            [target],
        )
        .await?;
        affected = scalar(conn, "SELECT COUNT(*) FROM bench_affected").await?;
    }
    let capture = start.elapsed().as_secs_f64() * 1e6;
    let start = Instant::now();
    rollback_to_height(conn, target).await?;
    let cascade = start.elapsed().as_secs_f64() * 1e6;
    let start = Instant::now();
    if layout != Layout::History {
        repair(conn, layout).await?;
    }
    Ok((
        capture,
        cascade,
        start.elapsed().as_secs_f64() * 1e6,
        affected,
    ))
}

async fn write_block(
    conn: &Connection,
    height: u64,
    distinct: u64,
    offset: u64,
    bytes: usize,
    deleted: bool,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO blocks VALUES (?, printf('%064x', ?), 1)",
        params![height, height],
    )
    .await?;
    let statement = conn
        .prepare(
            "INSERT OR REPLACE INTO contract_state
        (contract_id,height,size,path,value,deleted) VALUES (1,?,?,?,?,?)",
        )
        .await?;
    let value = if deleted {
        Vec::new()
    } else {
        encoded_value(height, bytes)?
    };
    for key in offset..offset + distinct {
        statement.reset();
        statement
            .execute(params![
                height,
                value.len() as u64,
                path("history-live", Some(key)),
                value.clone(),
                deleted
            ])
            .await?;
    }
    Ok(())
}

async fn mutations(
    conn: &Connection,
    layout: Layout,
    keys: u64,
    versions: u64,
    bytes: usize,
) -> Result<()> {
    let target = versions + 1;
    let before = checkpoint(conn).await?;
    for (depth, distinct, disjoint) in [
        (1, 100, false),
        (10, 100, false),
        (10, 100, true),
        (100, 100, false),
    ] {
        let mut samples = Vec::new();
        for trial in 0..4 {
            conn.execute_batch("BEGIN").await?;
            let start = Instant::now();
            for step in 1..=depth {
                let offset = if disjoint { (step - 1) * distinct } else { 0 };
                write_block(conn, target + step, distinct, offset, bytes, step % 3 == 0).await?;
            }
            conn.execute_batch("COMMIT").await?;
            let write_us = start.elapsed().as_secs_f64() * 1e6;
            verify_current(conn, layout).await?;
            conn.execute_batch("BEGIN").await?;
            let start = Instant::now();
            let (capture, cascade, repair, affected) = rollback(conn, layout, target).await?;
            conn.execute_batch("COMMIT").await?;
            let rollback_us = start.elapsed().as_secs_f64() * 1e6;
            verify_current(conn, layout).await?;
            ensure!(checkpoint(conn).await? == before);
            if trial > 0 {
                ensure!(
                    layout == Layout::History
                        || affected == if disjoint { distinct * depth } else { distinct }
                );
                samples.push([rollback_us, write_us, capture, cascade, repair]);
            }
        }
        let median = |column: usize| {
            let mut values: Vec<_> = samples.iter().map(|sample| sample[column]).collect();
            values.sort_by(f64::total_cmp);
            values[1]
        };
        let (rollback_us, write_us, capture, cascade, repair) =
            (median(0), median(1), median(2), median(3), median(4));
        let affected = if disjoint { distinct * depth } else { distinct };
        println!(
            "CURRENT_MUTATION {}",
            json!({"layout":format!("{layout:?}"),"keys":keys,"versions":versions,
            "bytes":bytes,"depth":depth,"distinct_per_block":distinct,"disjoint":disjoint,
            "affected":affected,"write_us":write_us,"rollback_us":rollback_us,
            "capture_us":capture,"cascade_us":cascade,"repair_us":repair})
        );
    }
    // SQL aborts must restore both tables, including a replacement at the same height.
    conn.execute_batch("BEGIN").await?;
    write_block(conn, target + 1, 10, 0, bytes, false).await?;
    write_block(conn, target + 1, 10, 0, bytes, true).await?;
    write_block(conn, target + 1, 10, 0, bytes, false).await?;
    verify_current(conn, layout).await?;
    conn.execute_batch("ROLLBACK").await?;
    verify_current(conn, layout).await?;
    ensure!(checkpoint(conn).await? == before);
    if layout != Layout::History {
        // A failed reorg must restore both the removed history and its current view.
        conn.execute_batch("BEGIN").await?;
        write_block(conn, target + 1, 10, 0, bytes, true).await?;
        let value = encoded_value(target + 1, bytes)?;
        conn.execute(
            "INSERT INTO contract_state (contract_id,height,size,path,value,deleted) VALUES (1,?,?,?,?,0)",
            params![target + 1, value.len() as u64, path("history-dead", Some(0)), value],
        ).await?;
        conn.execute_batch("COMMIT").await?;
        let tip_checkpoint = checkpoint(conn).await?;
        conn.execute_batch("BEGIN").await?;
        rollback(conn, layout, target).await?;
        conn.execute_batch("ROLLBACK").await?;
        verify_current(conn, layout).await?;
        ensure!(checkpoint(conn).await? == tip_checkpoint);
        conn.execute_batch("BEGIN").await?;
        rollback(conn, layout, target).await?;
        conn.execute_batch("COMMIT").await?;
        verify_current(conn, layout).await?;
        ensure!(checkpoint(conn).await? == before);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "history cursor versus maintained current state; run explicitly in release mode"]
async fn benchmark_current_state() -> Result<()> {
    let cases = std::env::var("KONTOR_CURRENT_CASES").unwrap_or_else(|_| {
        "100:1:32,100:1000:32,1000:10:32,10000:1:32,10000:10:32,1000:10:4096".into()
    });
    for case in cases.split(',') {
        let parts: Vec<_> = case
            .split(':')
            .map(str::parse::<u64>)
            .collect::<Result<_, _>>()?;
        ensure!(parts.len() == 3 && parts[0] > 0 && parts[1] > 0 && parts[2] >= 8);
        let (keys, versions, bytes) = (parts[0], parts[1], parts[2] as usize);
        for layout in [
            Layout::History,
            Layout::Pointer,
            Layout::Values,
            Layout::RowValues,
        ] {
            let (runtime, _dir, _name) = test_runtime().await?;
            let conn = &runtime.storage.conn;
            seed_sized(conn, versions, keys, bytes, true).await?;
            let history_bytes = allocated_bytes(conn).await?;
            let start = Instant::now();
            install(conn, layout).await?;
            let build_us = start.elapsed().as_secs_f64() * 1e6;
            let extra_bytes = allocated_bytes(conn).await? - history_bytes;
            verify_current(conn, layout).await?;
            println!(
                "CURRENT_SPACE {}",
                json!({"layout":format!("{layout:?}"),"keys":keys,
                "versions":versions,"bytes":bytes,"history_bytes":history_bytes,"extra_bytes":extra_bytes,"build_us":build_us})
            );
            reads(conn, layout, keys, versions, bytes, "archive").await?;
            mutations(conn, layout, keys, versions, bytes).await?;
            let before = checkpoint(conn).await?;
            runtime.storage.prune(0, versions + 1).await?;
            verify_current(conn, layout).await?;
            ensure!(checkpoint(conn).await? == before);
            reads(conn, layout, keys, versions, bytes, "finalized").await?;
            conn.execute_batch("VACUUM").await?;
            verify_current(conn, layout).await?;
        }
    }
    Ok(())
}
