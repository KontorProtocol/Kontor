use std::sync::Arc;

use anyhow::{Result, ensure};
use futures_util::TryStreamExt;
use libsql::{AuthAction, Authorization, Connection, params};
use stdlib::KeyElement;
use tempfile::TempDir;

use super::current_state::{RESTORE_AFFECTED_KEYS, prepare_affected_keys};
use super::{
    StorageRowCursor, exists_contract_state, find_live_subtree, get_latest_contract_state_value,
    hard_delete_rows, path_prefix_filter_contract_state, prune_contract_state, rollback_to_height,
};
use crate::database::connection::new_connection;

async fn write(
    conn: &Connection,
    contract: u64,
    height: u64,
    key: u64,
    deleted: bool,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO blocks VALUES (?, ?, 1)",
        params![height, format!("block-{height}")],
    )
    .await?;
    let value = vec![height as u8; if deleted { 0 } else { height as usize }];
    conn.execute(
        "INSERT OR REPLACE INTO contract_state (contract_id, height, path, size, value, deleted)
         VALUES (?, ?, ?, ?, ?, ?)",
        params![
            contract,
            height,
            key.encode(),
            value.len() as i64,
            value,
            deleted
        ],
    )
    .await?;
    Ok(())
}

async fn assert_index(conn: &Connection) -> Result<()> {
    // Independent oracle over history; EXCEPT in both directions detects extra
    // pointers, missing revivals, wrong heights, and stale sizes.
    let mut rows = conn.query(
        "WITH expected AS (
           SELECT contract_id, path, height, length(value) AS size FROM (
             SELECT *, row_number() OVER (PARTITION BY contract_id, path ORDER BY height DESC) AS rank
             FROM contract_state
           ) WHERE rank = 1 AND deleted = 0
         ), missing AS (SELECT * FROM expected EXCEPT SELECT * FROM current_contract_state),
         extra AS (SELECT * FROM current_contract_state EXCEPT SELECT * FROM expected)
         SELECT * FROM missing UNION ALL SELECT * FROM extra",
        (),
    ).await?;
    ensure!(
        rows.next().await?.is_none(),
        "current index diverged from history"
    );
    ensure!(
        conn.query("PRAGMA foreign_key_check", ())
            .await?
            .next()
            .await?
            .is_none()
    );
    Ok(())
}

async fn checkpoint(conn: &Connection) -> Result<Vec<(u64, String)>> {
    let mut rows = conn
        .query("SELECT height, hash FROM checkpoints ORDER BY height", ())
        .await?;
    let mut result = Vec::new();
    while let Some(row) = rows.next().await? {
        result.push((row.get(0)?, row.get(1)?));
    }
    Ok(result)
}

#[tokio::test]
async fn current_state_handles_replacement_old_imports_and_hard_deletion() -> Result<()> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "current.db").await?;
    write(&conn, 1, 1, 0, false).await?;
    write(&conn, 1, 3, 0, false).await?;
    write(&conn, 1, 2, 0, false).await?;
    write(&conn, 2, 3, 0, false).await?;
    assert_index(&conn).await?;
    ensure!(
        get_latest_contract_state_value(&conn, 3, 1, &0u64.encode()).await? == Some(vec![3; 3])
    );

    write(&conn, 1, 3, 0, true).await?;
    write(&conn, 1, 2, 0, false).await?;
    assert_index(&conn).await?;
    ensure!(!exists_contract_state(&conn, 1, &0u64.encode()).await?);
    write(&conn, 1, 3, 0, false).await?;
    assert_index(&conn).await?;

    let rows = find_live_subtree(&conn, 1, &[])
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    hard_delete_rows(&conn, 1, 3, &rows).await?;
    assert_index(&conn).await?;
    ensure!(
        get_latest_contract_state_value(&conn, 2, 1, &0u64.encode()).await? == Some(vec![2; 2])
    );

    // Removing a newer creation must restore an older tombstone, not its value.
    write(&conn, 1, 2, 0, true).await?;
    write(&conn, 1, 3, 0, false).await?;
    hard_delete_rows(&conn, 1, 3, &rows).await?;
    assert_index(&conn).await?;
    ensure!(!exists_contract_state(&conn, 1, &[]).await?);
    ensure!(exists_contract_state(&conn, 2, &[]).await?);
    Ok(())
}

#[tokio::test]
async fn current_state_survives_pruning_reorg_abort_replay_and_reopen() -> Result<()> {
    let dir = TempDir::new()?;
    let archive = new_connection(dir.path(), "archive.db").await?;
    let pruned = new_connection(dir.path(), "pruned.db").await?;
    for conn in [&archive, &pruned] {
        conn.execute("BEGIN", ()).await?;
        for height in 1..=12 {
            for contract in [1, 2] {
                for key in 0..12 {
                    if (key + height) % 3 != 0 {
                        write(conn, contract, height, key, (key + height) % 5 == 0).await?;
                    }
                }
            }
            assert_index(conn).await?;
        }
        conn.execute("COMMIT", ()).await?;
    }
    let original = checkpoint(&archive).await?;
    pruned.execute("BEGIN", ()).await?;
    prune_contract_state(&pruned, 0, 6).await?;
    pruned.execute("COMMIT", ()).await?;
    ensure!(checkpoint(&pruned).await? == original);
    assert_index(&pruned).await?;

    for conn in [&archive, &pruned] {
        conn.execute("BEGIN", ()).await?;
        rollback_to_height(conn, 8).await?;
        assert_index(conn).await?;
        conn.execute("ROLLBACK", ()).await?;
        assert_index(conn).await?;
        ensure!(checkpoint(conn).await? == original);

        // SQL failure after the block cascade must restore history and pointers.
        conn.execute_batch(
            "CREATE TEMP TRIGGER reject_pointer BEFORE INSERT ON current_contract_state
                            BEGIN SELECT RAISE(ABORT, 'injected repair failure'); END;",
        )
        .await?;
        ensure!(rollback_to_height(conn, 8).await.is_err());
        conn.execute("DROP TRIGGER reject_pointer", ()).await?;
        assert_index(conn).await?;
        ensure!(checkpoint(conn).await? == original);

        rollback_to_height(conn, 8).await?;
        assert_index(conn).await?;
        write(conn, 1, 9, 20, false).await?;
        conn.execute("SAVEPOINT rejected_call", ()).await?;
        write(conn, 1, 9, 20, true).await?;
        write(conn, 1, 9, 99, false).await?;
        conn.execute_batch("ROLLBACK TO rejected_call; RELEASE rejected_call;")
            .await?;
        assert_index(conn).await?;
        conn.execute("VACUUM", ()).await?;
        assert_index(conn).await?;
    }
    ensure!(checkpoint(&archive).await? == checkpoint(&pruned).await?);
    for key in 0..=20u64 {
        ensure!(
            get_latest_contract_state_value(&archive, 100, 1, &key.encode()).await?
                == get_latest_contract_state_value(&pruned, 100, 1, &key.encode()).await?
        );
    }
    drop(pruned);
    let reopened = new_connection(dir.path(), "pruned.db").await?;
    assert_index(&reopened).await?;
    ensure!(
        get_latest_contract_state_value(&reopened, 9, 1, &20u64.encode()).await?
            == Some(vec![9; 9])
    );
    Ok(())
}

#[tokio::test]
async fn current_state_migration_backfills_once_without_changing_checkpoints() -> Result<()> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "upgrade.db").await?;
    for height in 1..=4 {
        write(&conn, 1, height, 0, false).await?;
        write(&conn, 1, height, 1, height == 4).await?;
    }
    let original = checkpoint(&conn).await?;
    conn.execute_batch(
        "DROP TRIGGER maintain_current_contract_state; DROP TABLE current_contract_state;",
    )
    .await?;
    drop(conn);
    let conn = new_connection(dir.path(), "upgrade.db").await?;
    assert_index(&conn).await?;
    ensure!(checkpoint(&conn).await? == original);
    // Reopening must not backfill or update existing pointers.
    conn.execute_batch(
        "CREATE TRIGGER reject_rebuild BEFORE INSERT ON current_contract_state
                        BEGIN SELECT RAISE(ABORT, 'unexpected rebuild'); END;",
    )
    .await?;
    let reopened = new_connection(dir.path(), "upgrade.db").await?;
    assert_index(&reopened).await?;
    reopened.execute("DROP TRIGGER reject_rebuild", ()).await?;
    write(&reopened, 1, 5, 1, false).await?;
    assert_index(&reopened).await?;
    Ok(())
}

#[tokio::test]
async fn current_state_discovery_never_reads_history_or_unaffordable_payloads() -> Result<()> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "discovery.db").await?;
    conn.execute("BEGIN", ()).await?;
    for height in 1..=8 {
        for key in 0..128 {
            write(&conn, 1, height, key, height == 8 && key != 127).await?;
        }
    }
    conn.execute("COMMIT", ()).await?;
    conn.authorizer(Some(Arc::new(|context| match context.action {
        AuthAction::Read {
            table_name: "contract_state",
            ..
        } => Authorization::Deny,
        _ => Authorization::Allow,
    })))?;
    for descending in [false, true] {
        let keys = path_prefix_filter_contract_state(&conn, 1, vec![], None, None, descending)
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        ensure!(keys == vec![127u64.encode()]);
        let mut cursor = StorageRowCursor::new(&conn, 1, vec![], None, None, descending);
        ensure!(matches!(
            cursor.next(0).await,
            Err(super::Error::ValueTooLarge)
        ));
    }
    ensure!(exists_contract_state(&conn, 1, &[]).await?);
    ensure!(!exists_contract_state(&conn, 1, &0u64.encode()).await?);
    ensure!(
        get_latest_contract_state_value(&conn, 100, 1, &0u64.encode())
            .await?
            .is_none()
    );
    ensure!(matches!(
        get_latest_contract_state_value(&conn, 7, 1, &127u64.encode()).await,
        Err(super::Error::ValueTooLarge)
    ));
    conn.authorizer(None)?;
    let mut cursor = StorageRowCursor::new(&conn, 1, vec![], None, None, false);
    ensure!(cursor.next(100).await? == Some((127u64.encode(), vec![8; 8])));
    ensure!(cursor.next(100).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn current_state_repair_plan_seeks_once_per_affected_key() -> Result<()> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "plans.db").await?;
    prepare_affected_keys(&conn).await?;
    let mut rows = conn
        .query(&format!("EXPLAIN QUERY PLAN {RESTORE_AFFECTED_KEYS}"), ())
        .await?;
    let mut plan = Vec::new();
    while let Some(row) = rows.next().await? {
        plan.push(row.get::<String>(3)?);
    }
    ensure!(plan.iter().any(|s| s == "SCAN a"), "{plan:?}");
    ensure!(
        plan.iter()
            .any(|s| s.contains("SEARCH n USING COVERING INDEX idx_contract_state_lookup")),
        "{plan:?}"
    );
    ensure!(
        !plan
            .iter()
            .any(|s| s.starts_with("SCAN s") || s.starts_with("SCAN n")),
        "{plan:?}"
    );
    Ok(())
}
