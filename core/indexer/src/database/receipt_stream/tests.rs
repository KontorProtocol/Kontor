use anyhow::Result;
use libsql::{Connection, Value, params};
use tempfile::TempDir;

use super::{
    MAX_SAFE_RECEIPT_ID, RECOVERY_BATCH_LIMIT, initialize_receipt_stream, recovery_boundary,
    rotate_stream_epoch, stream_state,
};
use crate::database::connection::new_connection;
use crate::database::queries::rollback_to_height;

async fn fixture() -> Result<(TempDir, Connection)> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "stream.db").await?;
    conn.execute_batch(
        "INSERT INTO blocks VALUES (0, 'zero', 1), (1, 'one', 1), (2, 'two', 1);
         INSERT INTO signers VALUES (1, 0);",
    )
    .await?;
    Ok((dir, conn))
}

async fn receipt(conn: &Connection, id: Option<u64>, height: u64) -> Result<u64> {
    conn.execute(
        "INSERT INTO contract_results
         (id, contract_id, func, height, result_index, gas, size, signer_id)
         VALUES (?1, 1, 'test', ?2, 0, 1, 1, 1)",
        params![id.map(Value::try_from).transpose()?, height],
    )
    .await?;
    Ok(conn.last_insert_rowid() as u64)
}

#[tokio::test]
async fn rollback_boundary_precedes_new_batch_at_surviving_anchor() -> Result<()> {
    let (_dir, conn) = fixture().await?;
    receipt(&conn, Some(80), 0).await?;
    receipt(&conn, Some(100), 2).await?;
    let old = stream_state(&conn).await?;
    rollback_to_height(&conn, 1).await?;
    assert_eq!(receipt(&conn, None, 1).await?, 81);
    let state = stream_state(&conn).await?;
    let recovery = recovery_boundary(&conn, &state, old.generation, 100)
        .await?
        .unwrap();
    assert_eq!(recovery.cursor, 80);
    assert_eq!(recovery.surviving_height, 1);
    assert_eq!(state.max_result_id, 81);
    rollback_to_height(&conn, 0).await?;
    let state = stream_state(&conn).await?;
    let recovery = recovery_boundary(&conn, &state, old.generation, 100)
        .await?
        .unwrap();
    assert_eq!(recovery.cursor, 80);
    assert_eq!(recovery.surviving_height, 0);
    assert_eq!(recovery.generation, 2);
    Ok(())
}

#[tokio::test]
async fn sparse_deletion_preserves_acknowledged_survivor() -> Result<()> {
    let (_dir, conn) = fixture().await?;
    receipt(&conn, Some(80), 0).await?;
    receipt(&conn, Some(100), 2).await?;
    receipt(&conn, Some(101), 0).await?;
    rollback_to_height(&conn, 1).await?;
    assert_eq!(receipt(&conn, None, 1).await?, 102);
    let state = stream_state(&conn).await?;
    assert_eq!(
        recovery_boundary(&conn, &state, 0, 101)
            .await?
            .unwrap()
            .cursor,
        101
    );
    assert_eq!(
        recovery_boundary(&conn, &state, 0, 100)
            .await?
            .unwrap()
            .cursor,
        100
    );
    conn.execute("PRAGMA incremental_vacuum", ()).await?;
    conn.execute("VACUUM", ()).await?;
    assert_eq!(stream_state(&conn).await?, state);
    let mut rows = conn
        .query("SELECT id FROM contract_results ORDER BY id", ())
        .await?;
    let mut ids = Vec::new();
    while let Some(row) = rows.next().await? {
        ids.push(row.get::<u64>(0)?);
    }
    assert_eq!(ids, [80, 101, 102]);
    Ok(())
}

#[tokio::test]
async fn failed_rollback_and_outer_failure_restore_generation_and_receipts() -> Result<()> {
    let (_dir, conn) = fixture().await?;
    receipt(&conn, Some(100), 2).await?;
    let original = stream_state(&conn).await?;
    conn.execute_batch(
        "CREATE TRIGGER reject_stream_record BEFORE INSERT ON receipt_stream_rollbacks
         BEGIN SELECT RAISE(ABORT, 'injected journal failure'); END;",
    )
    .await?;
    assert!(rollback_to_height(&conn, 0).await.is_err());
    assert_eq!(stream_state(&conn).await?, original);
    conn.execute("DROP TRIGGER reject_stream_record", ())
        .await?;
    conn.execute("SAVEPOINT outer_repair", ()).await?;
    rollback_to_height(&conn, 0).await?;
    assert_eq!(stream_state(&conn).await?.generation, 1);
    conn.execute_batch("ROLLBACK TO outer_repair; RELEASE outer_repair")
        .await?;
    assert_eq!(stream_state(&conn).await?, original);
    Ok(())
}

#[tokio::test]
async fn recovery_is_bounded_and_rejects_missing_history() -> Result<()> {
    let (_dir, conn) = fixture().await?;
    for _ in 0..300 {
        rollback_to_height(&conn, 0).await?;
    }
    let state = stream_state(&conn).await?;
    let first = recovery_boundary(&conn, &state, 0, 100).await?.unwrap();
    assert_eq!(first.generation, RECOVERY_BATCH_LIMIT);
    assert_eq!(first.cursor, 0);
    let last = recovery_boundary(&conn, &state, first.generation, first.cursor)
        .await?
        .unwrap();
    assert_eq!(last.generation, 300);
    assert!(recovery_boundary(&conn, &state, 300, 0).await?.is_none());
    assert!(recovery_boundary(&conn, &state, 301, 0).await.is_err());
    conn.execute(
        "DELETE FROM receipt_stream_rollbacks WHERE generation = 260",
        (),
    )
    .await?;
    assert!(
        recovery_boundary(&conn, &state, first.generation, 0)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn unsupported_lineage_is_transactional_sticky_and_rotates_only_when_valid() -> Result<()> {
    let (_dir, conn) = fixture().await?;
    let original = stream_state(&conn).await?;
    conn.execute("SAVEPOINT failed_insert", ()).await?;
    receipt(&conn, Some(MAX_SAFE_RECEIPT_ID + 1), 2).await?;
    assert!(stream_state(&conn).await?.unsupported);
    conn.execute_batch("ROLLBACK TO failed_insert; RELEASE failed_insert")
        .await?;
    assert_eq!(stream_state(&conn).await?, original);
    receipt(&conn, Some(MAX_SAFE_RECEIPT_ID + 1), 2).await?;
    assert!(rotate_stream_epoch(&conn).await.is_err());
    rollback_to_height(&conn, 0).await?;
    let state = stream_state(&conn).await?;
    assert!(state.unsupported);
    assert_eq!(state.max_result_id, 0);
    assert!(recovery_boundary(&conn, &state, 0, 0).await.is_err());
    initialize_receipt_stream(&conn).await?;
    assert!(stream_state(&conn).await?.unsupported);
    let epoch = rotate_stream_epoch(&conn).await?;
    assert_ne!(epoch, original.epoch);
    let rotated = stream_state(&conn).await?;
    assert!(!rotated.unsupported);
    assert_eq!(rotated.generation, 0);
    initialize_receipt_stream(&conn).await?;
    assert_eq!(stream_state(&conn).await?, rotated);
    Ok(())
}
