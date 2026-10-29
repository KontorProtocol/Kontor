use anyhow::{Context, Result};
use indexer_types::{BlockRow, TransactionRow};
use libsql::{Builder, Connection, params};
use tempfile::TempDir;

use super::{
    get_confirmation_position, initialize_confirmation_metadata, set_confirmation_position,
};
use crate::database::connection::new_connection;
use crate::database::queries::{
    confirm_transaction, get_transaction_by_txid, insert_batch, insert_block, insert_transaction,
    rollback_to_height,
};
use crate::test_utils::new_mock_block_hash;

async fn legacy_projection(conn: &Connection, txid: &str) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(
        get_transaction_by_txid(conn, txid).await?,
    )?)
}

#[tokio::test]
async fn migration_preserves_legacy_rows_without_inventing_raw_positions() -> Result<()> {
    let db = Builder::new_local(":memory:").build().await?;
    let conn = db.connect()?;
    conn.execute_batch(
        "CREATE TABLE transactions (
           id INTEGER PRIMARY KEY, txid TEXT NOT NULL UNIQUE, height INTEGER NOT NULL,
           confirmed_height INTEGER, tx_index INTEGER, batch_height INTEGER);
         INSERT INTO transactions VALUES (1, 'confirmed', 4, 7, 0, 2);
         INSERT INTO transactions VALUES (2, 'pending', 4, NULL, NULL, 3);",
    )
    .await?;
    let confirmed = legacy_projection(&conn, "confirmed").await?;
    let pending = legacy_projection(&conn, "pending").await?;
    initialize_confirmation_metadata(&conn).await?;
    assert_eq!(get_confirmation_position(&conn, "confirmed").await?, None);
    assert_eq!(get_confirmation_position(&conn, "pending").await?, None);
    set_confirmation_position(&conn, "confirmed", 7, 9).await?;
    initialize_confirmation_metadata(&conn).await?;
    assert_eq!(
        get_confirmation_position(&conn, "confirmed").await?,
        Some(9)
    );
    assert_eq!(legacy_projection(&conn, "confirmed").await?, confirmed);
    assert_eq!(legacy_projection(&conn, "pending").await?, pending);
    assert!(
        set_confirmation_position(&conn, "pending", 4, 0)
            .await
            .is_err()
    );
    assert!(
        set_confirmation_position(&conn, "missing", 7, 0)
            .await
            .is_err()
    );
    assert!(
        set_confirmation_position(&conn, "confirmed", 8, 0)
            .await
            .is_err()
    );
    assert_eq!(
        get_confirmation_position(&conn, "confirmed").await?,
        Some(9)
    );
    set_confirmation_position(&conn, "confirmed", 7, u32::MAX).await?;
    assert_eq!(
        get_confirmation_position(&conn, "confirmed").await?,
        Some(u32::MAX)
    );
    for invalid in [-1_i64, i64::from(u32::MAX) + 1] {
        assert!(
            conn.execute(
                "UPDATE transactions SET confirmed_bitcoin_tx_index = ? WHERE txid = 'confirmed'",
                params![invalid],
            )
            .await
            .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn legacy_confirmation_changes_invalidate_position_and_rollback_atomically() -> Result<()> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "positions.db").await?;
    for height in 1..=3 {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .relevant(true)
                .build(),
        )
        .await?;
    }
    insert_batch(&conn, 1, 1, &new_mock_block_hash(1).to_string(), &[], true).await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .batch_height(1)
            .txid("batched".into())
            .build(),
    )
    .await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(3)
            .confirmed_height(3)
            .tx_index(1)
            .txid("block-only".into())
            .build(),
    )
    .await?;
    confirm_transaction(&conn, "batched", 2, 0).await?;
    set_confirmation_position(&conn, "batched", 2, 7).await?;
    let before = legacy_projection(&conn, "batched").await?;
    conn.execute_batch("SAVEPOINT confirmation_test").await?;
    confirm_transaction(&conn, "batched", 3, 1).await?;
    assert_eq!(get_confirmation_position(&conn, "batched").await?, None);
    set_confirmation_position(&conn, "batched", 3, 11).await?;
    conn.execute_batch("ROLLBACK TO confirmation_test; RELEASE confirmation_test")
        .await?;
    assert_eq!(get_confirmation_position(&conn, "batched").await?, Some(7));
    assert_eq!(legacy_projection(&conn, "batched").await?, before);

    set_confirmation_position(&conn, "block-only", 3, 12).await?;
    rollback_to_height(&conn, 1).await?;
    let surviving = get_transaction_by_txid(&conn, "batched")
        .await?
        .context("batch execution must survive confirmation rollback")?;
    assert_eq!(surviving.height, 1);
    assert_eq!(surviving.batch_height, Some(1));
    assert_eq!(surviving.confirmed_height, None);
    assert_eq!(surviving.tx_index, None);
    assert_eq!(get_confirmation_position(&conn, "batched").await?, None);
    assert!(
        get_transaction_by_txid(&conn, "block-only")
            .await?
            .is_none()
    );
    insert_block(
        &conn,
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(22))
            .relevant(true)
            .build(),
    )
    .await?;
    confirm_transaction(&conn, "batched", 2, 1).await?;
    set_confirmation_position(&conn, "batched", 2, 13).await?;
    assert_eq!(get_confirmation_position(&conn, "batched").await?, Some(13));
    let reconfirmed = get_transaction_by_txid(&conn, "batched").await?.unwrap();
    assert_eq!(reconfirmed.height, surviving.height);
    assert_eq!(reconfirmed.batch_height, surviving.batch_height);
    assert_eq!(reconfirmed.tx_index, Some(1));
    Ok(())
}
