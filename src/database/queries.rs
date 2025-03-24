use anyhow::Result;
use bitcoin::BlockHash;
use libsql::{Connection, de::from_row, params};

use super::types::BlockRow;

pub async fn insert_block(conn: &Connection, block: BlockRow) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO blocks (height, hash) VALUES (?, ?)",
        (block.height, block.hash.to_string()),
    )
    .await?;
    Ok(())
}

pub async fn rollback_to_height(conn: &Connection, height: u64) -> Result<u64> {
    let num_rows = conn
        .execute("DELETE FROM blocks WHERE height > ?", [height])
        .await?;

    Ok(num_rows)
}

pub async fn select_block_latest(conn: &Connection) -> Result<Option<BlockRow>> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;
    Ok(match rows.next().await? {
        Some(row) => Some(from_row::<BlockRow>(&row)?),
        None => None,
    })
}

pub async fn select_block_at_height(conn: &Connection, height: u64) -> Result<Option<BlockRow>> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks WHERE height = ?",
            params![height],
        )
        .await?;
    Ok(match rows.next().await? {
        Some(row) => Some(from_row::<BlockRow>(&row)?),
        None => None,
    })
}

pub async fn select_block_with_hash(
    conn: &Connection,
    hash: &BlockHash,
) -> Result<Option<BlockRow>> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks WHERE hash = ?",
            params![hash.to_string()],
        )
        .await?;
    Ok(match rows.next().await? {
        Some(row) => Some(from_row::<BlockRow>(&row)?),
        None => None,
    })
}
