use bitcoin::BlockHash;
use indexer_types::{BlockRow, PaginationMeta};
use libsql::{Connection, Value, de::from_row, params};

use super::Error;
use super::pagination::{PageOptions, get_paginated};
use crate::database::types::BlockQuery;

pub async fn insert_block(conn: &Connection, block: BlockRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT INTO blocks (height, hash, relevant) VALUES (?, ?, ?)",
        (block.height, block.hash.to_string(), block.relevant),
    )
    .await?;
    Ok(conn.last_insert_rowid())
}

pub async fn rollback_to_height(conn: &Connection, height: u64) -> Result<u64, Error> {
    // Clear confirmations by blocks that are about to disappear. The cascade below
    // keys on `height`, not `confirmed_height`, so a BATCH-executed row (whose
    // `height` is its anchor, potentially at or below the target) survives while
    // still pointing at a deleted block — and `confirmed_height` is exactly the
    // predicate the finality verdict reads. Block-path rows cannot be affected:
    // `insert_transaction` sets `height == confirmed_height`, so if one survives the
    // cascade its confirmation is at or below the target too.
    //
    // Restricted to batch rows because they are the only ones affected. The named
    // partial index bounds the work by rollback depth (a range seek over
    // confirmations above the target) instead of a walk of every batch-executed
    // transaction in history; the same index serves the late-confirmation arm of
    // `min_unsettled_batch_tx_height`, which is what tipped the churn-vs-scan
    // trade in its favour.
    conn.execute(
        "UPDATE transactions INDEXED BY idx_transactions_batch_confirmed \
         SET confirmed_height = NULL, tx_index = NULL \
         WHERE batch_height IS NOT NULL AND confirmed_height > ?",
        [height],
    )
    .await?;

    let num_rows = conn
        .execute("DELETE FROM blocks WHERE height > ?", [height])
        .await?;

    Ok(num_rows)
}

/// The highest block height VISIBLE to `conn` — `MAX(height) FROM blocks`, an O(1)
/// index lookup. Unlike [`select_block_latest`] it returns just the height and is
/// used by the `/view` staleness diagnostic to compare a pooled read connection's
/// snapshot against the reactor's committed tip. `None` = the connection sees no
/// blocks (empty table / pre-first-block).
pub async fn max_block_height(conn: &Connection) -> Result<Option<u64>, Error> {
    Ok(
        match conn
            .query("SELECT MAX(height) FROM blocks", params![])
            .await?
            .next()
            .await?
        {
            Some(r) => r.get::<Option<u64>>(0)?,
            None => None,
        },
    )
}

pub async fn select_block_latest(conn: &Connection) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash, relevant FROM blocks ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn select_recent_blocks(conn: &Connection, limit: i64) -> Result<Vec<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash, relevant FROM blocks ORDER BY height DESC LIMIT ?",
            params![limit],
        )
        .await?;
    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(from_row(&row)?);
    }
    Ok(results)
}

pub async fn select_block_by_height_or_hash(
    conn: &Connection,
    identifier: &str,
) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash, relevant FROM blocks WHERE height = ? OR hash = ?",
            params![identifier, identifier],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn select_block_at_height(
    conn: &Connection,
    height: u64,
) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash, relevant FROM blocks WHERE height = ?",
            params![height],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn select_block_with_hash(
    conn: &Connection,
    hash: &BlockHash,
) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash, relevant FROM blocks WHERE hash = ?",
            params![hash.to_string()],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_blocks_paginated(
    conn: &Connection,
    query: BlockQuery,
) -> Result<(Vec<BlockRow>, PaginationMeta), Error> {
    let var = "b";
    let mut where_clauses = vec![];
    let mut params = vec![];
    if let Some(relevant) = query.relevant {
        where_clauses.push("b.relevant = :relevant".to_string());
        params.push((":relevant".to_string(), Value::from(relevant)));
    }
    get_paginated(
        conn,
        var,
        "b.height, b.hash, b.relevant",
        &format!("blocks {}", var),
        where_clauses,
        params,
        PageOptions {
            order: query.order,
            cursor: query.cursor,
            offset: query.offset,
            limit: query.limit,
        },
    )
    .await
}
