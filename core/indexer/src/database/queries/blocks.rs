use bitcoin::BlockHash;
use indexer_types::{BlockRow, PaginationMeta};
use libsql::{Connection, Value, de::from_row, params};

use super::Error;
use super::pagination::get_paginated;
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
    let num_rows = conn
        .execute("DELETE FROM blocks WHERE height > ?", [height])
        .await?;

    Ok(num_rows)
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
    height: i64,
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
        query.order,
        query.cursor,
        query.offset,
        query.limit,
    )
    .await
}
