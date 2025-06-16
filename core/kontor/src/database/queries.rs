use bitcoin::BlockHash;
use libsql::{Connection, de::from_row, params};
use thiserror::Error as ThisError;

use crate::database::types::{
    PaginationMeta, TransactionCursor, TransactionResponse, TransactionRow, TransactionRowWithMeta,
};

use super::types::{BlockRow, ContractStateRow};

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("LibSQL error: {0}")]
    LibSQL(#[from] libsql::Error),
    #[error("Row deserialization error: {0}")]
    RowDeserialization(#[from] serde::de::value::Error),
    #[error("Invalid cursor: {0}")]
    InvalidCursor(#[from] crate::database::types::Error),
}

pub async fn insert_block(conn: &Connection, block: BlockRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT OR REPLACE INTO blocks (height, hash) VALUES (?, ?)",
        (block.height, block.hash.to_string()),
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
            "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
            params![],
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
            "SELECT height, hash FROM blocks WHERE height = ?",
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
            "SELECT height, hash FROM blocks WHERE hash = ?",
            params![hash.to_string()],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn insert_contract_state(conn: &Connection, row: ContractStateRow) -> Result<i64, Error> {
    conn.execute(
        r#"
            INSERT OR REPLACE INTO contract_state (
                contract_id,
                tx_id,
                height,
                path,
                value,
                deleted
            ) VALUES (?, ?, ?, ?, ?, ?)
        "#,
        params![
            row.contract_id,
            row.tx_id,
            row.height,
            row.path,
            row.value,
            row.deleted
        ],
    )
    .await?;

    Ok(conn.last_insert_rowid())
}

pub async fn get_latest_contract_state(
    conn: &Connection,
    contract_id: &str,
    path: &str,
) -> Result<Option<ContractStateRow>, Error> {
    let mut rows = conn
        .query(
            r#"
                SELECT
                    id,
                    contract_id,
                    tx_id,
                    height,
                    path,
                    value,
                    deleted
                FROM contract_state
                WHERE contract_id = ? AND path = ?
                ORDER BY height DESC
                LIMIT 1
            "#,
            params![contract_id, path],
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn insert_transaction(conn: &Connection, row: TransactionRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT INTO transactions (height, txid, tx_index) VALUES (?, ?, ?)",
        params![row.height, row.txid, row.tx_index],
    )
    .await?;

    Ok(conn.last_insert_rowid())
}

pub async fn get_transaction_by_id(
    conn: &Connection,
    id: i64,
) -> Result<Option<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, txid, height, tx_index FROM transactions WHERE id = ?",
            params![id],
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_transaction_by_txid(
    conn: &Connection,
    txid: &str,
) -> Result<Option<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, txid, height, tx_index FROM transactions WHERE txid = ?",
            params![txid],
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_transactions_at_height(
    conn: &Connection,
    height: u64,
) -> Result<Vec<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, txid, height, tx_index FROM transactions WHERE height = ?",
            params![height],
        )
        .await?;

    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(from_row(&row)?);
    }
    Ok(results)
}

pub async fn get_transactions_paginated(
    conn: &Connection,
    height: Option<u64>,
    cursor: Option<String>,
    offset: Option<u64>,
    limit: u32,
) -> Result<(Vec<TransactionResponse>, PaginationMeta), Error> {
    let mut params = Vec::new();
    let mut where_clauses = Vec::new();

    // Build height filter
    if let Some(h) = height {
        where_clauses.push("t.height = ?");
        params.push(libsql::Value::Integer(h as i64));
    }

    // Build cursor filter
    if let Some(c) = cursor.clone() {
        let cursor = TransactionCursor::decode(&c).map_err(Error::InvalidCursor)?;
        where_clauses.push("(t.height, t.tx_index) < (?, ?)");
        params.push(libsql::Value::Integer(cursor.height as i64));
        params.push(libsql::Value::Integer(cursor.tx_index as i64));
    }

    // Build WHERE clause
    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    // Get total count first
    let count_query = format!("SELECT COUNT(*) FROM transactions t {}", where_sql);
    let mut count_rows = conn.query(&count_query, params.clone()).await?;
    let total_count = count_rows
        .next()
        .await?
        .map(|r| r.get::<i64>(0))
        .transpose()?;

    // Build OFFSET clause
    let offset_clause = cursor
        .is_none()
        .then_some(offset)
        .flatten()
        .map_or(String::new(), |val| format!("OFFSET {}", val));

    // Main query for transactions
    let query = format!(
        r#"
        SELECT t.txid, t.height, t.tx_index
        FROM transactions t
        {where_sql}
        ORDER BY t.height DESC, t.tx_index DESC
        LIMIT {}
        {offset_clause}
        "#,
        limit + 1,
        where_sql = where_sql,
        offset_clause = offset_clause
    );

    let mut rows = conn.query(&query, params).await?;

    let mut transactions: Vec<TransactionResponse> = Vec::new();
    while let Some(row) = rows.next().await? {
        transactions.push(from_row(&row)?);
    }

    let has_more = transactions.len() > limit as usize;
    if has_more {
        transactions.pop();
    }

    let next_cursor = if offset.is_none() && has_more && !transactions.is_empty() {
        let last_tx = transactions.last().unwrap();
        let cursor = TransactionCursor {
            height: last_tx.height,
            tx_index: last_tx.tx_index,
        };
        Some(cursor.encode())
    } else {
        None
    };

    let next_offset = if cursor.is_none() {
        match offset {
            Some(current_offset) if has_more => Some(current_offset + limit as u64),
            None if has_more => Some(limit as u64),
            _ => None,
        }
    } else {
        None
    };

    let pagination_meta = PaginationMeta {
        next_cursor,
        next_offset,
        has_more,
        total_count: total_count.map(|c| c as u64),
    };

    Ok((transactions, pagination_meta))
}
