use bitcoin::BlockHash;
use libsql::{Connection, de::from_row, params};
use thiserror::Error as ThisError;

use crate::database::types::{
    PaginationMeta, TransactionCursor, TransactionRow, TransactionRowWithPagination,
};

use super::types::{BlockRow, ContractStateRow};

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("LibSQL error: {0}")]
    LibSQL(#[from] libsql::Error),
    #[error("Row deserialization error: {0}")]
    RowDeserialization(#[from] serde::de::value::Error),
    #[error("Invalid cursor format")]
    InvalidCursor,
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

pub async fn select_block_by_height_or_hash(
    conn: &Connection,
    identifier: &str,
) -> Result<Option<BlockRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT height, hash FROM blocks WHERE height = ? OR hash = ?",
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
) -> Result<(Vec<TransactionRow>, PaginationMeta), Error> {
    let mut params = Vec::new();
    let mut where_clauses = Vec::new();

    // Build height filter
    if let Some(h) = height {
        where_clauses.push("t.height = ?");
        params.push(libsql::Value::Integer(h as i64));
    }

    // Build cursor filter
    if let Some(c) = cursor.clone() {
        let cursor = TransactionCursor::decode(&c).map_err(|_| Error::InvalidCursor)?;
        where_clauses.push("(t.height, t.tx_index) <= (?, ?)");
        params.push(libsql::Value::Integer(cursor.height as i64));
        params.push(libsql::Value::Integer(cursor.tx_index as i64));
    }

    // Build WHERE clause
    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    // Build OFFSET clause
    let offset_clause = cursor
        .is_none()
        .then_some(offset)
        .flatten()
        .map_or(String::new(), |val| format!("OFFSET {}", val));

    // Conditionally include LEAD columns based on pagination type
    let select_columns = if offset.is_none() {
        // Using cursor pagination - include LEAD for next cursor
        "t.id, t.txid, t.height, t.tx_index, LEAD(t.height) OVER (ORDER BY t.height DESC, t.tx_index DESC) as next_height, LEAD(t.tx_index) OVER (ORDER BY t.height DESC, t.tx_index DESC) as next_tx_index, COUNT(*) OVER() as total_count"
    } else {
        // Using offset pagination - no need for LEAD
        "t.id, t.txid, t.height, t.tx_index, NULL as next_height, NULL as next_tx_index, COUNT(*) OVER() as total_count"
    };

    let query = format!(
        r#"
    SELECT {select_columns}
        FROM transactions t
        {where_sql}
        ORDER BY t.height DESC, t.tx_index DESC
    LIMIT {}
    {offset_clause}
    "#,
        limit + 1,
        select_columns = select_columns,
        where_sql = where_sql,
        offset_clause = offset_clause
    );

    let mut rows = conn.query(&query, params).await?;

    let mut transaction_rows_with_pagination: Vec<TransactionRowWithPagination> = Vec::new();
    while let Some(row) = rows.next().await? {
        transaction_rows_with_pagination.push(from_row(&row)?);
    }
    let mut transactions: Vec<TransactionRow> = transaction_rows_with_pagination
        .iter()
        .map(TransactionRow::from_transaction_row_with_pagination)
        .collect();

    let has_more = transactions.len() > limit as usize;

    // Capture the cursor BEFORE popping - this is the first transaction of the next page
    let next_cursor = if offset.is_none() && has_more {
        transaction_rows_with_pagination
            .get(limit as usize)
            .map(|r| TransactionCursor::from_transaction_row_with_pagination(r).encode())
    } else {
        None
    };

    if has_more {
        transactions.pop();
    }

    let next_offset = (cursor.is_none() && has_more)
        .then(|| offset.map_or(limit as u64, |current| current + limit as u64));

    let total_count = transaction_rows_with_pagination
        .first()
        .map_or(0, |r| r.total_count);

    let pagination = PaginationMeta {
        next_cursor,
        next_offset,
        has_more,
        total_count,
    };

    Ok((transactions, pagination))
}
