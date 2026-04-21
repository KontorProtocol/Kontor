use indexer_types::{PaginationMeta, TransactionRow};
use libsql::{Connection, Value, de::from_row, params};

use super::Error;
use super::batches::delete_unconfirmed_batch_tx;
use super::contracts::get_contract_id_from_address;
use super::pagination::get_paginated;
use crate::database::types::TransactionQuery;

pub async fn insert_transaction(conn: &Connection, row: TransactionRow) -> Result<i64, Error> {
    conn.execute(
        "INSERT INTO transactions (height, txid, confirmed_height, tx_index, batch_height) VALUES (?, ?, ?, ?, ?)",
        params![row.height, row.txid, row.confirmed_height, row.tx_index, row.batch_height],
    )
    .await?;
    Ok(conn.last_insert_rowid())
}

pub async fn confirm_transaction(
    conn: &Connection,
    txid: &str,
    confirmed_height: i64,
    tx_index: i64,
) -> Result<(), Error> {
    conn.execute(
        "UPDATE transactions SET confirmed_height = ?, tx_index = ? WHERE txid = ?",
        params![confirmed_height, tx_index, txid],
    )
    .await?;
    delete_unconfirmed_batch_tx(conn, txid).await?;
    Ok(())
}

pub async fn get_transaction_by_txid(
    conn: &Connection,
    txid: &str,
) -> Result<Option<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, txid, height, confirmed_height, tx_index, batch_height FROM transactions WHERE txid = ?",
            params![txid],
        )
        .await?;

    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_transactions_at_height(
    conn: &Connection,
    height: i64,
) -> Result<Vec<TransactionRow>, Error> {
    let mut rows = conn
        .query(
            "SELECT id, txid, height, confirmed_height, tx_index, batch_height FROM transactions WHERE height = ?",
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
    query: TransactionQuery,
) -> Result<(Vec<TransactionRow>, PaginationMeta), Error> {
    let mut params: Vec<(String, Value)> = Vec::new();
    let var = "t";
    let mut selects =
        "t.id, t.txid, t.height, t.confirmed_height, t.tx_index, t.batch_height".to_string();
    let mut from = "transactions t".to_string();
    let mut where_clauses = vec![];
    if let Some(address) = &query.contract {
        let contract_id = get_contract_id_from_address(conn, address)
            .await?
            .ok_or(Error::ContractNotFound(address.to_string()))?;
        selects = format!("DISTINCT {}", selects);
        from = format!("{} JOIN contract_state c ON c.tx_id = t.id", from);
        where_clauses.push(format!("c.contract_id = {}", contract_id));
    }

    if let Some(height) = query.height {
        where_clauses.push("t.height = :height".to_string());
        params.push((":height".to_string(), Value::Integer(height)));
    }

    get_paginated(
        conn,
        var,
        &selects,
        &from,
        where_clauses,
        params,
        query.order,
        query.cursor,
        query.offset,
        query.limit,
    )
    .await
}

/// Return the subset of `txids` that already exist in the transactions table.
pub async fn select_existing_txids(
    conn: &Connection,
    txids: &[String],
) -> Result<std::collections::HashSet<String>, Error> {
    if txids.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let placeholders: Vec<&str> = txids.iter().map(|_| "?").collect();
    let sql = format!(
        "SELECT txid FROM transactions WHERE txid IN ({})",
        placeholders.join(", ")
    );
    let params: Vec<libsql::Value> = txids
        .iter()
        .map(|t| libsql::Value::from(t.clone()))
        .collect();
    let mut rows = conn
        .query(&sql, libsql::params::Params::Positional(params))
        .await?;
    let mut result = std::collections::HashSet::new();
    while let Some(row) = rows.next().await? {
        let txid: String = row.get(0)?;
        result.insert(txid);
    }
    Ok(result)
}
