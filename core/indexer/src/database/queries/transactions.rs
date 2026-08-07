use indexer_types::{PaginationMeta, TransactionRow};
use libsql::{Connection, Value, de::from_row, params};

use super::Error;
use super::batches::delete_unconfirmed_batch_tx;
use super::contracts::get_contract_id_from_address;
use super::pagination::{PageOptions, get_paginated};
use crate::database::types::TransactionQuery;

pub async fn insert_transaction(conn: &Connection, row: TransactionRow) -> Result<u64, Error> {
    let txid = row.txid.clone();
    let confirmed = row.confirmed_height.is_some();
    conn.execute(
        "INSERT INTO transactions (height, txid, confirmed_height, tx_index, batch_height) VALUES (?, ?, ?, ?, ?)",
        params![
            row.height,
            row.txid,
            row.confirmed_height.map(Value::try_from).transpose()?,
            row.tx_index,
            row.batch_height.map(Value::try_from).transpose()?,
        ],
    )
    .await?;
    // Captured before the delete below. `last_insert_rowid` tracks INSERTs only, so a
    // DELETE would not disturb it — but reading it first means that never has to be
    // re-derived by whoever edits this next.
    let tx_id = conn.last_insert_rowid() as u64;
    // Inserted ALREADY CONFIRMED means the transaction is on chain and indexed, so
    // the raw copy kept for sync is redundant — same rule `confirm_transaction`
    // applies when it moves an existing row to confirmed. Without it a record-only
    // batch (which stores raw txs but writes no `transactions` row) leaks one full
    // transaction body per txid forever: the confirming block takes this branch, not
    // `confirm_transaction`, so nothing ever deleted it.
    //
    // Gated on `confirmed_height`, not unconditional: the batch-execution path
    // inserts with `confirmed_height = None`, and its raw copy is exactly what a
    // replay or a syncing peer still needs.
    if confirmed {
        delete_unconfirmed_batch_tx(conn, &txid).await?;
    }
    Ok(tx_id)
}

pub async fn confirm_transaction(
    conn: &Connection,
    txid: &str,
    confirmed_height: u64,
    tx_index: u32,
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
    height: u64,
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
    let mut needs_distinct = false;

    if let Some(address) = &query.contract {
        let contract_id = get_contract_id_from_address(conn, address)
            .await?
            .ok_or(Error::ContractNotFound(address.to_string()))?;
        needs_distinct = true;
        from = format!("{} JOIN contract_state c ON c.tx_id = t.id", from);
        where_clauses.push(format!("c.contract_id = {}", contract_id));
    }

    if let Some(signer_id) = query.signer_id {
        // contract_results carries the per-op signer (set by execute_op),
        // including per-input signer for aggregated/bulk transactions —
        // so this captures "transactions a user was involved in" via any
        // op that produced a result.
        needs_distinct = true;
        from = format!("{} JOIN contract_results r ON r.tx_id = t.id", from);
        where_clauses.push("r.signer_id = :signer_id".to_string());
        params.push((":signer_id".to_string(), Value::try_from(signer_id)?));
    }

    if needs_distinct {
        selects = format!("DISTINCT {}", selects);
    }

    if let Some(height) = query.height {
        where_clauses.push("t.height = :height".to_string());
        params.push((":height".to_string(), Value::try_from(height)?));
    }

    get_paginated(
        conn,
        var,
        &selects,
        &from,
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

/// Bound placeholders per `txid IN (?…)` statement. SQLite's compile-time
/// `SQLITE_MAX_VARIABLE_NUMBER` is 32766 and exceeding it fails at PREPARE, so an
/// unchunked list is a crash, not a slow query. The largest caller is `make_value`,
/// which passes the entire mempool pool — bounded by bitcoind, not by anything
/// Kontor controls — so the chunking has to live here rather than at a call site.
const TXID_PROBE_CHUNK: usize = 900;

/// Rows in the transactions table for any of `txids`, keyed by txid.
///
/// One statement per chunk; absent txids are simply absent from the map.
pub async fn select_transactions_by_txids(
    conn: &Connection,
    txids: &[String],
) -> Result<std::collections::HashMap<String, TransactionRow>, Error> {
    let mut result = std::collections::HashMap::new();
    for chunk in txids.chunks(TXID_PROBE_CHUNK) {
        let placeholders: Vec<&str> = chunk.iter().map(|_| "?").collect();
        let sql = format!(
            "SELECT id, txid, height, confirmed_height, tx_index, batch_height \
             FROM transactions WHERE txid IN ({})",
            placeholders.join(", ")
        );
        let params: Vec<Value> = chunk.iter().map(|t| Value::from(t.clone())).collect();
        let mut rows = conn
            .query(&sql, libsql::params::Params::Positional(params))
            .await?;
        while let Some(row) = rows.next().await? {
            let parsed: TransactionRow = from_row(&row)?;
            result.insert(parsed.txid.clone(), parsed);
        }
    }
    Ok(result)
}

/// Return the subset of `txids` that already exist in the transactions table.
pub async fn select_existing_txids(
    conn: &Connection,
    txids: &[String],
) -> Result<std::collections::HashSet<String>, Error> {
    Ok(select_transactions_by_txids(conn, txids)
        .await?
        .into_keys()
        .collect())
}

/// Lowest anchor height of a batch-executed transaction that is not SETTLED —
/// meaning it did not confirm on Bitcoin by its batch's deadline.
///
/// "Settled" must mean exactly what the finality verdict means. Testing only for
/// `confirmed_height IS NULL` would treat a LATE confirmation as settled, when
/// finality still counts it missing and still owes that batch a rollback. A batch
/// row's `height` IS its anchor, so its deadline is `height + finality_window` and
/// no join is needed.
///
/// Two callers, both of which need the finality notion: the startup floor extension
/// (how far below the window rehydration must reach to pick up a batch whose verdict
/// was never rendered) and the divergence probe.
pub async fn min_unsettled_batch_tx_height(
    conn: &Connection,
    finality_window: u64,
) -> Result<Option<u64>, Error> {
    Ok(
        match conn
            .query(
                "SELECT MIN(height) FROM transactions \
                 WHERE batch_height IS NOT NULL \
                   AND (confirmed_height IS NULL OR confirmed_height > height + ?)",
                params![finality_window],
            )
            .await?
            .next()
            .await?
        {
            Some(row) => row.get::<Option<u64>>(0)?,
            None => None,
        },
    )
}
