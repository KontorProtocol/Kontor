use libsql::{Connection, params};

use super::Error;
use crate::database::types::BatchQueryResult;

pub async fn insert_batch(
    conn: &Connection,
    consensus_height: u64,
    anchor_height: u64,
    anchor_hash: &str,
    certificate: &[u8],
    is_block: bool,
) -> Result<(), Error> {
    conn.execute(
        "INSERT OR IGNORE INTO batches (consensus_height, anchor_height, anchor_hash, certificate, is_block) VALUES (?, ?, ?, ?, ?)",
        params![
            consensus_height,
            anchor_height,
            anchor_hash,
            certificate,
            is_block as i64,
        ],
    )
    .await?;
    Ok(())
}

/// The immutable decided txid list for a batch, written at decide time (see
/// schema.sql `batch_txids`). Idempotent per (batch_height, position).
pub async fn insert_batch_txids(
    conn: &Connection,
    batch_height: u64,
    txids: &[String],
) -> Result<(), Error> {
    for (position, txid) in txids.iter().enumerate() {
        conn.execute(
            "INSERT OR IGNORE INTO batch_txids (batch_height, position, txid) VALUES (?, ?, ?)",
            params![batch_height, position as u64, txid.as_str()],
        )
        .await?;
    }
    Ok(())
}

/// Startup cleanup: forget the decided-but-unexecuted SUFFIX of consensus
/// history. `X` is the last consensus height whose anchor this node has
/// actually processed; everything above `X` is deleted (children first — the
/// FKs carry no cascade, deliberately) and re-synced from peers. A suffix,
/// NOT an anchor band: deleting by `anchor_height > ?` punches holes in the
/// consensus-height sequence when anchors are non-monotone across a rollback,
/// and a gap can never be refilled locally. Returns (deleted batches, X).
pub async fn delete_unexecuted_batch_suffix(
    conn: &Connection,
    last_block_height: u64,
) -> Result<(u64, u64), Error> {
    let mut rows = conn
        .query(
            "SELECT COALESCE(MAX(consensus_height), 0) FROM batches WHERE anchor_height <= ?",
            params![last_block_height],
        )
        .await?;
    let x: u64 = match rows.next().await? {
        Some(row) => row.get(0)?,
        None => 0,
    };
    conn.execute(
        "DELETE FROM unconfirmed_batch_txs WHERE batch_height > ?",
        params![x],
    )
    .await?;
    conn.execute("DELETE FROM batch_txids WHERE batch_height > ?", params![x])
        .await?;
    let deleted = conn
        .execute("DELETE FROM batches WHERE consensus_height > ?", params![x])
        .await?;
    Ok((deleted, x))
}

pub async fn select_latest_consensus_height(conn: &Connection) -> Result<Option<u64>, Error> {
    // `SELECT MAX(...)` always yields a row (NULL on empty table). Read the
    // column directly as `Option<u64>` so NULL surfaces as `None` and any
    // decode error propagates instead of being silently swallowed — a lost
    // error here would restart consensus from height 1 and discard all
    // prior batch history. Matches the pattern in `select_min_batch_height`.
    let Some(row) = conn
        .query("SELECT MAX(consensus_height) FROM batches", ())
        .await?
        .next()
        .await?
    else {
        return Ok(None);
    };
    Ok(row.get::<Option<u64>>(0)?)
}

pub async fn select_batch(
    conn: &Connection,
    consensus_height: u64,
) -> Result<Option<BatchQueryResult>, Error> {
    let results = query_batches(
        conn,
        "",
        &format!("WHERE b.consensus_height = {consensus_height}"),
    )
    .await?;
    Ok(results.into_iter().next())
}

pub async fn select_min_batch_height(conn: &Connection) -> Result<Option<u64>, Error> {
    let mut rows = conn
        .query("SELECT MIN(consensus_height) FROM batches", params![])
        .await?;

    let Some(row) = rows.next().await? else {
        return Ok(None);
    };

    Ok(row.get::<Option<u64>>(0)?)
}

pub async fn select_batches_from_anchor(
    conn: &Connection,
    from_anchor: u64,
) -> Result<Vec<BatchQueryResult>, Error> {
    // INDEXED BY: production DBs never run ANALYZE, so without stats the
    // planner full-scans `batches` for this anchor-band filter instead of
    // using the index built for it.
    query_batches(
        conn,
        "INDEXED BY idx_batches_anchor_height",
        &format!("WHERE b.anchor_height >= {from_anchor}"),
    )
    .await
}

pub async fn select_batches_in_range(
    conn: &Connection,
    start: u64,
    end: u64,
) -> Result<Vec<BatchQueryResult>, Error> {
    query_batches(
        conn,
        "",
        &format!("WHERE b.consensus_height >= {start} AND b.consensus_height <= {end}"),
    )
    .await
}

/// Load batches with their CERTIFIED txid lists (`batch_txids`, written at
/// decide time) — not the `transactions` join: execution rows are absent for
/// record-only batches and cascade-deleted by rollbacks, so deriving the
/// served value from them diverges from the certificate. Rows recorded before
/// `batch_txids` existed fall back to the `transactions` join.
async fn query_batches(
    conn: &Connection,
    index_hint: &str,
    where_clause: &str,
) -> Result<Vec<BatchQueryResult>, Error> {
    let sql = format!(
        "SELECT b.consensus_height, b.anchor_height, b.anchor_hash, b.is_block, b.certificate, \
                bt.txid \
         FROM batches b {index_hint} \
         LEFT JOIN batch_txids bt ON bt.batch_height = b.consensus_height \
         {where_clause} \
         ORDER BY b.consensus_height, bt.position"
    );
    let mut rows = conn.query(&sql, ()).await?;

    let mut results: Vec<BatchQueryResult> = Vec::new();
    while let Some(row) = rows.next().await? {
        let consensus_height: u64 = row.get(0)?;
        let txid: Option<String> = row.get(5)?;

        if results
            .last()
            .is_some_and(|r| r.consensus_height == consensus_height)
        {
            if let Some(txid) = txid {
                results.last_mut().unwrap().txids.push(txid);
            }
        } else {
            results.push(BatchQueryResult {
                consensus_height,
                anchor_height: row.get(1)?,
                anchor_hash: row.get(2)?,
                is_block: row.get::<i64>(3)? != 0,
                certificate: row.get(4)?,
                txids: txid.into_iter().collect(),
            });
        }
    }

    // Legacy fallback: batches recorded before the batch_txids table existed
    // have no certified rows — recover their txids from the transactions join
    // (valid only while those execution rows survive, which matched the old
    // serving behavior anyway). One query for all such heights.
    let legacy: Vec<u64> = results
        .iter()
        .filter(|r| !r.is_block && r.txids.is_empty())
        .map(|r| r.consensus_height)
        .collect();
    if !legacy.is_empty() {
        let in_list = legacy
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT batch_height, txid FROM transactions \
             WHERE batch_height IN ({in_list}) ORDER BY batch_height, id"
        );
        let mut rows = conn.query(&sql, ()).await?;
        while let Some(row) = rows.next().await? {
            let height: u64 = row.get(0)?;
            let txid: String = row.get(1)?;
            if let Some(r) = results.iter_mut().find(|r| r.consensus_height == height) {
                r.txids.push(txid);
            }
        }
    }

    Ok(results)
}

pub async fn insert_unconfirmed_batch_tx(
    conn: &Connection,
    txid: &str,
    batch_height: u64,
    raw_tx: &[u8],
) -> Result<(), Error> {
    conn.execute(
        "INSERT OR IGNORE INTO unconfirmed_batch_txs (txid, batch_height, raw_tx) VALUES (?, ?, ?)",
        params![txid, batch_height, raw_tx],
    )
    .await?;
    Ok(())
}

pub async fn delete_unconfirmed_batch_tx(conn: &Connection, txid: &str) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM unconfirmed_batch_txs WHERE txid = ?",
        params![txid],
    )
    .await?;
    Ok(())
}

pub async fn select_unconfirmed_batch_txs(
    conn: &Connection,
    batch_height: u64,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            "SELECT raw_tx FROM unconfirmed_batch_txs WHERE batch_height = ?",
            params![batch_height],
        )
        .await?;
    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        let raw_tx: Vec<u8> = row.get(0)?;
        results.push(raw_tx);
    }
    Ok(results)
}

pub async fn select_unconfirmed_batch_tx(
    conn: &Connection,
    txid: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let mut rows = conn
        .query(
            "SELECT raw_tx FROM unconfirmed_batch_txs WHERE txid = ?",
            params![txid],
        )
        .await?;
    Ok(rows
        .next()
        .await?
        .map(|row| row.get::<Vec<u8>>(0))
        .transpose()?)
}
