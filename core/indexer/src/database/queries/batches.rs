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

/// Recorded exclusions that STILL HOLD, keyed by the consensus height they apply to.
///
/// The stored row is a node-local fact: "we found T missing at H's deadline". The
/// `NOT EXISTS` is the shared, node-independent half — the same predicate
/// `missing_txids` renders (I2) — and it is baked into the READ so that no caller can
/// apply a row without re-verifying it. There is deliberately no DELETE: a replay can
/// never manufacture a Bitcoin confirmation, so suppression can only ever come from
/// the chain, and keeping the row lets a later reorg re-suppress or re-apply it.
///
/// The `batch_height` qualifier on the confirmation is load-bearing. Without it: T is
/// excluded at H, re-batched and executed at H3, and confirms at or below H's
/// deadline; a deep rollback replays both; the row is suppressed; H and H3 BOTH
/// execute T, and `insert_transaction` is a plain INSERT against
/// `transactions.txid UNIQUE` — the #515 collision from a new direction. A
/// confirmation attributable to another batch's execution must not un-exclude here. A
/// confirmation via the BLOCK path (`batch_height IS NULL`) must, and does: that is
/// the reorg-healing case, and a peer syncing from genesis reaches the same answer.
pub async fn select_applicable_exclusions(
    conn: &Connection,
) -> Result<std::collections::HashMap<u64, std::collections::HashSet<String>>, Error> {
    let mut rows = conn
        .query(
            "SELECT e.batch_height, e.txid \
             FROM excluded_batch_txids e \
             WHERE NOT EXISTS ( \
               SELECT 1 FROM transactions t \
                WHERE t.txid = e.txid \
                  AND t.confirmed_height IS NOT NULL \
                  AND t.confirmed_height <= e.deadline \
                  AND (t.batch_height IS NULL OR t.batch_height = e.batch_height))",
            (),
        )
        .await?;
    let mut out: std::collections::HashMap<u64, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    while let Some(row) = rows.next().await? {
        out.entry(row.get::<u64>(0)?)
            .or_default()
            .insert(row.get::<String>(1)?);
    }
    Ok(out)
}

/// Record what a finality pass dropped, as `(consensus_height, txid, deadline)`.
/// Idempotent — the same batch can be narrowed by more than one pass.
pub async fn insert_excluded_batch_txids(
    conn: &Connection,
    rows: &[(u64, String, u64)],
) -> Result<(), Error> {
    for (batch_height, txid, deadline) in rows {
        conn.execute(
            "INSERT OR IGNORE INTO excluded_batch_txids (batch_height, txid, deadline) \
             VALUES (?, ?, ?)",
            params![*batch_height, txid.clone(), *deadline],
        )
        .await?;
    }
    Ok(())
}

/// Executed, still-unfinalized batches anchored at or above `from_anchor`, with the
/// txids this node ACTUALLY executed for each — for rebuilding finality tracking
/// after a restart.
///
/// Sourced from `transactions`, deliberately NOT from `batch_txids`. The certified
/// list is append-only (`INSERT OR IGNORE` on `(batch_height, position)`, no cascade),
/// so once a replay has dropped excluded transactions from a batch the stored list
/// still holds them, permanently. Rehydrating from it would re-arm a deadline on
/// txids this node deliberately dropped and trigger a rollback no peer performs.
/// The join also subsumes an "did we execute this batch" existence check: record-only
/// batches write no `transactions` rows and rolled-back ones have theirs cascade-deleted.
pub async fn select_unfinalized_batches(
    conn: &Connection,
    from_anchor: u64,
) -> Result<Vec<BatchQueryResult>, Error> {
    let sql = format!(
        "SELECT b.consensus_height, b.anchor_height, b.anchor_hash, b.certificate, t.txid \
         FROM batches b INDEXED BY idx_batches_anchor_height \
         JOIN blocks bl ON bl.height = b.anchor_height AND bl.hash = b.anchor_hash \
         JOIN executed_batch_txids t ON t.batch_height = b.consensus_height \
         WHERE b.anchor_height >= {from_anchor} AND b.is_block = 0 \
         ORDER BY b.consensus_height, t.id"
    );
    let mut rows = conn.query(&sql, ()).await?;

    let mut results: Vec<BatchQueryResult> = Vec::new();
    while let Some(row) = rows.next().await? {
        let consensus_height: u64 = row.get(0)?;
        let txid: String = row.get(4)?;
        if results
            .last()
            .is_some_and(|r| r.consensus_height == consensus_height)
        {
            results.last_mut().unwrap().txids.push(txid);
        } else {
            results.push(BatchQueryResult {
                consensus_height,
                anchor_height: row.get(1)?,
                anchor_hash: row.get(2)?,
                certificate: row.get(3)?,
                is_block: false,
                txids: vec![txid],
            });
        }
    }
    Ok(results)
}
