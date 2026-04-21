use libsql::{Connection, params};

use super::Error;
use crate::database::types::BatchQueryResult;

pub async fn insert_batch(
    conn: &Connection,
    consensus_height: i64,
    anchor_height: i64,
    anchor_hash: &str,
    certificate: &[u8],
    is_block: bool,
) -> Result<(), Error> {
    conn.execute(
        "INSERT OR IGNORE INTO batches (consensus_height, anchor_height, anchor_hash, certificate, is_block) VALUES (?, ?, ?, ?, ?)",
        params![consensus_height, anchor_height, anchor_hash, certificate, is_block as i64],
    )
    .await?;
    Ok(())
}

pub async fn delete_batches_above_anchor(conn: &Connection, max_anchor: i64) -> Result<u64, Error> {
    let rows = conn
        .execute(
            "DELETE FROM batches WHERE anchor_height > ?",
            params![max_anchor],
        )
        .await?;

    Ok(rows)
}

pub async fn select_latest_consensus_height(conn: &Connection) -> Result<Option<i64>, Error> {
    Ok(conn
        .query("SELECT MAX(consensus_height) FROM batches", ())
        .await?
        .next()
        .await?
        .and_then(|row| row.get(0).ok()))
}

pub async fn select_batch(
    conn: &Connection,
    consensus_height: i64,
) -> Result<Option<BatchQueryResult>, Error> {
    let results = query_batches(
        conn,
        &format!("WHERE b.consensus_height = {consensus_height}"),
    )
    .await?;
    Ok(results.into_iter().next())
}

pub async fn select_min_batch_height(conn: &Connection) -> Result<Option<i64>, Error> {
    let mut rows = conn
        .query("SELECT MIN(consensus_height) FROM batches", params![])
        .await?;

    let Some(row) = rows.next().await? else {
        return Ok(None);
    };

    Ok(row.get::<Option<i64>>(0)?)
}

pub async fn select_batches_from_anchor(
    conn: &Connection,
    from_anchor: i64,
) -> Result<Vec<BatchQueryResult>, Error> {
    query_batches(conn, &format!("WHERE b.anchor_height >= {from_anchor}")).await
}

pub async fn select_batches_in_range(
    conn: &Connection,
    start: i64,
    end: i64,
) -> Result<Vec<BatchQueryResult>, Error> {
    query_batches(
        conn,
        &format!("WHERE b.consensus_height >= {start} AND b.consensus_height <= {end}"),
    )
    .await
}

async fn query_batches(
    conn: &Connection,
    where_clause: &str,
) -> Result<Vec<BatchQueryResult>, Error> {
    let sql = format!(
        "SELECT b.consensus_height, b.anchor_height, b.anchor_hash, b.is_block, b.certificate, \
                t.txid \
         FROM batches b \
         LEFT JOIN transactions t ON t.batch_height = b.consensus_height \
         {where_clause} \
         ORDER BY b.consensus_height, t.id"
    );
    let mut rows = conn.query(&sql, ()).await?;

    let mut results: Vec<BatchQueryResult> = Vec::new();
    while let Some(row) = rows.next().await? {
        let consensus_height: i64 = row.get(0)?;
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

    Ok(results)
}

pub async fn insert_unconfirmed_batch_tx(
    conn: &Connection,
    txid: &str,
    batch_height: i64,
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
    batch_height: i64,
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
