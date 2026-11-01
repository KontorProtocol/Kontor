use std::sync::Arc;

use anyhow::{Context, Result};
use libsql::{Connection, params};

use crate::protocol::native_bootstrap::{BootstrapRead, BootstrapSnapshot};

async fn stored_field(conn: &Connection, id: u64, path: Vec<u8>) -> Result<Option<Vec<u8>>> {
    let row = conn.query(
        "SELECT value, deleted FROM contract_state WHERE contract_id = ? AND path = ? ORDER BY height DESC LIMIT 1",
        params![id, path],
    ).await?.next().await?;
    match row {
        Some(row) if row.get::<i64>(1)? == 0 => Ok(Some(row.get(0)?)),
        _ => Ok(None),
    }
}

pub(crate) fn bootstrap_reader(conn: &Connection) -> BootstrapRead {
    let conn = conn.clone();
    Arc::new(move |staking_id, floor_path, validators_path| {
        let conn = conn.clone();
        Box::pin(async move {
            read_snapshot(&conn, staking_id, floor_path, validators_path)
                .await
                .map_err(|error| error.to_string())
        })
    })
}

async fn read_snapshot(
    conn: &Connection,
    staking_id: u64,
    floor_path: Vec<u8>,
    validators_path: Vec<u8>,
) -> Result<BootstrapSnapshot> {
    let published_count = conn
        .query(
            "SELECT COUNT(*) FROM contracts WHERE height = 0 AND tx_index = 0",
            (),
        )
        .await?
        .next()
        .await?
        .context("missing publication count")?
        .get(0)?;
    let mut rows = conn.query(
        "SELECT contract_id, func, tx_id, input_index, op_index, result_index, signer_id, payer_signer_id, status FROM contract_results WHERE height = 0 ORDER BY id", (),
    ).await?;
    let mut receipts = Vec::new();
    while let Some(row) = rows.next().await? {
        receipts.push((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
        ));
    }
    Ok((
        published_count,
        receipts,
        stored_field(conn, staking_id, floor_path).await?,
        stored_field(conn, staking_id, validators_path).await?,
    ))
}
