use anyhow::Result;
use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use libsql::{Builder, Connection, params};
use tempfile::TempDir;
use tokio::fs;

use super::{ConfirmationBackfillArgs, run};
use crate::database::init::CREATE_SCHEMA;

async fn snapshot(conn: &Connection) -> Result<Vec<(String, Vec<Vec<String>>)>> {
    let mut tables = conn.query(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name", (),
    ).await?;
    let mut result = Vec::new();
    while let Some(row) = tables.next().await? {
        let name: String = row.get(0)?;
        let projection = if name == "transactions" {
            "id, txid, height, confirmed_height, tx_index, batch_height"
        } else {
            "*"
        };
        let quoted = name.replace('"', "\"\"");
        let mut rows = conn
            .query(&format!("SELECT {projection} FROM \"{quoted}\""), ())
            .await?;
        let columns = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(
                (0..columns)
                    .map(|i| Ok(format!("{:?}", row.get_value(i)?)))
                    .collect::<libsql::Result<Vec<_>>>()?,
            );
        }
        values.sort();
        result.push((name, values));
    }
    Ok(result)
}

async fn schema(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut rows = conn.query(
        "SELECT name, sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT IN
         ('transactions', 'idx_transactions_confirmation_height', 'invalidate_confirmation_position') ORDER BY name", (),
    ).await?;
    let mut result = Vec::new();
    while let Some(row) = rows.next().await? {
        result.push((row.get(0)?, row.get(1)?));
    }
    Ok(result)
}

#[tokio::test]
async fn command_migrates_legacy_metadata_without_general_node_initialization() -> Result<()> {
    let dir = TempDir::new()?;
    let path = dir.path().join("node.db");
    let db = Builder::new_local(&path).build().await?;
    let conn = db.connect()?;
    conn.execute_batch(CREATE_SCHEMA).await?;
    let block = genesis_block(Network::Regtest);
    let txid = block.txdata[0].compute_txid().to_string();
    conn.execute(
        "INSERT INTO blocks VALUES (0, ?, 1)",
        params![block.block_hash().to_string()],
    )
    .await?;
    conn.execute("INSERT INTO transactions (id, txid, height, confirmed_height, tx_index) VALUES (1, ?, 0, 0, 0)", params![txid]).await?;
    conn.execute("INSERT INTO node_meta VALUES ('preserve', X'001122')", ())
        .await?;
    let before = snapshot(&conn).await?;
    let schema_before = schema(&conn).await?;
    let raw = dir.path().join("block.bin");
    fs::write(&raw, serialize(&block)).await?;
    let report = run(ConfirmationBackfillArgs {
        database: path,
        height: 0,
        block_file: raw,
    })
    .await?;
    assert_eq!((report.updated, report.already_known), (1, 0));
    assert_eq!(snapshot(&conn).await?, before);
    assert_eq!(schema(&conn).await?, schema_before);
    let row = conn
        .query("SELECT confirmed_bitcoin_tx_index FROM transactions", ())
        .await?
        .next()
        .await?
        .unwrap();
    assert_eq!(row.get::<u32>(0)?, 0);
    assert!(!dir.path().join("crypto.so").exists());
    assert!(!dir.path().join("crypto.dylib").exists());
    Ok(())
}

#[tokio::test]
async fn command_rejects_unrelated_database_without_writing_it() -> Result<()> {
    let dir = TempDir::new()?;
    let path = dir.path().join("unrelated.db");
    let db = Builder::new_local(&path).build().await?;
    let conn = db.connect()?;
    conn.execute_batch(
        "CREATE TABLE unrelated(value BLOB); INSERT INTO unrelated VALUES (X'001122');",
    )
    .await?;
    let before = fs::read(&path).await?;
    let raw = dir.path().join("block.bin");
    fs::write(&raw, serialize(&genesis_block(Network::Regtest))).await?;
    assert!(
        run(ConfirmationBackfillArgs {
            database: path.clone(),
            height: 0,
            block_file: raw
        })
        .await
        .is_err()
    );
    assert_eq!(fs::read(&path).await?, before);
    assert_eq!(snapshot(&conn).await?.len(), 1);
    assert!(!dir.path().join("crypto.so").exists());
    assert!(!dir.path().join("crypto.dylib").exists());
    Ok(())
}
