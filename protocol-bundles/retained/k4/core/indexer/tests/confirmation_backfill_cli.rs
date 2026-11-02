use std::path::Path;
use std::process::Output;
use std::time::Duration;

use anyhow::Result;
use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use indexer::database::init::CREATE_SCHEMA;
use libsql::{Builder, params};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::fs;
use tokio::process::Command;
use tokio::time::timeout;

async fn backfill(directory: &Path, database: &Path, block: &Path) -> Result<Output> {
    Ok(timeout(
        Duration::from_secs(30),
        Command::new(env!("CARGO_BIN_EXE_kontor"))
            .current_dir(directory)
            .arg("backfill-confirmations")
            .arg("--database")
            .arg(database)
            .args(["--height", "0", "--block-file"])
            .arg(block)
            .kill_on_drop(true)
            .output(),
    )
    .await??)
}

#[tokio::test]
async fn executable_backfills_once_and_rejects_invalid_targets() -> Result<()> {
    let directory = TempDir::new()?;
    let database = directory.path().join("node.db");
    let raw = directory.path().join("block.bin");
    let block = genesis_block(Network::Regtest);
    let txid = block.txdata[0].compute_txid().to_string();
    fs::write(&raw, serialize(&block)).await?;
    {
        let db = Builder::new_local(&database).build().await?;
        let conn = db.connect()?;
        conn.execute_batch(CREATE_SCHEMA).await?;
        conn.execute(
            "INSERT INTO blocks VALUES (0, ?, 1)",
            params![block.block_hash().to_string()],
        )
        .await?;
        conn.execute(
            "INSERT INTO transactions (id, txid, height, confirmed_height, tx_index)
             VALUES (1, ?, 0, 0, 0)",
            params![txid],
        )
        .await?;
        conn.execute("INSERT INTO node_meta VALUES ('preserve', X'001122')", ())
            .await?;
    }
    for (updated, already_known) in [(1, 0), (0, 1)] {
        let output = backfill(directory.path(), &database, &raw).await?;
        assert!(output.status.success(), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            report,
            json!({
                "height": 0,
                "block_hash": block.block_hash().to_string(),
                "updated": updated,
                "already_known": already_known,
            })
        );
    }
    {
        let db = Builder::new_local(&database).build().await?;
        let conn = db.connect()?;
        let row = conn
            .query("SELECT confirmed_bitcoin_tx_index FROM transactions", ())
            .await?
            .next()
            .await?
            .unwrap();
        assert_eq!(row.get::<u32>(0)?, 0);
        let row = conn
            .query("SELECT value FROM node_meta WHERE key = 'preserve'", ())
            .await?
            .next()
            .await?
            .unwrap();
        assert_eq!(row.get::<Vec<u8>>(0)?, [0, 0x11, 0x22]);
    }
    let missing = directory.path().join("missing.db");
    assert!(
        !backfill(directory.path(), &missing, &raw)
            .await?
            .status
            .success()
    );
    assert!(!missing.exists());

    let unrelated = directory.path().join("unrelated.db");
    {
        let db = Builder::new_local(&unrelated).build().await?;
        db.connect()?
            .execute_batch("CREATE TABLE keep(value BLOB);")
            .await?;
    }
    let before = fs::read(&unrelated).await?;
    assert!(
        !backfill(directory.path(), &unrelated, &raw)
            .await?
            .status
            .success()
    );
    assert_eq!(fs::read(&unrelated).await?, before);
    for extension in ["so", "dylib", "dll"] {
        assert!(
            !directory
                .path()
                .join(format!("crypto.{extension}"))
                .exists()
        );
    }
    Ok(())
}
