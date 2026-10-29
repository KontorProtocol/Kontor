use std::path::Path;
use std::process::Output;
use std::time::Duration;

use anyhow::Result;
use indexer::database::init::CREATE_SCHEMA;
use indexer::database::receipt_stream::{initialize_receipt_stream, stream_state};
use libsql::Builder;
use serde_json::Value;
use tempfile::TempDir;
use tokio::fs;
use tokio::process::Command;
use tokio::time::timeout;

async fn rotate(directory: &Path, database: &Path) -> Result<Output> {
    Ok(timeout(
        Duration::from_secs(30),
        Command::new(env!("CARGO_BIN_EXE_kontor"))
            .current_dir(directory)
            .arg("rotate-receipt-stream")
            .arg("--database")
            .arg(database)
            .kill_on_drop(true)
            .output(),
    )
    .await??)
}

#[tokio::test]
async fn executable_rotates_only_stream_metadata_in_existing_node_database() -> Result<()> {
    let directory = TempDir::new()?;
    let database = directory.path().join("node.db");
    let original_epoch;
    {
        let db = Builder::new_local(&database).build().await?;
        let conn = db.connect()?;
        conn.execute_batch(CREATE_SCHEMA).await?;
        initialize_receipt_stream(&conn).await?;
        conn.execute_batch(
            "INSERT INTO blocks VALUES (0, 'preserved-block', 1);
             INSERT INTO node_meta VALUES ('preserved', X'001122');
             UPDATE receipt_stream_state SET generation = 1;
             INSERT INTO receipt_stream_rollbacks VALUES (1, 0, 0);",
        )
        .await?;
        original_epoch = stream_state(&conn).await?.epoch;
    }
    let output = rotate(directory.path(), &database).await?;
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    {
        let db = Builder::new_local(&database).build().await?;
        let conn = db.connect()?;
        let state = stream_state(&conn).await?;
        assert_ne!(state.epoch, original_epoch);
        assert_eq!(report["epoch"], state.epoch);
        assert_eq!(state.generation, 0);
        let row = conn
            .query("SELECT hash FROM blocks WHERE height = 0", ())
            .await?
            .next()
            .await?
            .unwrap();
        assert_eq!(row.get::<String>(0)?, "preserved-block");
        let row = conn
            .query("SELECT value FROM node_meta WHERE key = 'preserved'", ())
            .await?
            .next()
            .await?
            .unwrap();
        assert_eq!(row.get::<Vec<u8>>(0)?, [0, 0x11, 0x22]);
    }
    let missing = directory.path().join("missing.db");
    assert!(!rotate(directory.path(), &missing).await?.status.success());
    assert!(!missing.exists());
    let unrelated = directory.path().join("unrelated.db");
    {
        let db = Builder::new_local(&unrelated).build().await?;
        db.connect()?
            .execute("CREATE TABLE keep(value TEXT)", ())
            .await?;
    }
    let before = fs::read(&unrelated).await?;
    assert!(!rotate(directory.path(), &unrelated).await?.status.success());
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
