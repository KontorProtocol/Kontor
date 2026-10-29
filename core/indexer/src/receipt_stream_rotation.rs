use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::Args;
use libsql::{Builder, OpenFlags};
use serde::Serialize;
use tokio::fs::canonicalize;

use crate::database::maintenance::validate_node_schema;
use crate::database::receipt_stream::rotate_stream_epoch;

#[derive(Args)]
pub struct ReceiptStreamRotationArgs {
    /// Existing node database. Stop the node before restoring and rotating its epoch.
    #[arg(long)]
    pub database: PathBuf,
}

#[derive(Serialize)]
pub struct ReceiptStreamRotation {
    pub epoch: String,
}

pub async fn run(args: ReceiptStreamRotationArgs) -> Result<ReceiptStreamRotation> {
    let database = canonicalize(&args.database)
        .await
        .context("resolve existing node database")?;
    ensure!(database.is_file(), "database path is not a file");
    let db = Builder::new_local(database)
        .flags(OpenFlags::SQLITE_OPEN_READ_WRITE)
        .build()
        .await?;
    let conn = db.connect()?;
    validate_node_schema(&conn).await?;
    let mut tables = conn
        .query(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
             AND name IN ('receipt_stream_state', 'receipt_stream_rollbacks')",
            (),
        )
        .await?;
    let count: i64 = tables
        .next()
        .await?
        .context("read receipt stream schema")?
        .get(0)?;
    ensure!(
        count == 2,
        "receipt-stream metadata is missing; for a backup predating receipt streams, normal node startup migration assigns a fresh epoch, so offline rotation is unnecessary"
    );
    drop(tables);
    conn.query("PRAGMA busy_timeout = 5000", ()).await?;
    Ok(ReceiptStreamRotation {
        epoch: rotate_stream_epoch(&conn).await?,
    })
}
