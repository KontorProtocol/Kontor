use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use bitcoin::Block;
use bitcoin::consensus::deserialize;
use clap::Args;
use libsql::{Builder, Connection, OpenFlags};
use tokio::fs::{File, canonicalize};
use tokio::io::AsyncReadExt;

use crate::database::confirmation::{
    ConfirmationBackfill, backfill_confirmation_positions, initialize_confirmation_metadata,
};

#[derive(Args)]
pub struct ConfirmationBackfillArgs {
    /// Existing node SQLite database file.
    #[arg(long)]
    pub database: PathBuf,
    /// Bitcoin height of the stored canonical block.
    #[arg(long)]
    pub height: u64,
    /// Raw Bitcoin block in consensus binary format, not hex text.
    #[arg(long)]
    pub block_file: PathBuf,
}

pub async fn run(args: ConfirmationBackfillArgs) -> Result<ConfirmationBackfill> {
    let mut raw = Vec::new();
    File::open(&args.block_file)
        .await
        .context("open raw Bitcoin block")?
        .take(4_000_001)
        .read_to_end(&mut raw)
        .await
        .context("read raw Bitcoin block")?;
    ensure!(
        raw.len() <= 4_000_000,
        "raw Bitcoin block exceeds maximum size"
    );
    let block: Block = deserialize(&raw).context("decode raw Bitcoin block")?;
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
    conn.query("PRAGMA busy_timeout = 5000", ()).await?;
    conn.query("PRAGMA foreign_keys = ON", ()).await?;
    initialize_confirmation_metadata(&conn).await?;
    Ok(backfill_confirmation_positions(&conn, args.height, &block).await?)
}

async fn validate_node_schema(conn: &Connection) -> Result<()> {
    // Fail before any DDL. The maintenance path must not turn an unrelated
    // SQLite file into a node database or run other startup migrations.
    for projection in [
        "SELECT height, hash, relevant FROM blocks LIMIT 0",
        "SELECT id, txid, height, confirmed_height, tx_index, batch_height FROM transactions LIMIT 0",
        "SELECT id, name, height, tx_index, bytes FROM contracts LIMIT 0",
        "SELECT contract_id, path, height, value, deleted FROM contract_state LIMIT 0",
        "SELECT id, contract_id, tx_id, status FROM contract_results LIMIT 0",
        "SELECT height, hash FROM checkpoints LIMIT 0",
        "SELECT key, value FROM node_meta LIMIT 0",
    ] {
        conn.query(projection, ())
            .await
            .context("not a supported node database")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
