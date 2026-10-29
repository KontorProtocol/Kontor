use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use bitcoin::Block;
use bitcoin::consensus::deserialize;
use clap::Args;
use tokio::fs::{File, canonicalize};
use tokio::io::AsyncReadExt;

use crate::database::Writer;
use crate::database::confirmation::{ConfirmationBackfill, backfill_confirmation_positions};

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
    // Resolve an existing file before opening Writer, which otherwise creates
    // a new database for a mistyped path.
    let database = canonicalize(&args.database)
        .await
        .context("resolve existing node database")?;
    ensure!(database.is_file(), "database path is not a file");
    let directory = database
        .parent()
        .context("database has no parent directory")?;
    let filename = database
        .file_name()
        .and_then(|name| name.to_str())
        .context("database filename is not UTF-8")?;
    let writer = Writer::new(directory, filename).await?;
    Ok(backfill_confirmation_positions(&writer.connection(), args.height, &block).await?)
}
