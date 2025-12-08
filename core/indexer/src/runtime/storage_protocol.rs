//! Storage Protocol instruction handling.
//!
//! This module implements the File Persistence Protocol as native instructions.

use anyhow::{Result, bail};
use libsql::Connection;

use super::FileLedger;

/// Handle CreateAgreement instruction.
///
/// Registers the file in the FileLedger
/// The agreement data (owner, etc.) is available on-chain via the transaction.
pub async fn handle_create_agreement(
    conn: &Connection,
    file_ledger: &FileLedger,
    file_id: String,
    root: Vec<u8>,
    tree_depth: u32,
    height: i64,
    tx_index: i64,
) -> Result<()> {
    // Validate root is 32 bytes
    if root.len() != 32 {
        bail!("Root must be 32 bytes, got {}", root.len());
    }

    // Check if file already registered
    let existing = conn
        .query(
            "SELECT 1 FROM file_ledger_entries WHERE file_id = ?",
            [file_id.clone()],
        )
        .await?
        .next()
        .await?;

    if existing.is_some() {
        bail!("Agreement already exists for file {}", file_id);
    }

    // Register in FileLedger (both in-memory and DB)
    // This stores the cryptographic data (root, tree_depth) for PoR verification
    file_ledger
        .add_file(
            conn,
            file_id.clone(),
            root,
            tree_depth as usize,
            height,
            tx_index,
        )
        .await?;

    tracing::info!("CreateAgreement: registered file {}", file_id);

    Ok(())
}
