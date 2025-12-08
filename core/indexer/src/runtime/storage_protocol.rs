//! Storage Protocol instruction handling.
//!
//! This module implements the File Persistence Protocol as native instructions.

use anyhow::{Result, bail};
use libsql::Connection;

use super::FileLedger;

/// Handle CreateAgreement instruction.
///
/// Registers the file in the FileLedger.
/// Multiple agreements can exist for the same file_id (each is a new leaf).
/// The agreement data (owner, etc.) is available on-chain via the transaction.
pub async fn handle_create_agreement(
    conn: &Connection,
    file_ledger: &FileLedger,
    txid: String,
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

    // Register in FileLedger (both in-memory and DB)
    let ledger_entry_id = file_ledger
        .add_file(
            conn,
            txid.clone(),
            file_id.clone(),
            root,
            tree_depth as usize,
            height,
            tx_index,
        )
        .await?;

    tracing::info!(
        "CreateAgreement: registered file {} as ledger entry {} (txid: {})",
        file_id,
        ledger_entry_id,
        txid
    );

    Ok(())
}

/// Handle JoinAgreement instruction.
///
/// Storage node joins an existing agreement by referencing txid + file_id.
/// Multiple CreateAgreement instructions can exist in the same tx, so both are needed.
/// The node_id is the signer of the instruction.
pub async fn handle_join_agreement(
    conn: &Connection,
    agreement_txid: String,
    file_id: String,
    node_id: String,
    height: i64,
) -> Result<()> {
    // Look up the ledger entry by txid + file_id (both needed for unique identification)
    let mut rows = conn
        .query(
            "SELECT id FROM file_ledger_entries WHERE txid = ? AND file_id = ?",
            (agreement_txid.clone(), file_id.clone()),
        )
        .await?;

    let ledger_entry_id: i64 = match rows.next().await? {
        Some(row) => row.get(0)?,
        None => bail!(
            "Agreement not found for txid {} / file_id {}",
            agreement_txid,
            file_id
        ),
    };

    // Check if node already joined this specific agreement
    let existing = conn
        .query(
            "SELECT 1 FROM agreement_nodes WHERE ledger_entry_id = ? AND node_id = ?",
            (ledger_entry_id, node_id.clone()),
        )
        .await?
        .next()
        .await?;

    if existing.is_some() {
        bail!(
            "Node {} already in agreement (txid: {})",
            node_id,
            agreement_txid
        );
    }

    // Add node to agreement
    conn.execute(
        "INSERT INTO agreement_nodes (ledger_entry_id, node_id, joined_at_height) VALUES (?, ?, ?)",
        (ledger_entry_id, node_id.clone(), height),
    )
    .await?;

    tracing::info!(
        "JoinAgreement: node {} joined agreement txid {} (file: {})",
        node_id,
        agreement_txid,
        file_id
    );

    Ok(())
}
