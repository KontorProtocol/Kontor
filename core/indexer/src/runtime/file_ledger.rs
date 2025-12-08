use anyhow::{Result, anyhow};
use ff::PrimeField;
use kontor_crypto::FileLedger as CryptoFileLedger;
use kontor_crypto::api::FieldElement;
use libsql::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Wrapper around kontor_crypto::FileLedger
#[derive(Clone)]
pub struct FileLedger {
    inner: Arc<Mutex<CryptoFileLedger>>,
}

impl FileLedger {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CryptoFileLedger::new())),
        }
    }

    /// Rebuild the ledger from database on startup.
    ///
    /// Loads all file entries and re-adds them to the inner kontor-crypto FileLedger.
    pub async fn rebuild_from_db(conn: &Connection) -> Result<Self> {
        let ledger = Self::new();

        let mut rows = conn
            .query(
                "SELECT file_id, root, tree_depth FROM file_ledger_entries ORDER BY id ASC",
                (),
            )
            .await?;

        while let Some(row) = rows.next().await? {
            let file_id: String = row.get(0)?;
            let root_bytes: Vec<u8> = row.get(1)?;
            let tree_depth: i64 = row.get(2)?;

            let root = Self::bytes_to_field_element(&root_bytes)?;

            let mut inner = ledger.inner.lock().await;
            inner
                .add_file(file_id.clone(), root, tree_depth as usize)
                .map_err(|e| anyhow!("Failed to add file {}: {:?}", file_id, e))?;
        }

        tracing::info!("Rebuilt FileLedger from database");
        Ok(ledger)
    }

    /// Add a file to the ledger and persist to database.
    ///
    /// The root bytes come from kontor-crypto's prepare_file():
    ///   let (prepared_file, metadata) = prepare_file(data, filename)?;
    ///   let root_bytes: Vec<u8> = metadata.root.to_repr().as_ref().to_vec();
    pub async fn add_file(
        &self,
        conn: &Connection,
        file_id: String,
        root: Vec<u8>,
        tree_depth: usize,
        height: i64,
        tx_index: i64,
    ) -> Result<()> {
        let root_field = Self::bytes_to_field_element(&root)?;

        // Add to inner FileLedger
        {
            let mut inner = self.inner.lock().await;
            inner
                .add_file(file_id.clone(), root_field, tree_depth)
                .map_err(|e| anyhow!("Failed to add file to ledger: {:?}", e))?;
        }

        // Persist to database
        conn.execute(
            "INSERT INTO file_ledger_entries (file_id, root, tree_depth, height, tx_index) VALUES (?, ?, ?, ?, ?)",
            (file_id, root, tree_depth as i64, height, tx_index),
        )
        .await?;

        Ok(())
    }

    /// Access the inner crypto FileLedger
    pub fn inner(&self) -> &Arc<Mutex<CryptoFileLedger>> {
        &self.inner
    }

    /// Convert bytes to FieldElement using canonical deserialization.
    ///
    /// This is the inverse of FieldElement::to_repr().
    fn bytes_to_field_element(bytes: &[u8]) -> Result<FieldElement> {
        if bytes.len() != 32 {
            return Err(anyhow!(
                "Expected 32 bytes for FieldElement, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);

        // Use proper canonical deserialization (inverse of to_repr())
        FieldElement::from_repr(arr.into())
            .into_option()
            .ok_or_else(|| anyhow!("Invalid bytes for FieldElement"))
    }
}

impl Default for FileLedger {
    fn default() -> Self {
        Self::new()
    }
}
