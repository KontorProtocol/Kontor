use anyhow::{Result, anyhow};
use kontor_crypto::FileLedger as CryptoFileLedger;
use kontor_crypto::api::FieldElement;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;

use crate::{database::types::FileLedgerEntryRow, runtime::Storage};

pub struct CryptoFileLedgerEntry {
    pub file_id: String,
    pub root: FieldElement,
    pub tree_depth: i64,
}

/// Wrapper around kontor_crypto::FileLedger
#[derive(Clone)]
pub struct FileLedger {
    inner: Arc<Mutex<CryptoFileLedger>>,
    /// Tracks whether the ledger has been modified since last sync.
    /// Used to skip unnecessary rebuilds on rollback.
    pub dirty: Arc<AtomicBool>,
}

impl FileLedger {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CryptoFileLedger::new())),
            dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Rebuild the ledger from database on startup.
    pub async fn rebuild_from_db(storage: &Storage) -> Result<Self> {
        let ledger = Self::new();
        let mut inner = ledger.inner.lock().await;
        Self::load_entries_into_ledger(&mut inner, storage).await?;
        tracing::info!("Rebuilt FileLedger from database");
        drop(inner);
        Ok(ledger)
    }

    /// Rebuild the in-memory ledger from the database.
    ///
    /// Call this after a rollback to re-sync the in-memory state with the DB.
    /// Only rebuilds if the ledger has been modified (dirty flag is true).
    pub async fn resync_from_db(&self, storage: &Storage) -> Result<()> {
        // Skip rebuild if ledger hasn't been modified
        if !self.dirty.load(Ordering::SeqCst) {
            tracing::info!("FileLedger not dirty, skipping resync");
            return Ok(());
        }

        let mut inner = self.inner.lock().await;
        *inner = CryptoFileLedger::new();
        Self::load_entries_into_ledger(&mut inner, storage).await?;

        // Clear dirty flag after successful rebuild
        self.dirty.store(false, Ordering::SeqCst);
        tracing::info!("Resynced FileLedger from database");
        Ok(())
    }

    /// Load all file ledger entries from DB and add them to the crypto ledger.
    async fn load_entries_into_ledger(
        inner: &mut CryptoFileLedger,
        storage: &Storage,
    ) -> Result<()> {
        let rows = storage.all_file_ledger_entries().await?;
        for row in rows {
            let entry: CryptoFileLedgerEntry = (&row).try_into()?;
            // TODO: update once kontor-crypto exposes adding leaves and building the tree once
            inner
                .add_file(entry.file_id.clone(), entry.root, entry.tree_depth as usize)
                .map_err(|e| anyhow!("Failed to add file {}: {:?}", entry.file_id, e))?;
        }
        Ok(())
    }

    /// Add a file to the ledger and persist to database.
    pub async fn add_file(
        &self,
        storage: &Storage,
        file_id: String,
        root: Vec<u8>,
        tree_depth: i64,
    ) -> Result<()> {
        let row: FileLedgerEntryRow = FileLedgerEntryRow::builder()
            .file_id(file_id)
            .root(root)
            .tree_depth(tree_depth)
            .height(storage.height)
            .tx_index(storage.tx_index)
            .build();

        // Convert to get the FieldElement root for the crypto ledger
        let entry: CryptoFileLedgerEntry = (&row).try_into()?;

        // Add to inner FileLedger
        {
            let mut inner = self.inner.lock().await;
            inner
                .add_file(entry.file_id.clone(), entry.root, entry.tree_depth as usize)
                .map_err(|e| anyhow!("Failed to add file to ledger: {:?}", e))?;
        }

        // Persist to database
        storage.insert_file_ledger_entry(row).await?;

        // Mark ledger as dirty (needs resync on rollback)
        self.dirty.store(true, Ordering::SeqCst);

        Ok(())
    }
}
