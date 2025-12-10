use anyhow::{Result, anyhow};
use kontor_crypto::FileLedger as CryptoFileLedger;
use kontor_crypto::api::FieldElement;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{database::types::FileLedgerEntryRow, runtime::Storage};

pub struct CryptoFileLedgerEntry {
    pub file_id: String,
    pub root: FieldElement,
    pub tree_depth: i64,
}

/// Inner state protected by a single mutex
struct FileLedgerInner {
    ledger: CryptoFileLedger,
    /// Tracks whether the ledger has been modified since last sync.
    /// Used to skip unnecessary rebuilds on rollback.
    dirty: bool,
}

/// Wrapper around kontor_crypto::FileLedger
#[derive(Clone)]
pub struct FileLedger {
    inner: Arc<Mutex<FileLedgerInner>>,
}

impl FileLedger {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FileLedgerInner {
                ledger: CryptoFileLedger::new(),
                dirty: false,
            })),
        }
    }

    /// Rebuild the ledger from database on startup.
    pub async fn rebuild_from_db(storage: &Storage) -> Result<Self> {
        let file_ledger = Self::new();
        {
            let mut inner = file_ledger.inner.lock().await;
            Self::load_entries_into_ledger(&mut inner.ledger, storage).await?;
        }
        tracing::info!("Rebuilt FileLedger from database");
        Ok(file_ledger)
    }

    /// Rebuild the in-memory ledger from the database.
    ///
    /// Call this after a rollback to re-sync the in-memory state with the DB.
    /// Only rebuilds if the ledger has been modified (dirty flag is true).
    pub async fn resync_from_db(&self, storage: &Storage) -> Result<()> {
        let mut inner = self.inner.lock().await;

        // Skip rebuild if ledger hasn't been modified
        if !inner.dirty {
            tracing::info!("FileLedger not dirty, skipping resync");
            return Ok(());
        }

        inner.ledger = CryptoFileLedger::new();
        Self::load_entries_into_ledger(&mut inner.ledger, storage).await?;

        // Clear dirty flag after successful rebuild
        inner.dirty = false;
        tracing::info!("Resynced FileLedger from database");
        Ok(())
    }

    pub async fn force_resync_from_db(&self, storage: &Storage) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.ledger = CryptoFileLedger::new();
        Self::load_entries_into_ledger(&mut inner.ledger, storage).await?;
        inner.dirty = false;
        tracing::info!("Force resynced FileLedger from database");
        Ok(())
    }

    /// Load all file ledger entries from DB and add them to the crypto ledger.
    async fn load_entries_into_ledger(
        ledger: &mut CryptoFileLedger,
        storage: &Storage,
    ) -> Result<()> {
        let rows = storage.all_file_ledger_entries().await?;
        for row in rows {
            let entry: CryptoFileLedgerEntry = (&row).try_into()?;
            // TODO: update once kontor-crypto exposes adding leaves and building the tree once
            ledger
                .add_file(entry.file_id.clone(), entry.root, entry.tree_depth as usize)
                .map_err(|e| anyhow!("Failed to add file {}: {:?}", entry.file_id, e))?;
        }
        Ok(())
    }

    /// Add a file to the ledger and persist to database.
    ///
    /// Holds the lock for the entire operation to ensure the in-memory ledger
    /// and database stay in sync even with concurrent calls.
    pub async fn add_file(
        &self,
        storage: &Storage,
        file_id: String,
        root: Vec<u8>,
        tree_depth: i64,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;

        let row: FileLedgerEntryRow = FileLedgerEntryRow::builder()
            .file_id(file_id)
            .root(root)
            .tree_depth(tree_depth)
            .height(storage.height)
            .build();

        // Convert to get the FieldElement root for the crypto ledger
        let entry: CryptoFileLedgerEntry = (&row).try_into()?;

        // Add to inner FileLedger
        inner
            .ledger
            .add_file(entry.file_id.clone(), entry.root, entry.tree_depth as usize)
            .map_err(|e| anyhow!("Failed to add file to ledger: {:?}", e))?;

        // Persist to database
        storage.insert_file_ledger_entry(row).await?;

        // Mark ledger as dirty (needs resync on rollback)
        inner.dirty = true;

        Ok(())
    }

    /// Clear the dirty flag. Call this before starting a new operation
    /// that should be atomic with respect to rollback.
    pub async fn clear_dirty(&self) {
        let mut inner = self.inner.lock().await;
        inner.dirty = false;
    }
}
