use anyhow::{Result, anyhow};
use kontor_crypto::FileLedger as CryptoFileLedger;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::database::types::FileMetadataRow;
use crate::runtime::Storage;

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

    /// Load all file metadata entries from DB and add them to the crypto ledger.
    async fn load_entries_into_ledger(
        ledger: &mut CryptoFileLedger,
        storage: &Storage,
    ) -> Result<()> {
        let rows = storage.all_file_metadata().await?;
        ledger
            .add_files(&rows)
            .map_err(|e| anyhow!("Failed to add files to ledger: {:?}", e))?;
        Ok(())
    }

    /// Add a file to the ledger and persist to database.
    ///
    /// Holds the lock for the entire operation to ensure the in-memory ledger
    /// and database stay in sync even with concurrent calls.
    pub async fn add_file(&self, storage: &Storage, metadata: &FileMetadataRow) -> Result<()> {
        let mut inner = self.inner.lock().await;

        // Add to inner FileLedger
        inner
            .ledger
            .add_file(metadata)
            .map_err(|e| anyhow!("Failed to add file to ledger: {:?}", e))?;

        // Convert to database row and persist
        storage.insert_file_metadata(metadata.clone()).await?;

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
