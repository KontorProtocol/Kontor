use anyhow::{Result, anyhow};
use kontor_crypto::FileLedger as CryptoFileLedger;
use std::sync::Arc;
use tokio::sync::RwLock;

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
    inner: Arc<RwLock<FileLedgerInner>>,
}

impl FileLedger {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(FileLedgerInner {
                ledger: CryptoFileLedger::new(),
                dirty: false,
            })),
        }
    }

    /// Rebuild the ledger from database on startup.
    pub async fn rebuild_from_db(storage: &Storage) -> Result<Self> {
        let file_ledger = Self::new();
        {
            let mut inner = file_ledger.inner.write().await;
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
        let mut inner = self.inner.write().await;

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
        let mut inner = self.inner.write().await;
        inner.ledger = CryptoFileLedger::new();
        Self::load_entries_into_ledger(&mut inner.ledger, storage).await?;
        inner.dirty = false;
        tracing::info!("Force resynced FileLedger from database");
        Ok(())
    }

    /// Load all file metadata entries from DB and add them to the crypto ledger.
    /// Also restores the historical roots from the stored values.
    async fn load_entries_into_ledger(
        ledger: &mut CryptoFileLedger,
        storage: &Storage,
    ) -> Result<()> {
        let rows = storage.all_file_metadata().await?;

        // Add all files to rebuild the tree (this will generate incorrect historical roots)
        ledger
            .add_files(&rows)
            .map_err(|e| anyhow!("Failed to add files to ledger: {:?}", e))?;

        // Collect the stored historical roots in order and restore them
        let historical_roots: Vec<[u8; 32]> =
            rows.iter().filter_map(|row| row.historical_root).collect();

        ledger.set_historical_roots(historical_roots);

        Ok(())
    }

    /// Add a file to the ledger and persist to database.
    ///
    /// Holds the lock for the entire operation to ensure the in-memory ledger
    /// and database stay in sync even with concurrent calls.
    ///
    /// The historical root (the pre-modification ledger root) is captured and stored
    /// in the database for later reconstruction during rebuilds.
    pub async fn add_file(&self, storage: &Storage, metadata: &FileMetadataRow) -> Result<()> {
        let mut inner = self.inner.write().await;

        // Capture the number of historical roots before adding
        let historical_roots_count_before = inner.ledger.historical_roots.len();

        // Add to inner FileLedger (this may push a historical root)
        inner
            .ledger
            .add_file(metadata)
            .map_err(|e| anyhow!("Failed to add file to ledger: {:?}", e))?;

        // Check if a new historical root was pushed
        let historical_root = if inner.ledger.historical_roots.len() > historical_roots_count_before
        {
            // The last element is the newly pushed historical root
            inner.ledger.historical_roots.last().copied()
        } else {
            // No historical root was pushed (ledger was empty before)
            None
        };

        // Create metadata with the historical root for persistence
        let metadata_with_historical = FileMetadataRow {
            historical_root,
            ..metadata.clone()
        };

        // Persist to database
        storage
            .insert_file_metadata(metadata_with_historical)
            .await?;

        // Mark ledger as dirty (needs resync on rollback)
        inner.dirty = true;

        Ok(())
    }

    /// Clear the dirty flag. Call this before starting a new operation
    /// that should be atomic with respect to rollback.
    pub async fn clear_dirty(&self) {
        let mut inner = self.inner.write().await;
        inner.dirty = false;
    }

    /// Execute a closure with read access to the inner kontor_crypto::FileLedger.
    /// This avoids cloning the ledger while still providing safe access for verification.
    /// Uses a read lock to allow concurrent read operations (e.g., multiple proof verifications).
    pub async fn with_ledger<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&CryptoFileLedger) -> R,
    {
        let inner = self.inner.read().await;
        f(&inner.ledger)
    }
}
