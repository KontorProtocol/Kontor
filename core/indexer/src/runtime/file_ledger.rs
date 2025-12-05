use anyhow::Result;
use kontor_crypto::FileLedger as CryptoFileLedger;
use libsql::Connection;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Entry representing a file stored in the ledger
pub struct FileLedgerEntry {
    pub file_id: String,
    pub root: Vec<u8>,
    pub tree_depth: usize,
    pub height: i64,
    pub tx_index: i64,
}

/// Wrapper around kontor_crypto::FileLedger that adds persistence
pub struct PersistentFileLedger {
    pub inner: CryptoFileLedger,
    pub entries: Vec<FileLedgerEntry>,
}

impl PersistentFileLedger {
    pub fn new() -> Self {
        Self {
            inner: CryptoFileLedger::new(),
            entries: Vec::new(),
        }
    }

    /// Rebuild the ledger from database on startup
    pub async fn rebuild_from_db(_conn: &Connection) -> Result<Self> {
        todo!()
    }

    /// Add a file to the ledger and persist to database
    pub async fn add_file(
        &mut self,
        _conn: &Connection,
        _file_id: String,
        _root: Vec<u8>,
        _tree_depth: usize,
        _height: i64,
        _tx_index: i64,
    ) -> Result<()> {
        todo!()
    }

    /// Lookup an entry by file_id
    pub fn get_entry(&self, _file_id: &str) -> Option<&FileLedgerEntry> {
        todo!()
    }
}

impl Default for PersistentFileLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe shared access to the FileLedger
pub type SharedFileLedger = Arc<RwLock<PersistentFileLedger>>;

pub fn new_shared_file_ledger() -> SharedFileLedger {
    Arc::new(RwLock::new(PersistentFileLedger::new()))
}

pub async fn rebuild_shared_file_ledger(_conn: &Connection) -> Result<SharedFileLedger> {
    todo!()
}
