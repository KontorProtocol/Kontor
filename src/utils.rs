use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bitcoin::{BlockHash, Txid, hashes::Hash};
use libsql::Connection;
use tempfile::TempDir;

use crate::{
    block::HasTxid,
    database::{Reader, Writer, connection::new_connection},
};

#[derive(Clone, Debug, PartialEq)]
pub struct MockTransaction {
    txid: Txid,
}

impl MockTransaction {
    pub fn new(txid_num: u32) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&txid_num.to_le_bytes()); // Use the 4 bytes of txid_num
        MockTransaction {
            txid: Txid::from_slice(&bytes).unwrap(),
        }
    }
}

impl HasTxid for MockTransaction {
    fn txid(&self) -> Txid {
        self.txid
    }
}

pub async fn new_test_db() -> Result<(Reader, Writer, TempDir)> {
    let temp_dir = TempDir::new()?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let db_name = format!("test_db_{}.db", timestamp);
    let db_path = temp_dir.path().join(db_name);
    let writer = Writer::new(&db_path).await?;
    let reader = Reader::new(&db_path).await?; // Assuming Reader::new exists
    Ok((reader, writer, temp_dir))
}

pub async fn new_test_conn() -> Result<(Connection, TempDir)> {
    let temp_dir = TempDir::new()?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let db_name = format!("test_db_{}.db", timestamp);
    let db_path = temp_dir.path().join(db_name);
    let conn = new_connection(&db_path).await?;
    Ok((conn, temp_dir))
}

pub fn new_mock_block_hash(i: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    let i_bytes = i.to_le_bytes();
    for chunk in bytes.chunks_mut(4) {
        chunk.copy_from_slice(&i_bytes[..chunk.len()]);
    }
    BlockHash::from_slice(&bytes).unwrap()
}
