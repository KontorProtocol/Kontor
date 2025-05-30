use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bitcoin::{BlockHash, Txid, hashes::Hash};
use tempfile::TempDir;

use crate::{
    block::HasTxid,
    config::Config,
    database::{Reader, Writer},
};

pub enum ControlFlow {
    Continue,
    Break,
}

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

pub async fn new_test_db(config: &Config) -> Result<(Reader, Writer, TempDir)> {
    let temp_dir = TempDir::new()?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let db_name = format!("test_db_{}.db", timestamp);
    let mut tmp_config = config.clone();
    tmp_config.data_dir = temp_dir.path().to_owned();
    let writer = Writer::new(&tmp_config, &db_name).await?;
    let reader = Reader::new(tmp_config, &db_name).await?; // Assuming Reader::new exists
    Ok((reader, writer, temp_dir))
}

pub fn new_mock_block_hash(i: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    let i_bytes = i.to_le_bytes();
    for chunk in bytes.chunks_mut(4) {
        chunk.copy_from_slice(&i_bytes[..chunk.len()]);
    }
    BlockHash::from_slice(&bytes).unwrap()
}
