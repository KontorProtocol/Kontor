use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRow {
    pub height: u64,
    pub hash: BlockHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRow {
    pub height: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRow {
    pub id: Option<i64>,  // Optional because it's auto-generated on insert
    pub tx_index: u32,
    pub txid: String,
    pub block_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractStateRow {
    pub id: Option<i64>,  // Optional because it's auto-generated on insert
    pub contract_id: String,
    pub tx_id: i64,
    pub height: u64,
    pub path: String,
    pub value: Option<Vec<u8>>,  // BLOB can be NULL
    pub deleted: bool,
}
