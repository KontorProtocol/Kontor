use bitcoin::BlockHash;
use bon::Builder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRow {
    pub height: u64,
    pub hash: BlockHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRow {
    pub id: i64,
    pub height: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct TransactionRow {
    pub id: Option<i64>,
    pub height: u64,
    pub txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct ContractStateRow {
    pub id: Option<i64>,
    pub contract_id: String,
    pub tx_id: i64,
    pub height: u64,
    pub path: String,
    pub value: Option<Vec<u8>>,
    #[builder(default = false)]
    pub deleted: bool,
}
