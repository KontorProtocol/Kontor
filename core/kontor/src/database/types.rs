use base64::{Engine, engine::general_purpose};
use bitcoin::BlockHash;
use bon::Builder;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

#[derive(Error, Debug)]
pub enum Error {
    #[error("LibSQL error: {0}")]
    LibSQL(#[from] libsql::Error),
    #[error("Row deserialization error: {0}")]
    RowDeserialization(#[from] serde::de::value::Error),
    #[error("Invalid cursor format")]
    InvalidCursor,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct TransactionRow {
    pub id: Option<i64>,
    pub txid: String,
    pub height: u64,
    pub tx_index: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub txid: String,
    pub height: u64,
    pub tx_index: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRowWithMeta {
    pub txid: String,
    pub height: u64,
    pub tx_index: i32,
    pub total_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCursor {
    pub height: u64,
    pub tx_index: i32,
}

impl TransactionCursor {
    pub fn encode(&self) -> String {
        let cursor_str = format!("{}:{}", self.height, self.tx_index);
        general_purpose::STANDARD.encode(cursor_str.as_bytes())
    }

    pub fn decode(cursor: &str) -> Result<Self, Error> {
        // rename base64_encode
        let decoded_bytes = general_purpose::STANDARD
            .decode(cursor)
            .map_err(|_| Error::InvalidCursor)?;

        let cursor_str = String::from_utf8(decoded_bytes).map_err(|_| Error::InvalidCursor)?;

        let parts: Vec<&str> = cursor_str.split(':').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidCursor);
        }

        let height = parts[0].parse::<u64>().map_err(|_| Error::InvalidCursor)?;
        let tx_index = parts[1].parse::<i32>().map_err(|_| Error::InvalidCursor)?;

        Ok(TransactionCursor { height, tx_index })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    pub next_cursor: Option<String>,
    pub next_offset: Option<u64>,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionListResponse {
    pub results: Vec<TransactionResponse>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationQuery {
    pub cursor: Option<String>,
    pub offset: Option<u64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionQuery {
    pub cursor: Option<String>,
    pub offset: Option<u64>,
    pub limit: Option<u32>,
    pub height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPaginationQuery {
    pub cursor: Option<String>,
    pub offset: Option<u64>,
    pub limit: Option<u32>,
}
