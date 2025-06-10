use base64::prelude::*;
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

#[derive(Deserialize)]
pub struct PaginationQuery {
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_limit")]
    pub limit: u64,
}

fn default_limit() -> u64 {
    20
}

impl PaginationQuery {
    pub fn validate(&self) -> Result<(), String> {
        if self.limit > 1000 {
            return Err("Limit cannot exceed 1000".to_string());
        }
        if self.limit == 0 {
            return Err("Limit must be > 0".to_string());
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: u64,
    pub offset: u64,
    pub limit: u64,
    pub has_more: bool,
}

#[derive(Deserialize)]
pub struct CursorQuery {
    #[serde(default = "default_limit")]
    pub limit: u64,
    pub cursor: Option<String>,
}

impl CursorQuery {
    pub fn validate(&self) -> Result<(), String> {
        if self.limit > 1000 {
            return Err("Limit cannot exceed 1000".to_string());
        }
        if self.limit == 0 {
            return Err("Limit must be > 0".to_string());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockCursor {
    pub height: u64,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionCursor {
    pub height: u64,
    pub id: i64,
}

impl BlockCursor {
    pub fn encode(&self) -> String {
        let json = serde_json::to_string(self).unwrap();
        BASE64_STANDARD.encode(json)
    }

    pub fn decode(cursor: &str) -> Result<Self, String> {
        let json = BASE64_STANDARD
            .decode(cursor)
            .map_err(|_| "Invalid cursor".to_string())?;
        serde_json::from_slice(&json).map_err(|_| "Invalid cursor format".to_string())
    }
}

impl TransactionCursor {
    pub fn encode(&self) -> String {
        let json = serde_json::to_string(self).unwrap();
        BASE64_STANDARD.encode(json)
    }

    pub fn decode(cursor: &str) -> Result<Self, String> {
        let json = BASE64_STANDARD
            .decode(cursor)
            .map_err(|_| "Invalid cursor".to_string())?;
        serde_json::from_slice(&json).map_err(|_| "Invalid cursor format".to_string())
    }
}

#[derive(Serialize)]
pub struct CursorResponse<T> {
    pub data: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub latest_height: u64,
}
