use base64::{Engine, engine::general_purpose};
use bitcoin::BlockHash;
use bon::Builder;
use serde::{Deserialize, Serialize};

use crate::{
    block::{Block, Tx},
    database::queries::Error,
};

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct BlockRow {
    pub height: u64,
    pub hash: BlockHash,
}

impl<T: Tx> From<&Block<T>> for BlockRow {
    fn from(b: &Block<T>) -> Self {
        BlockRow {
            height: b.height,
            hash: b.hash,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRow {
    pub id: i64,
    pub height: i64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct ContractStateRow {
    pub id: Option<i64>,
    pub contract_id: String,
    pub tx_id: i64,
    pub height: i64,
    pub path: String,
    #[builder(default = vec![246])] // cbor serialized null
    pub value: Vec<u8>,
    #[builder(default = false)]
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct TransactionRow {
    #[serde(skip_serializing)]
    pub id: Option<i64>,
    pub txid: String,
    pub height: i64,
    pub tx_index: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct ContractRow {
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct ContractId {
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCursor {
    pub height: i64,
    pub tx_index: i64,
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

        let height = parts[0].parse::<i64>().map_err(|_| Error::InvalidCursor)?;
        let tx_index = parts[1].parse::<i64>().map_err(|_| Error::InvalidCursor)?;

        Ok(TransactionCursor { height, tx_index })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<i64>,
    pub has_more: bool,
    pub total_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionListResponse {
    pub transactions: Vec<TransactionRow>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationQuery {
    pub cursor: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionQuery {
    pub cursor: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    pub height: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPaginationQuery {
    pub cursor: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}
