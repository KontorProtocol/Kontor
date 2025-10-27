use std::fmt::Display;

use base64::{Engine, engine::general_purpose};
use bitcoin::BlockHash;
use bon::Builder;
use serde::{Deserialize, Serialize};

use crate::{block::Block, database::queries::Error};

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct BlockRow {
    pub height: i64,
    pub hash: BlockHash,
}

impl From<&Block> for BlockRow {
    fn from(b: &Block) -> Self {
        BlockRow {
            height: b.height as i64,
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
    pub contract_id: i64,
    pub height: i64,
    pub tx_index: i64,
    pub path: String,
    #[builder(default = vec![])]
    pub value: Vec<u8>,
    #[builder(default = false)]
    pub deleted: bool,
}

impl ContractStateRow {
    pub fn size(&self) -> u64 {
        self.value.len() as u64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct TransactionRow {
    pub txid: String,
    pub height: i64,
    pub tx_index: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct ContractRow {
    #[builder(default = 0)]
    pub id: i64,
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
    pub bytes: Vec<u8>,
}

impl ContractRow {
    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCursor {
    pub height: i64,
    pub index: i64,
}

impl TransactionCursor {
    pub fn encode(&self) -> String {
        let cursor_str = format!("{}:{}", self.height, self.index);
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
        let index = parts[1].parse::<i64>().map_err(|_| Error::InvalidCursor)?;

        Ok(TransactionCursor { height, index })
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

#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct ContractResultRow {
    pub height: i64,
    pub tx_index: i64,
    #[builder(default = 0)]
    pub input_index: i64,
    #[builder(default = 0)]
    pub op_index: i64,
    #[builder(default = 0)]
    pub result_index: i64,
    #[builder(default = 0)]
    pub contract_id: i64,
    #[builder(default = "".to_string())]
    pub func_name: String,
    pub value: Option<String>,
}

impl ContractResultRow {
    pub fn size(&self) -> u64 {
        self.value.as_ref().map_or(0, |v| v.len() as u64)
    }
}

#[derive(Debug, Clone, Builder, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct OpResultId {
    pub txid: String,
    #[builder(default = 0)]
    pub input_index: i64,
    #[builder(default = 0)]
    pub op_index: i64,
}

impl Display for OpResultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.txid, self.input_index, self.op_index)
    }
}
