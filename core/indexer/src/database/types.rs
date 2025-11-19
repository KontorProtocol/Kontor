use std::fmt::Display;

use bitcoin::BlockHash;
use bon::Builder;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

use crate::{block::Block, runtime::ContractAddress};

pub trait HasRowId {
    fn id(&self) -> i64;
}

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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CheckpointRow {
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
    #[builder(default = 0)]
    pub id: i64,
    pub txid: String,
    pub height: i64,
    pub tx_index: i64,
}

impl HasRowId for TransactionRow {
    fn id(&self) -> i64 {
        self.id
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct ContractListRow {
    pub id: i64,
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
    pub size: i64,
}

impl From<ContractRow> for ContractListRow {
    fn from(row: ContractRow) -> Self {
        ContractListRow {
            id: row.id,
            name: row.name,
            height: row.height,
            tx_index: row.tx_index,
            size: row.bytes.len() as i64,
        }
    }
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

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub next_cursor: Option<i64>,
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

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationQuery {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub cursor: Option<i64>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct TransactionQuery {
    #[serde_as(as = "Option<DisplayFromStr>")]
    cursor: Option<i64>,
    pub offset: Option<i64>,
    limit: Option<i64>,
    pub height: Option<i64>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub contract: Option<ContractAddress>,
}

impl TransactionQuery {
    pub fn cursor(&self) -> Option<i64> {
        if let Some(cursor) = self.cursor
            && cursor < 0
        {
            return None;
        }
        self.cursor
    }

    pub fn limit(&self) -> i64 {
        self.limit.map_or(20, |l| l.clamp(0, 1000))
    }
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
    pub gas: i64,
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
