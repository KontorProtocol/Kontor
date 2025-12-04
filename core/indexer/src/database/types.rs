use std::fmt::Display;

use bitcoin::BlockHash;
use bon::Builder;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::{DefaultOnNull, DisplayFromStr, serde_as};

use crate::{block::Block, runtime::ContractAddress};

pub trait HasRowId {
    fn id(&self) -> i64;
    fn id_name() -> String;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OrderDirection {
    Asc,
    #[default]
    Desc,
}

impl std::fmt::Display for OrderDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrderDirection::Asc => write!(f, "ASC"),
            OrderDirection::Desc => write!(f, "DESC"),
        }
    }
}

impl std::str::FromStr for OrderDirection {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "asc" | "ascending" => Ok(OrderDirection::Asc),
            "desc" | "descending" | "" => Ok(OrderDirection::Desc), // empty also defaults
            _ => Err("Invalid order direction".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder, JsonSchema)]
pub struct BlockRow {
    pub height: i64,
    #[schemars(with = "String")]
    pub hash: BlockHash,
    #[builder(default = false)]
    pub relevant: bool,
}

impl From<&Block> for BlockRow {
    fn from(b: &Block) -> Self {
        BlockRow {
            height: b.height as i64,
            hash: b.hash,
            relevant: !b.transactions.is_empty(),
        }
    }
}

impl HasRowId for BlockRow {
    fn id(&self) -> i64 {
        self.height
    }

    fn id_name() -> String {
        "height".to_string()
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

#[derive(Debug, Clone, Serialize, Deserialize, Builder, JsonSchema)]
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

    fn id_name() -> String {
        "id".to_string()
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PaginationMeta {
    #[schemars(with = "String")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub next_cursor: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<i64>,
    pub has_more: bool,
    pub total_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PaginatedResponse<T> {
    pub results: Vec<T>,
    pub pagination: PaginationMeta,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct BlockQuery {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub cursor: Option<i64>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    #[builder(default)]
    #[serde_as(as = "DefaultOnNull<DisplayFromStr>")]
    #[serde(default)]
    pub order: OrderDirection,
    pub relevant: Option<bool>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct TransactionQuery {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub cursor: Option<i64>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    #[builder(default)]
    #[serde_as(as = "DefaultOnNull<DisplayFromStr>")]
    #[serde(default)]
    pub order: OrderDirection,

    pub height: Option<i64>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub contract: Option<ContractAddress>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct ResultQuery {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub cursor: Option<i64>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    #[builder(default)]
    #[serde_as(as = "DefaultOnNull<DisplayFromStr>")]
    #[serde(default)]
    pub order: OrderDirection,

    pub height: Option<i64>,
    pub start_height: Option<i64>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub contract: Option<ContractAddress>,
    pub func: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct ContractResultRow {
    #[builder(default = 0)]
    pub id: i64,
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
    pub func: String,
    pub gas: i64,
    pub value: Option<String>,
}

impl ContractResultRow {
    pub fn size(&self) -> u64 {
        self.value.as_ref().map_or(0, |v| v.len() as u64)
    }
}

// provide contract address instead of internal contract id
#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct ContractResultPublicRow {
    #[builder(default = 0)]
    pub id: i64,
    pub height: i64,
    pub tx_index: i64,
    #[builder(default = 0)]
    pub input_index: i64,
    #[builder(default = 0)]
    pub op_index: i64,
    #[builder(default = 0)]
    pub result_index: i64,
    #[builder(default = "".to_string())]
    pub func: String,
    pub gas: i64,
    pub value: Option<String>,
    pub contract_name: String,
    pub contract_height: i64,
    pub contract_tx_index: i64,
}

impl HasRowId for ContractResultPublicRow {
    fn id(&self) -> i64 {
        self.id
    }

    fn id_name() -> String {
        "id".to_string()
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
        write!(f, "{}_{}_{}", self.txid, self.input_index, self.op_index)
    }
}

impl std::str::FromStr for OpResultId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('_').collect();
        if parts.len() != 3 {
            return Err(format!(
                "Invalid OpResultId format: expected 3 parts separated by '_', got '{s}'"
            ));
        }

        let txid = parts[0].to_string();
        if txid.is_empty() {
            return Err("txid cannot be empty".to_string());
        }

        let input_index = parts[1]
            .parse::<i64>()
            .map_err(|e| format!("Failed to parse input_index '{}': {e}", parts[1]))?;

        let op_index = parts[2]
            .parse::<i64>()
            .map_err(|e| format!("Failed to parse op_index '{}': {e}", parts[2]))?;

        Ok(OpResultId {
            txid,
            input_index,
            op_index,
        })
    }
}
