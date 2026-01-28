use std::fmt::Display;

use bon::Builder;
use ff::PrimeField;
use indexer_types::{BlockRow, ContractListRow, ResultRow, TransactionRow};
use kontor_crypto::{FieldElement, FileDescriptor};
use serde::{Deserialize, Serialize};
use serde_with::{DefaultOnNull, DisplayFromStr, serde_as};

use crate::runtime::ContractAddress;

// ─────────────────────────────────────────────────────────────────
// FieldElement <-> [u8; 32] conversion utilities
// ─────────────────────────────────────────────────────────────────

/// Convert a 32-byte array to a FieldElement.
/// Returns None if the bytes don't represent a valid field element.
pub fn bytes_to_field_element(bytes: &[u8; 32]) -> Option<FieldElement> {
    FieldElement::from_repr((*bytes).into()).into_option()
}

/// Convert a FieldElement to a 32-byte array.
pub fn field_element_to_bytes(fe: &FieldElement) -> [u8; 32] {
    fe.to_repr().into()
}

// ─────────────────────────────────────────────────────────────────

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
    pub tx_index: Option<i64>,
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

impl HasRowId for TransactionRow {
    fn id(&self) -> i64 {
        self.id
    }

    fn id_name() -> String {
        "id".to_string()
    }
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
    pub tx_index: Option<i64>,
    pub input_index: Option<i64>,
    pub op_index: Option<i64>,
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
    pub tx_index: Option<i64>,
    pub input_index: Option<i64>,
    pub op_index: Option<i64>,
    #[builder(default = 0)]
    pub result_index: i64,
    #[builder(default = "".to_string())]
    pub func: String,
    pub gas: i64,
    pub value: Option<String>,
    pub contract_name: String,
    pub contract_height: i64,
    pub contract_tx_index: i64,
    pub txid: Option<String>,
}

impl HasRowId for ContractResultPublicRow {
    fn id(&self) -> i64 {
        self.id
    }

    fn id_name() -> String {
        "id".to_string()
    }
}

impl From<ContractResultPublicRow> for ResultRow {
    fn from(row: ContractResultPublicRow) -> Self {
        ResultRow {
            id: row.id,
            height: row.height,
            tx_index: row.tx_index,
            input_index: row.input_index,
            op_index: row.op_index,
            result_index: row.result_index,
            func: row.func,
            gas: row.gas,
            value: row.value,
            contract: ContractAddress {
                name: row.contract_name,
                height: row.contract_height as u64,
                tx_index: row.contract_tx_index as u64,
            }
            .to_string(),
            txid: row.txid,
        }
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

/// Database row for file metadata, matching kontor-crypto's FileMetadata structure.
#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct FileMetadataRow {
    #[builder(default = 0)]
    pub id: i64,
    pub file_id: String,
    pub object_id: String,
    pub nonce: Vec<u8>,
    pub root: [u8; 32],
    pub padded_len: u64,
    pub original_size: u64,
    pub filename: String,
    pub height: i64,
    pub historical_root: Option<[u8; 32]>,
}

impl FileDescriptor for FileMetadataRow {
    fn file_id(&self) -> &str {
        &self.file_id
    }

    fn root(&self) -> FieldElement {
        bytes_to_field_element(&self.root).expect("Invalid field element bytes for root")
    }

    fn depth(&self) -> usize {
        let padded_len = self.padded_len;
        if padded_len == 0 {
            0
        } else {
            padded_len.trailing_zeros() as usize
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct SignerRegistryRow {
    #[builder(default = 0)]
    pub id: i64,
    pub bls_pubkey: Vec<u8>,
    pub first_seen_height: i64,
    pub first_seen_tx_index: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct SignerNonceRow {
    pub signer_id: i64,
    pub nonce: i64,
    pub height: i64,
}
