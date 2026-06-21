use std::fmt::Display;

use bon::Builder;
use ff::PrimeField;
use indexer_types::{BlockRow, ContractListRow, OpStatus, ResultRow, TransactionRow};
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

/// Merkle tree depth for a file whose padded leaf count is `padded_len` (a power of
/// two): `log2(padded_len)`, or 0 for an empty file. Assumes `padded_len` was already
/// validated by [`validate_padded_len`] at the host trust boundary — `trailing_zeros`
/// silently yields a wrong depth for a non-power-of-two.
pub fn padded_len_to_depth(padded_len: u64) -> usize {
    if padded_len == 0 {
        0
    } else {
        padded_len.trailing_zeros() as usize
    }
}

/// Validate that `padded_len` is a positive power of two (the leaf count of a full
/// binary Merkle tree) and return its depth. The contract enforces this too, but the
/// host re-checks at its trust boundary: a non-power-of-two would pass `trailing_zeros`
/// and produce a wrong depth → wrong aggregated root / challenge indices.
pub fn validate_padded_len(padded_len: u64) -> Result<usize, &'static str> {
    if padded_len == 0 || !padded_len.is_power_of_two() {
        return Err("padded_len must be a positive power of 2");
    }
    Ok(padded_len.trailing_zeros() as usize)
}

/// Validate that `root` is exactly 32 bytes encoding a canonical field element,
/// returning both the byte array (for storage) and the decoded `FieldElement`. The
/// `Err` is a ready-to-show message; callers wrap it in their error type. This is
/// the single root-validation gate shared by descriptor parsing and `aggregate_root`.
pub fn validate_root(root: &[u8]) -> Result<([u8; 32], FieldElement), &'static str> {
    let bytes: [u8; 32] = root.try_into().map_err(|_| "expected 32 bytes for root")?;
    let fe = bytes_to_field_element(&bytes).ok_or("root bytes are not a valid field element")?;
    Ok((bytes, fe))
}

// ─────────────────────────────────────────────────────────────────

pub trait HasRowId {
    fn id(&self) -> u64;
    fn id_name() -> &'static str;
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
    fn id(&self) -> u64 {
        self.height
    }

    fn id_name() -> &'static str {
        "height"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    signer_id: u64,
    key: String,
}

impl Identity {
    pub fn new(signer_id: u64) -> Self {
        Self {
            signer_id,
            key: signer_id.to_string(),
        }
    }

    pub fn signer_id(&self) -> u64 {
        self.signer_id
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

/// The reserved signer_id for the Core (system) signer. By construction the
/// Core row is the first one inserted into `signers` at genesis, so SQLite
/// auto-increment assigns it id = 1. This constant pins that contract and is
/// asserted by `create_core_signer`.
pub const CORE_SIGNER_ID: u64 = 1;

#[derive(Debug, Clone, Deserialize)]
pub struct SignerEntry {
    pub signer_id: u64,
    pub x_only_pubkey: Option<String>,
    pub bls_pubkey: Option<Vec<u8>>,
    pub next_nonce: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct BatchQueryResult {
    pub consensus_height: u64,
    pub anchor_height: u64,
    pub anchor_hash: String,
    pub certificate: Vec<u8>,
    pub is_block: bool,
    pub txids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct ContractStateRow {
    pub contract_id: u64,
    pub height: u64,
    pub tx_id: Option<u64>,
    /// Order-preserving tuple-codec bytes (see `stdlib::keycodec`).
    pub path: Vec<u8>,
    #[builder(default = vec![])]
    pub value: Vec<u8>,
    #[builder(default = false)]
    pub deleted: bool,
    /// The signer who wrote (deposited for) this version — the storage-deposit
    /// refund target. `None` for tombstones and Core/system writes (Option implies
    /// a `None` builder default).
    pub depositor: Option<u64>,
    /// The deposit locked for this row = (path + value bytes) × D, as a decimal
    /// string; the exact amount refunded when the row is freed. `None` when there
    /// is no depositor.
    pub deposited_amount: Option<String>,
}

impl ContractStateRow {
    pub fn size(&self) -> u64 {
        self.value.len() as u64
    }
}

impl HasRowId for TransactionRow {
    fn id(&self) -> u64 {
        self.id
    }

    fn id_name() -> &'static str {
        "id"
    }
}

impl From<ContractRow> for ContractListRow {
    fn from(row: ContractRow) -> Self {
        ContractListRow {
            id: row.id,
            name: row.name,
            height: row.height,
            tx_index: row.tx_index,
            size: row.bytes.len() as u64,
            signer_id: row.signer_id,
        }
    }
}

impl HasRowId for ContractListRow {
    fn id(&self) -> u64 {
        self.id
    }

    fn id_name() -> &'static str {
        "id"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct ContractRow {
    #[builder(default = 0)]
    pub id: u64,
    pub name: String,
    pub height: u64,
    pub tx_index: u32,
    pub bytes: Vec<u8>,
    pub signer_id: Option<u64>,
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
    pub cursor: Option<u64>,
    pub offset: Option<u64>,
    pub limit: Option<u32>,
    #[builder(default)]
    #[serde_as(as = "DefaultOnNull<DisplayFromStr>")]
    #[serde(default)]
    pub order: OrderDirection,
    pub relevant: Option<bool>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct ContractQuery {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub cursor: Option<u64>,
    pub offset: Option<u64>,
    pub limit: Option<u32>,
    #[builder(default)]
    #[serde_as(as = "DefaultOnNull<DisplayFromStr>")]
    #[serde(default)]
    pub order: OrderDirection,
    pub signer_id: Option<u64>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct TransactionQuery {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub cursor: Option<u64>,
    pub offset: Option<u64>,
    pub limit: Option<u32>,
    #[builder(default)]
    #[serde_as(as = "DefaultOnNull<DisplayFromStr>")]
    #[serde(default)]
    pub order: OrderDirection,

    pub height: Option<u64>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub contract: Option<ContractAddress>,
    pub signer_id: Option<u64>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct ResultQuery {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub cursor: Option<u64>,
    pub offset: Option<u64>,
    pub limit: Option<u32>,
    #[builder(default)]
    #[serde_as(as = "DefaultOnNull<DisplayFromStr>")]
    #[serde(default)]
    pub order: OrderDirection,

    pub height: Option<u64>,
    pub start_height: Option<u64>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub contract: Option<ContractAddress>,
    pub func: Option<String>,
    pub signer_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder, Eq, PartialEq)]
pub struct ContractResultRow {
    #[builder(default = 0)]
    pub id: u64,
    pub height: u64,
    pub tx_id: Option<u64>,
    pub input_index: Option<u32>,
    pub op_index: Option<u32>,
    #[builder(default = 0)]
    pub result_index: u32,
    #[builder(default = 0)]
    pub contract_id: u64,
    #[builder(default = "".to_string())]
    pub func: String,
    pub gas: u64,
    pub value: Option<String>,
    #[builder(default = 0)]
    pub signer_id: u64,
    /// Who funded gas for this op. Equals `signer_id` for self-pay ops; for
    /// BLS-aggregate sponsored ops it's the publisher's signer_id. `None` for
    /// ops that don't go through user-side gas accounting (Issuance,
    /// RegisterBlsKey via the Core-paid path).
    pub payer_signer_id: Option<u64>,
    /// Outcome of the call. Populated by `handle_procedure` from the wasm
    /// result before writing the row.
    #[builder(default = OpStatus::Ok)]
    pub status: OpStatus,
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
    pub id: u64,
    pub height: u64,
    pub tx_index: Option<u32>,
    pub input_index: Option<u32>,
    pub op_index: Option<u32>,
    #[builder(default = 0)]
    pub result_index: u32,
    #[builder(default = "".to_string())]
    pub func: String,
    pub gas: u64,
    pub value: Option<String>,
    pub contract_name: String,
    pub contract_height: u64,
    pub contract_tx_index: u32,
    pub txid: Option<String>,
    pub signer_id: u64,
    pub payer_signer_id: Option<u64>,
    #[builder(default = OpStatus::Ok)]
    pub status: OpStatus,
}

impl HasRowId for ContractResultPublicRow {
    fn id(&self) -> u64 {
        self.id
    }

    fn id_name() -> &'static str {
        "id"
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
            status: row.status,
            value: row.value,
            contract: ContractAddress {
                name: row.contract_name,
                height: row.contract_height,
                tx_index: row.contract_tx_index,
            }
            .to_string(),
            txid: row.txid,
            signer_id: row.signer_id,
            payer_signer_id: row.payer_signer_id,
        }
    }
}

#[derive(Debug, Clone, Builder, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct OpResultId {
    pub txid: String,
    #[builder(default = 0)]
    pub input_index: u32,
    #[builder(default = 0)]
    pub op_index: u32,
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
            .parse::<u32>()
            .map_err(|e| format!("Failed to parse input_index '{}': {e}", parts[1]))?;

        let op_index = parts[2]
            .parse::<u32>()
            .map_err(|e| format!("Failed to parse op_index '{}': {e}", parts[2]))?;

        Ok(OpResultId {
            txid,
            input_index,
            op_index,
        })
    }
}

/// In-memory file metadata carried by the `FileDescriptor` host resource — the
/// fields the deleted `file_metadata` DB row held, minus the row bookkeeping
/// (`id`/`height`/`historical_root`). Matches kontor-crypto's `FileMetadata`.
#[derive(Debug, Clone, Builder)]
pub struct FileMeta {
    pub file_id: String,
    pub object_id: String,
    pub nonce: Vec<u8>,
    pub root: [u8; 32],
    pub padded_len: u64,
    pub original_size: u64,
    pub filename: String,
}

impl FileDescriptor for FileMeta {
    fn file_id(&self) -> &str {
        &self.file_id
    }

    fn root(&self) -> FieldElement {
        bytes_to_field_element(&self.root).expect("Invalid field element bytes for root")
    }

    fn depth(&self) -> usize {
        padded_len_to_depth(self.padded_len)
    }
}
