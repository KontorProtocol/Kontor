extern crate alloc;

use anyhow::Result;
use bitcoin::{
    BlockHash, FeeRate, OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey, taproot::LeafVersion,
};
use bon::Builder;
use indexmap::IndexMap;
use macros::contract_address;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use ts_rs::TS;
pub use wit_bindgen;

#[derive(Serialize, Deserialize, Clone, Builder, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct InstructionQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub funding_utxo_ids: String,
    pub instruction: Inst,
    pub chained_instruction: Option<Inst>,
}

#[derive(Serialize, Deserialize, Builder, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct ComposeQuery {
    pub instructions: Vec<InstructionQuery>,
    #[ts(type = "number")]
    pub sat_per_vbyte: u64,
    #[ts(type = "number | null")]
    pub envelope: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct TapLeafScript {
    #[ts(type = "number")]
    #[serde(rename = "leafVersion")]
    pub leaf_version: LeafVersion,
    #[ts(as = "String")]
    pub script: ScriptBuf,
    #[ts(as = "String")]
    #[serde(rename = "controlBlock")]
    pub control_block: ScriptBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct ParticipantScripts {
    pub address: String,
    pub x_only_public_key: String,
    pub commit_tap_leaf_script: TapLeafScript,
    pub chained_tap_leaf_script: Option<TapLeafScript>,
}

#[derive(Debug, Serialize, Deserialize, Builder, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct ComposeOutputs {
    #[ts(as = "String")]
    pub commit_transaction: bitcoin::Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
    #[ts(as = "String")]
    pub reveal_transaction: bitcoin::Transaction,
    pub reveal_transaction_hex: String,
    pub reveal_psbt_hex: String,
    pub per_participant: Vec<ParticipantScripts>,
}

#[derive(Builder, Serialize, Clone, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct CommitOutputs {
    #[ts(as = "String")]
    pub commit_transaction: bitcoin::Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
    pub reveal_inputs: RevealInputs,
}

#[derive(Serialize, Deserialize, Clone, Builder, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct RevealParticipantQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub commit_vout: u32,
    pub commit_script_data: Vec<u8>,
    pub chained_instruction: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, TS, Clone, Builder)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct RevealQuery {
    pub commit_tx_hex: String,
    #[ts(type = "number")]
    pub sat_per_vbyte: u64,
    pub participants: Vec<RevealParticipantQuery>,
    pub op_return_data: Option<Vec<u8>>,
    #[ts(type = "number | null")]
    pub envelope: Option<u64>,
}

#[derive(Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct TxOutSchema {
    #[ts(type = "number")]
    pub value: u64,
    pub script_pubkey: String,
}

#[derive(Clone, Serialize, Builder, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct RevealParticipantInputs {
    #[ts(as = "String")]
    pub address: bitcoin::Address,
    #[ts(as = "String")]
    pub x_only_public_key: XOnlyPublicKey,
    #[ts(as = "String")]
    pub commit_outpoint: OutPoint,
    #[ts(as = "TxOutSchema")]
    pub commit_prevout: TxOut,
    pub commit_tap_leaf_script: TapLeafScript,
    pub chained_instruction: Option<Vec<u8>>,
}

#[derive(Builder, Serialize, Clone, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct RevealInputs {
    #[ts(as = "String")]
    pub commit_tx: bitcoin::Transaction,
    #[ts(type = "number")]
    pub fee_rate: FeeRate,
    pub participants: Vec<RevealParticipantInputs>,
    pub op_return_data: Option<Vec<u8>>,
    #[ts(type = "number")]
    pub envelope: u64,
}

#[derive(Builder, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct RevealOutputs {
    #[ts(as = "String")]
    pub transaction: bitcoin::Transaction,
    pub transaction_hex: String,
    pub psbt_hex: String,
    pub participants: Vec<ParticipantScripts>,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct ResultResponse<T: TS> {
    pub result: T,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
#[serde(tag = "type")]
pub enum WsRequest {
    Subscribe,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
#[serde(tag = "type")]
pub enum WsResponse {
    Event { event: Event },
    Error { error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
#[serde(tag = "type")]
pub enum Event {
    Processed {
        block: Block,
    },
    Rolledback {
        #[ts(type = "number")]
        height: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct Transaction {
    #[ts(type = "string")]
    pub txid: Txid,
    #[ts(type = "number")]
    pub index: i64,
    pub ops: Vec<Op>,
    #[ts(type = "Record<number, OpReturnData>")]
    #[serde(with = "indexmap::map::serde_seq")]
    pub op_return_data: IndexMap<u64, OpReturnData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct Block {
    #[ts(type = "number")]
    pub height: u64,
    #[ts(type = "string")]
    pub hash: BlockHash,
    #[ts(type = "string")]
    pub prev_hash: BlockHash,
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub enum Signer {
    Core(Box<Signer>),
    XOnlyPubKey(String),
    ContractId {
        #[ts(type = "number")]
        id: i64,
        id_str: String,
    },
    Nobody,
}

impl Signer {
    pub fn new_contract_id(id: i64) -> Self {
        Self::ContractId {
            id,
            id_str: format!("__cid__{}", id),
        }
    }

    pub fn is_core(&self) -> bool {
        matches!(self, Signer::Core(_))
    }
}

impl core::ops::Deref for Signer {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Nobody => "nobody",
            Self::Core(_) => "core",
            Self::XOnlyPubKey(s) => s,
            Self::ContractId { id_str, .. } => id_str,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContractAddress {
    pub name: String,
    pub height: u64,
    pub tx_index: u64,
}

contract_address!(ContractAddress);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct OpMetadata {
    #[ts(as = "String")]
    pub previous_output: bitcoin::OutPoint,
    #[ts(type = "number")]
    pub input_index: i64,
    pub signer: Signer,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub enum Op {
    Publish {
        metadata: OpMetadata,
        #[ts(type = "number")]
        gas_limit: u64,
        name: String,
        bytes: Vec<u8>,
    },
    Call {
        metadata: OpMetadata,
        #[ts(type = "number")]
        gas_limit: u64,
        #[ts(as = "String")]
        #[serde_as(as = "DisplayFromStr")]
        contract: ContractAddress,
        expr: String,
    },
    Issuance {
        metadata: OpMetadata,
    },
}

impl Op {
    pub fn metadata(&self) -> &OpMetadata {
        match self {
            Op::Publish { metadata, .. } => metadata,
            Op::Call { metadata, .. } => metadata,
            Op::Issuance { metadata, .. } => metadata,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct BlockRow {
    #[ts(type = "number")]
    pub height: i64,
    #[ts(as = "String")]
    pub hash: BlockHash,
    #[builder(default = false)]
    pub relevant: bool,
}

impl From<&Block> for BlockRow {
    fn from(b: &Block) -> Self {
        Self {
            height: b.height as i64,
            hash: b.hash,
            relevant: !b.transactions.is_empty(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct TransactionRow {
    #[ts(type = "number")]
    #[builder(default = 0)]
    pub id: i64,
    pub txid: String,
    #[ts(type = "number")]
    pub height: i64,
    #[ts(type = "number")]
    pub tx_index: i64,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct ContractListRow {
    #[ts(type = "number")]
    pub id: i64,
    pub name: String,
    #[ts(type = "number")]
    pub height: i64,
    #[ts(type = "number")]
    pub tx_index: i64,
    #[ts(type = "number")]
    pub size: i64,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct PaginationMeta {
    #[ts(as = "String")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub next_cursor: Option<i64>,
    #[ts(type = "number | null")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<i64>,
    pub has_more: bool,
    #[ts(type = "number")]
    pub total_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct PaginatedResponse<T> {
    pub results: Vec<T>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct Info {
    pub version: String,
    pub target: String,
    pub network: String,
    pub available: bool,
    #[ts(type = "number")]
    pub height: i64,
    pub checkpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct TransactionHex {
    pub hex: String,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct OpWithResult {
    pub op: Op,
    pub result: Option<ResultRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct ViewExpr {
    pub expr: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
#[serde(tag = "type")]
pub enum ViewResult {
    Ok { value: String },
    Err { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct ContractResponse {
    pub wit: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub struct ResultRow {
    #[ts(type = "number")]
    pub id: i64,
    #[ts(type = "number")]
    pub height: i64,
    #[ts(type = "number")]
    pub tx_index: i64,
    #[ts(type = "number")]
    pub input_index: i64,
    #[ts(type = "number")]
    pub op_index: i64,
    #[ts(type = "number")]
    pub result_index: i64,
    pub func: String,
    #[ts(type = "number")]
    pub gas: i64,
    pub value: Option<String>,
    pub contract: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpReturnData {
    PubKey(XOnlyPublicKey),
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/src/bindings.d.ts")]
pub enum Inst {
    Publish {
        #[ts(type = "number")]
        gas_limit: u64,
        name: String,
        bytes: Vec<u8>,
    },
    Call {
        #[ts(type = "number")]
        gas_limit: u64,
        #[ts(type = "string")]
        #[serde_as(as = "DisplayFromStr")]
        contract: ContractAddress,
        expr: String,
    },
    Issuance,
}

pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(postcard::to_allocvec(value)?)
}

pub fn deserialize<T: for<'a> Deserialize<'a>>(buffer: &[u8]) -> Result<T> {
    Ok(postcard::from_bytes(buffer)?)
}

pub fn json_to_bytes<T: for<'a> Deserialize<'a> + Serialize>(json: String) -> Vec<u8> {
    let inst = serde_json::from_str::<T>(&json).expect("Invalid JSON string");
    serialize(&inst).expect("Failed to serialize to postcard")
}

pub fn bytes_to_json<T: for<'a> Deserialize<'a> + Serialize>(bytes: Vec<u8>) -> String {
    let inst = deserialize::<T>(&bytes).expect("Failed to deserialize from postcard");
    serde_json::to_string(&inst).expect("Failed to serialize to JSON")
}

pub fn inst_json_to_bytes(json: String) -> Vec<u8> {
    json_to_bytes::<Inst>(json)
}

pub fn inst_bytes_to_json(bytes: Vec<u8>) -> String {
    bytes_to_json::<Inst>(bytes)
}

pub fn op_return_data_json_to_bytes(json: String) -> Vec<u8> {
    json_to_bytes::<OpReturnData>(json)
}

pub fn op_return_data_bytes_to_json(bytes: Vec<u8>) -> String {
    bytes_to_json::<OpReturnData>(bytes)
}
