extern crate alloc;

use anyhow::Result;
use bitcoin::{BlockHash, FeeRate, ScriptBuf, TxOut, Txid, XOnlyPublicKey, taproot::LeafVersion};
use bon::Builder;
use macros::{contract_address, holder_ref};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use ts_rs::TS;
pub use wit_bindgen;

#[derive(Serialize, Deserialize, Clone, Builder, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct InstructionQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub funding_utxo_ids: String,
    pub insts: Insts,
    pub chained_insts: Option<Insts>,
}

#[derive(Serialize, Deserialize, Builder, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct ComposeQuery {
    pub instructions: Vec<InstructionQuery>,
    /// Optional: when omitted, the server falls back to its currently
    /// published `fastest_fee` (sat/vB) from `/api/fees`.
    #[ts(type = "number | null")]
    pub sat_per_vbyte: Option<u64>,
    #[ts(type = "number | null")]
    pub envelope: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
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
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct ParticipantScripts {
    pub address: String,
    pub x_only_public_key: String,
    pub commit_tap_leaf_script: TapLeafScript,
    pub chained_tap_leaf_script: Option<TapLeafScript>,
}

#[derive(Debug, Serialize, Deserialize, Builder, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
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
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct CommitOutputs {
    #[ts(as = "String")]
    pub commit_transaction: bitcoin::Transaction,
    pub commit_transaction_hex: String,
    pub commit_psbt_hex: String,
    pub reveal_inputs: RevealInputs,
}

#[derive(Serialize, Deserialize, Clone, Builder, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct RevealParticipantQuery {
    pub address: String,
    pub x_only_public_key: String,
    pub commit_vout: u32,
    pub commit_script_data: Vec<u8>,
    pub chained_instruction: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, TS, Clone, Builder)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct RevealQuery {
    pub commit_tx_hex: String,
    /// Optional: when omitted, the server falls back to its currently
    /// published `fastest_fee` (sat/vB) from `/api/fees`.
    #[ts(type = "number | null")]
    pub sat_per_vbyte: Option<u64>,
    pub participants: Vec<RevealParticipantQuery>,
    pub op_return_data: Option<Vec<u8>>,
    #[ts(type = "number | null")]
    pub envelope: Option<u64>,
}

#[derive(Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct TxOutSchema {
    #[ts(type = "number")]
    pub value: u64,
    pub script_pubkey: String,
}

#[derive(Clone, Serialize, Builder, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct RevealParticipantInputs {
    #[ts(as = "String")]
    pub address: bitcoin::Address,
    #[ts(as = "String")]
    pub x_only_public_key: XOnlyPublicKey,
    #[ts(as = "String")]
    pub commit_outpoint: bitcoin::OutPoint,
    #[ts(as = "TxOutSchema")]
    pub commit_prevout: TxOut,
    pub commit_tap_leaf_script: TapLeafScript,
    pub chained_instruction: Option<Vec<u8>>,
}

#[derive(Builder, Serialize, Clone, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
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
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct RevealOutputs {
    #[ts(as = "String")]
    pub transaction: bitcoin::Transaction,
    pub transaction_hex: String,
    pub psbt_hex: String,
    pub participants: Vec<ParticipantScripts>,
}

/// Request body for `POST /api/transactions/broadcast`: raw Bitcoin tx
/// hex in dependency order (e.g. `[commit, reveal]`), relayed to bitcoind
/// as a single `submitpackage`.
#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct BroadcastQuery {
    pub transactions: Vec<String>,
}

/// Response from `POST /api/transactions/broadcast`: the txid of the last
/// transaction in the package — the reveal, which carries the Kontor op
/// and is what callers wait on for results.
#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct BroadcastResult {
    pub txid: String,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct ResultResponse<T: TS> {
    pub result: T,
}

/// Reactor → consumers notification of indexer state changes. Consumed
/// in-process by the info-publisher and the reactor cluster tests; not
/// part of the public API surface, so it carries no `TS` export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Event {
    Processed { block: BlockRow, txids: Vec<String> },
    BatchProcessed { txids: Vec<String> },
    Rolledback { height: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct Input {
    #[ts(as = "String")]
    pub previous_output: bitcoin::OutPoint,
    #[ts(type = "number")]
    pub input_index: i64,
    #[ts(as = "String")]
    pub x_only_pubkey: XOnlyPublicKey,
    pub insts: Insts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct Transaction {
    #[ts(type = "string")]
    pub txid: Txid,
    #[ts(type = "number")]
    pub index: i64,
    pub inputs: Vec<Input>,
    /// OP_RETURN directives, one entry per reveal input that carries one.
    pub op_return_data: Vec<OpReturnEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct Block {
    #[ts(type = "number")]
    pub height: u64,
    #[ts(type = "string")]
    pub hash: BlockHash,
    #[ts(type = "string")]
    pub prev_hash: BlockHash,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct OutPoint {
    pub txid: String,
    pub vout: u64,
}

#[derive(Debug, Clone, Hash, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub enum HolderRef {
    XOnlyPubkey(String),
    SignerId(u64),
    Core,
    Burner,
    Utxo(OutPoint),
}

holder_ref!(HolderRef);

impl core::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
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
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct OpMetadata {
    #[ts(as = "String")]
    pub previous_output: bitcoin::OutPoint,
    #[ts(type = "number")]
    pub input_index: i64,
    #[ts(type = "number")]
    pub op_index: i64,
    #[ts(type = "number")]
    pub signer_id: u64,
    pub payment: Payment,
}

/// Resolved per-op execution payment, lives on `OpMetadata`.
///
/// `signer_id` is who funds this op's gas; `gas_limit` is the cap.
///
/// Derived from:
/// - Direct input, no `Sponsor`: `signer_id` = input signer, `gas_limit` = `Inst.gas_limit`.
/// - Direct input, prev-input `Sponsor` active: `signer_id` = sponsor's signer,
///   `gas_limit` = sponsor's cap (overrides `Inst.gas_limit`).
/// - Aggregate input, `AggregateSigner.sponsored = false`: `signer_id` =
///   co-signer, `gas_limit` = `Inst.gas_limit`.
/// - Aggregate input, `AggregateSigner.sponsored = true`: `signer_id` =
///   publisher (the input's signer), `gas_limit` = `Inst.gas_limit`.
///
/// `Issuance` carries a sentinel `Payment { signer_id: CORE_SIGNER_ID,
/// gas_limit: 0 }` since it's system-paid via the `Signer::Core` bypass
/// — the field exists for shape uniformity, not because Issuance funds
/// itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct Payment {
    #[ts(type = "number")]
    pub signer_id: u64,
    #[ts(type = "number")]
    pub gas_limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct AggregateInfo {
    /// One entry per op in `Insts.ops`, in parallel order. Binds each
    /// co-signer claim (existing `signer_id` or fresh x-only `PubKey`)
    /// to its nonce (replay protection) and to a `sponsored` flag (whether
    /// the publisher pays the op's gas).
    pub signers: Vec<AggregateSigner>,
    pub signature: Vec<u8>,
    // Publisher-sponsorship is no longer a separate `Option<u64>` on
    // AggregateInfo. The publisher commits to each sponsored op's cap
    // implicitly by signing the bulk — the cap is the per-Inst
    // `gas_limit`. Per-op opt-in lives on `AggregateSigner.sponsored`.
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct AggregateSigner {
    pub identity: SignerRef,
    #[ts(type = "number")]
    pub nonce: u64,
    /// `true` → this op's gas is paid by the publisher (the input's
    /// signer) up to `Inst.gas_limit`. `false` → co-signer self-pays up
    /// to `Inst.gas_limit`. The publisher commits by signing the bulk;
    /// the co-signer commits via their BLS signature contribution.
    pub sponsored: bool,
}

/// How a co-signer identifies themselves in an aggregate bulk.
///
/// - `Id(u64)` is compact (8 bytes) for users who already have a
///   `signer_id` from prior on-chain activity.
/// - `PubKey(XOnlyPublicKey)` is 32 bytes; used for first-time signers
///   who don't yet have a `signer_id`. The reactor resolves it via
///   `get_or_create_identity` during aggregate verification.
///
/// Identity binding comes from the BLS signature verification, not from
/// which variant is chosen — the variant only controls how to *index*
/// the verification key, not which key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub enum SignerRef {
    SignerId(#[ts(type = "number")] u64),
    XOnlyPubkey(#[ts(as = "String")] XOnlyPublicKey),
}

impl SignerRef {
    /// Build an `XOnlyPubkey` ref from an x-only pubkey hex string,
    /// validating that it is a real curve point. Used at the codec
    /// boundary, where the input is an untrusted string.
    pub fn pubkey_from_hex(hex: &str) -> Result<Self, String> {
        hex.parse::<XOnlyPublicKey>()
            .map(Self::XOnlyPubkey)
            .map_err(|e| format!("invalid x-only pubkey '{hex}': {e}"))
    }
}

/// `SignerRef` is exactly the two real-account arms of `HolderRef`;
/// this widening is total.
impl From<SignerRef> for HolderRef {
    fn from(value: SignerRef) -> Self {
        match value {
            SignerRef::SignerId(id) => HolderRef::SignerId(id),
            SignerRef::XOnlyPubkey(pk) => HolderRef::XOnlyPubkey(pk.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct Insts {
    pub ops: Vec<Inst>,
    pub aggregate: Option<AggregateInfo>,
}

impl Insts {
    pub fn direct(ops: Vec<Inst>) -> Self {
        Self {
            ops,
            aggregate: None,
        }
    }

    pub fn single(inst: Inst) -> Self {
        Self::direct(vec![inst])
    }

    pub fn is_aggregate(&self) -> bool {
        self.aggregate.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct Op {
    pub metadata: OpMetadata,
    pub kind: OpKind,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub enum OpKind {
    Publish {
        name: String,
        bytes: Vec<u8>,
    },
    Call {
        #[ts(as = "String")]
        #[serde_as(as = "DisplayFromStr")]
        contract: ContractAddress,
        expr: String,
    },
    Issuance,
    RegisterBlsKey {
        bls_pubkey: Vec<u8>,
        schnorr_sig: Vec<u8>,
        bls_sig: Vec<u8>,
    },
    /// Sponsor's on-chain effect: when this op is processed in the per-tx
    /// loop, the executor sets `pending_for_next` from the op's `Payment`
    /// (signer = sponsor; gas_limit = sponsor's cap). At the next input
    /// boundary, `pending_for_next` becomes `active` and overrides every
    /// op's Payment in that input. Sponsor itself does not call into a
    /// contract.
    Sponsor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
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
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct TransactionRow {
    #[ts(type = "number")]
    #[builder(default = 0)]
    pub id: i64,
    pub txid: String,
    #[ts(type = "number")]
    pub height: i64,
    #[ts(type = "number | null")]
    pub confirmed_height: Option<i64>,
    #[ts(type = "number | null")]
    pub tx_index: Option<i64>,
    #[ts(type = "number | null")]
    pub batch_height: Option<i64>,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
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
    #[ts(type = "number | null")]
    pub signer_id: Option<i64>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
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
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct PaginatedResponse<T> {
    pub results: Vec<T>,
    pub pagination: PaginationMeta,
}

/// Whether this node participates in consensus voting.
///
/// Surfaced in the `Info` response so operators monitoring the cluster
/// externally can confirm a pod's actual mode rather than just trusting
/// the config they passed in.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS, clap::ValueEnum,
)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
#[serde(rename_all = "lowercase")]
pub enum ConsensusMode {
    /// Signs votes and proposals.
    Validator,
    /// Sync-only; does not participate in consensus.
    #[default]
    Follower,
}

/// One entry in `Info::recent_blocks` — a `BlockRow` trimmed to the
/// fields the SDK needs for reorg detection (no `relevant` flag).
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct RecentBlock {
    #[ts(type = "number")]
    pub height: i64,
    #[ts(as = "String")]
    pub hash: BlockHash,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct Info {
    pub version: String,
    pub target: String,
    pub network: String,
    pub available: bool,
    pub consensus_mode: ConsensusMode,
    #[ts(type = "number")]
    pub height: i64,
    pub checkpoint: Option<String>,
    #[ts(type = "number | null")]
    pub consensus_height: Option<i64>,
    /// Highest `contract_results.id` — the SDK's forward cursor for
    /// draining `/api/results`. 0 when no results exist yet.
    #[ts(type = "number")]
    pub last_result_id: i64,
    /// The last 10 indexed blocks, height-descending. The SDK compares
    /// these against its local block-hash cache for reorg detection.
    pub recent_blocks: Vec<RecentBlock>,
    /// Hash of `last_result_id` + `recent_blocks`. Pass back as
    /// `?since=` to the long-poll endpoint; the request blocks until
    /// this value changes.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct TransactionHex {
    pub hex: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct Fees {
    /// Recommended fee rate (sat/vB) to land in the next ~1 block.
    #[ts(type = "number")]
    pub fastest: u64,
    /// Recommended fee rate (sat/vB) to land in roughly the next 3 blocks.
    #[ts(type = "number")]
    pub half_hour: u64,
    /// Recommended fee rate (sat/vB) to land in roughly the next 6 blocks.
    #[ts(type = "number")]
    pub hour: u64,
}

impl Fees {
    /// All three tiers floored to the same value. Used as the initial
    /// snapshot before the reactor has produced any projection, and as
    /// the reset state when the mempool's minimum fee changes — readers
    /// never see a value below the current Bitcoin Core mempool floor.
    pub fn floor(min_fee_sat_per_vb: u64) -> Self {
        Self {
            fastest: min_fee_sat_per_vb,
            half_hour: min_fee_sat_per_vb,
            hour: min_fee_sat_per_vb,
        }
    }
}

/// One entry per `Inst` in the input. `Materialized` means the op was
/// successfully materialized (had a runnable `Op`) and reached the runtime;
/// `Rejected` means materialization itself failed (currently only orphan
/// `Sponsored` ops with no publisher offer). Both variants carry an optional
/// `error_message` populated only on the `/transactions/simulate` endpoint;
/// `/inspect` always leaves it `None` since error strings aren't persisted.
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
#[serde(tag = "kind")]
#[allow(clippy::large_enum_variant)]
pub enum OpWithResult {
    Materialized {
        op: Op,
        result: Option<ResultRow>,
        error_message: Option<String>,
    },
    Rejected {
        #[ts(type = "number")]
        input_index: i64,
        #[ts(type = "number")]
        op_index: i64,
        error_message: Option<String>,
    },
}

impl OpWithResult {
    pub fn op(&self) -> Option<&Op> {
        match self {
            OpWithResult::Materialized { op, .. } => Some(op),
            OpWithResult::Rejected { .. } => None,
        }
    }

    pub fn result(&self) -> Option<&ResultRow> {
        match self {
            OpWithResult::Materialized { result, .. } => result.as_ref(),
            OpWithResult::Rejected { .. } => None,
        }
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            OpWithResult::Materialized { error_message, .. }
            | OpWithResult::Rejected { error_message, .. } => error_message.as_deref(),
        }
    }

    pub fn input_index(&self) -> i64 {
        match self {
            OpWithResult::Materialized { op, .. } => op.metadata.input_index,
            OpWithResult::Rejected { input_index, .. } => *input_index,
        }
    }

    pub fn op_index(&self) -> i64 {
        match self {
            OpWithResult::Materialized { op, .. } => op.metadata.op_index,
            OpWithResult::Rejected { op_index, .. } => *op_index,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct ViewExpr {
    pub expr: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
#[serde(tag = "type")]
pub enum ViewResult {
    Ok { value: String },
    Err { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct ContractResponse {
    pub wit: String,
}

/// What happened when this op ran. Persisted per row in `contract_results`.
///
/// - `Ok`: the contract function returned successfully.
/// - `ContractErr`: the function returned `result<_, error>::Err` — its state
///   mutations were rolled back, but the call itself completed cleanly.
/// - `OutOfFuel`: the call ran out of fuel mid-execution (either a host
///   import couldn't be charged, or wasmtime trapped on a fuel decrement).
/// - `Trap`: any non-fuel wasmtime trap — panic, unreachable, memory error.
/// - `Other`: a deterministic failure that doesn't fit the above (currently
///   uncommon for rows that get inserted — pre-execution rejections like
///   parse errors / contract-not-found don't reach `handle_procedure`).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub enum OpStatus {
    Ok,
    ContractErr,
    OutOfFuel,
    Trap,
    Other,
}

impl OpStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            OpStatus::Ok => "Ok",
            OpStatus::ContractErr => "ContractErr",
            OpStatus::OutOfFuel => "OutOfFuel",
            OpStatus::Trap => "Trap",
            OpStatus::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct ResultRow {
    #[ts(type = "number")]
    pub id: i64,
    #[ts(type = "number")]
    pub height: i64,
    #[ts(type = "number | null")]
    pub tx_index: Option<i64>,
    #[ts(type = "number | null")]
    pub input_index: Option<i64>,
    #[ts(type = "number | null")]
    pub op_index: Option<i64>,
    #[ts(type = "number")]
    pub result_index: i64,
    pub func: String,
    #[ts(type = "number")]
    pub gas: i64,
    /// Outcome category for this op. `Ok` for successful calls (regardless
    /// of whether the contract returned `ok(...)` or just a value); the
    /// failure variants distinguish what went wrong.
    pub status: OpStatus,
    pub value: Option<String>,
    pub contract: String,
    pub txid: Option<String>,
    #[ts(type = "number")]
    pub signer_id: i64,
    /// Who funded gas for this op. Equals `signer_id` for self-pay ops;
    /// for BLS-aggregate sponsored ops it's the publisher's signer_id.
    /// `null` for ops that don't go through user-side gas accounting.
    #[ts(type = "number | null")]
    pub payer_signer_id: Option<i64>,
}

/// One OP_RETURN directive bound to the reveal input it applies to:
/// where the asset detached by that input's op should land. A
/// transaction's OP_RETURN payload is a `Vec<OpReturnEntry>` — the
/// per-input binding kept as a plain list (not a map) so it is fully
/// expressible in WIT — `list<op-return-entry>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct OpReturnEntry {
    #[ts(type = "number")]
    pub input_index: u32,
    pub recipient: SignerRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct Inst {
    /// Gas cap for this op. Self-pay default — the input's signer is
    /// charged up to this amount.
    ///
    /// Overridden in two cases:
    /// - Direct context with a previous-input `Sponsor` Inst → the
    ///   Sponsor's own `gas_limit` is the cap and its signer is the payer.
    /// - BLS aggregate with `AggregateSigner.sponsored = true` → the
    ///   publisher (the input's signer) is the payer; `gas_limit` here is
    ///   the cap they signed off on by signing the bulk.
    ///
    /// Otherwise: input signer is payer; `gas_limit` is the cap.
    ///
    /// Sentinel `0` is used for ops the runtime pays for (currently only
    /// `InstKind::Issuance`, which bypasses gas accounting via `Signer::Core`).
    #[ts(type = "number")]
    pub gas_limit: u64,
    pub kind: InstKind,
}

impl Inst {
    /// Shorthand for an op that self-pays up to `gas_limit`.
    pub fn self_pay(gas_limit: u64, kind: InstKind) -> Self {
        Self { gas_limit, kind }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub enum InstKind {
    Publish {
        name: String,
        bytes: Vec<u8>,
    },
    Call {
        #[ts(type = "string")]
        #[serde_as(as = "DisplayFromStr")]
        contract: ContractAddress,
        expr: String,
    },
    Issuance,
    RegisterBlsKey {
        bls_pubkey: Vec<u8>,
        schnorr_sig: Vec<u8>,
        bls_sig: Vec<u8>,
    },
    /// A unilateral payer designation: the signer of the input carrying
    /// this `Sponsor` agrees to pay gas (up to the outer `Inst.gas_limit`)
    /// for every op in the *next* input. Those ops see this Sponsor's
    /// signer as `ctx.payer()` and run with this Sponsor's cap,
    /// overriding the next input's per-Inst `gas_limit`.
    ///
    /// Drives the marketplace swap path — the buyer's input carries a
    /// `Sponsor` and the escrow input that follows carries the detach,
    /// so the buyer pays the detach's gas and is the asset's recipient.
    /// Without a `Sponsor`, the next input's ops default to "payer =
    /// signer of that input" — which is exactly how revoke works: seller
    /// spends own escrow → payer = seller → detach back to seller.
    ///
    /// Sponsor itself is a directive consumed at materialization — it
    /// does not execute against a contract and produces no `OpResult`.
    /// At most one `Sponsor` per input; multiple → invalid batch. Not
    /// aggregatable (rejected in BLS-aggregate inputs).
    Sponsor,
}

impl Inst {
    /// Build the domain-separated signing message for one operation in an aggregate batch.
    ///
    /// Returns `KONTOR-OP-V1 || postcard((claim, nonce, sponsored, self))` —
    /// `claim` and `nonce` are the matching `AggregateSigner` entry's fields
    /// and `sponsored` is that entry's `sponsored` flag. Including `sponsored`
    /// in the signed bytes prevents the publisher from flipping a
    /// co-signer's choice after the fact (a publisher-side rug on who pays
    /// gas).
    ///
    /// Signing over the `SignerRef` rather than a resolved `signer_id` lets
    /// a brand-new co-signer (no `signer_id` yet) participate in aggregates:
    /// they sign over `SignerRef::XOnlyPubkey(self_x_only)`, which they
    /// know locally.
    pub fn aggregate_signing_message(
        &self,
        claim: &SignerRef,
        nonce: u64,
        sponsored: bool,
    ) -> Result<Vec<u8>> {
        const KONTOR_OP_PREFIX: &[u8] = b"KONTOR-OP-V1";
        let op_bytes = serialize(&(claim, nonce, sponsored, self))?;
        let mut msg = Vec::with_capacity(KONTOR_OP_PREFIX.len() + op_bytes.len());
        msg.extend_from_slice(KONTOR_OP_PREFIX);
        msg.extend_from_slice(&op_bytes);
        Ok(msg)
    }
}

pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(postcard::to_allocvec(value)?)
}

pub fn deserialize<T: for<'a> Deserialize<'a>>(buffer: &[u8]) -> Result<T> {
    Ok(postcard::from_bytes(buffer)?)
}

/// Parse `json` as a `T` and postcard-encode it. Both halves can fail
/// — malformed JSON, or a value that fails `T`'s own validation (an
/// x-only pubkey not on the curve, say) — so the error is returned, not
/// panicked: callers across the WASM boundary get a catchable string.
pub fn json_to_bytes<T: for<'a> Deserialize<'a> + Serialize>(
    json: String,
) -> Result<Vec<u8>, String> {
    let value = serde_json::from_str::<T>(&json).map_err(|e| e.to_string())?;
    serialize(&value).map_err(|e| e.to_string())
}

/// Postcard-decode `bytes` as a `T` and re-encode it as JSON.
pub fn bytes_to_json<T: for<'a> Deserialize<'a> + Serialize>(
    bytes: Vec<u8>,
) -> Result<String, String> {
    let value = deserialize::<T>(&bytes).map_err(|e| e.to_string())?;
    serde_json::to_string(&value).map_err(|e| e.to_string())
}

pub fn insts_json_to_bytes(json: String) -> Result<Vec<u8>, String> {
    json_to_bytes::<Insts>(json)
}

pub fn insts_bytes_to_json(bytes: Vec<u8>) -> Result<String, String> {
    bytes_to_json::<Insts>(bytes)
}

/// The full OP_RETURN payload of a Kontor transaction — one entry per
/// reveal input that carries a directive. This is what a reveal embeds
/// and what `block.rs` postcard-decodes when indexing.
pub type OpReturnPayload = Vec<OpReturnEntry>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct SignerResponse {
    #[ts(type = "number")]
    pub signer_id: u64,
    pub x_only_pubkey: Option<String>,
    pub bls_pubkey: Option<Vec<u8>>,
    #[ts(type = "number | null")]
    pub next_nonce: Option<u64>,
}
