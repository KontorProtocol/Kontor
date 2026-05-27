extern crate alloc;

use anyhow::Result;
use bitcoin::hex::DisplayHex;
use bitcoin::{BlockHash, ScriptBuf, Txid, XOnlyPublicKey, taproot::LeafVersion};
use bon::Builder;
use macros::{contract_address, holder_ref};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use ts_rs::TS;
pub use wit_bindgen;

// ────────────────────────────────────────────────────────────────────
// Reveal-centric compose API
//
// `Reveal` is the universal input: it describes a Kontor reveal
// transaction — its participants (tap-leaf script-spend inputs), any
// additional non-Kontor inputs (key-path), and its outputs in order.
//
// Used as the body of three endpoints:
//   - compose:        builds whatever needs building (commits + reveal).
//                     If all participants are Existing, builds only the
//                     reveal. If any are Build, builds those commits too.
//   - compose_commit: builds only the commits for Build participants;
//                     returns the Reveal with their outpoints filled in.
//                     For the split-flow case (commit now, reveal later).
//   - compose_reveal: shorthand for compose where all participants are
//                     Existing; builds only the reveal PSBT.
//
// `CommitSource` per participant captures whether the commit already
// exists on chain (Existing) or needs to be built by this call (Build).
// The same Reveal value can drive all three endpoints — endpoint choice
// determines what gets built.
//
// Output structure is explicit: `extra_outputs` lists every non-paired
// output, and each `RevealParticipant.output` is the tx output at that
// participant's input index (for SACP alignment). No implicit defaults.
// ────────────────────────────────────────────────────────────────────

/// A complete description of a Kontor reveal tx. Used by `compose`,
/// `compose_commit`, and `compose_reveal`.
#[derive(Serialize, Deserialize, Clone, Builder, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct Reveal {
    /// Optional: when omitted, the server falls back to its currently
    /// published `fastest_fee` (sat/vB) from `/api/fees`.
    #[ts(type = "number | null")]
    pub sat_per_vbyte: Option<u64>,
    pub participants: Vec<RevealParticipant>,
    #[builder(default)]
    pub extra_inputs: Vec<ExtraInput>,
    #[builder(default)]
    pub extra_outputs: Vec<RevealOutput>,
}

/// One participant in the reveal: the tap-leaf script-spend input plus
/// the output paired with it (placed at the same index, which BIP-341
/// SIGHASH_SINGLE pre-signed signatures commit to).
#[derive(Serialize, Deserialize, Clone, Builder, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct RevealParticipant {
    pub x_only_public_key: String,
    pub commit_insts: Insts,
    /// Optional. The common seller-offer pattern (chained envelope +
    /// change in extras) leaves this unset; the marketplace swap sets
    /// it to the SACP-paired output (Change for buyer, Fixed for seller).
    pub output: Option<RevealOutput>,
    pub commit_source: CommitSource,
}

impl CommitSource {
    /// Construct a `CommitSource::Build` for a commit to be built by
    /// this call. Accepts any iterable of `OutPoint` for funding — the
    /// helper formats them into the wire-string shape internally.
    pub fn build(
        address: &bitcoin::Address,
        funding: impl IntoIterator<Item = bitcoin::OutPoint>,
    ) -> Self {
        Self::Build {
            address: address.to_string(),
            funding_utxo_ids: funding
                .into_iter()
                .map(|op| format!("{}:{}", op.txid, op.vout))
                .collect(),
        }
    }

    /// Construct a `CommitSource::Existing` for an already-on-chain commit.
    pub fn existing(outpoint: bitcoin::OutPoint, prevout: bitcoin::TxOut) -> Self {
        Self::Existing { outpoint, prevout }
    }
}

impl RevealOutput {
    /// Fixed-value output. Accepts a `ScriptBuf` (any output script type)
    /// and hex-encodes it internally for the wire shape.
    pub fn fixed(script: &bitcoin::Script, value: u64) -> Self {
        Self::Fixed {
            script_pubkey: script.as_bytes().to_lower_hex_string(),
            value,
        }
    }

    /// Auto-computed change to `script`. Hex-encodes internally.
    pub fn change(script: &bitcoin::Script) -> Self {
        Self::Change {
            script_pubkey: script.as_bytes().to_lower_hex_string(),
        }
    }

    /// Inscription envelope committing to `insts` with `internal_key` as
    /// the tap internal key. Takes the typed `XOnlyPublicKey`.
    pub fn chained_envelope(
        insts: Insts,
        value: u64,
        internal_key: bitcoin::XOnlyPublicKey,
    ) -> Self {
        Self::ChainedEnvelope {
            insts,
            value,
            internal_key: internal_key.to_string(),
        }
    }

    /// OP_RETURN with arbitrary data.
    pub fn op_return(data: Vec<u8>) -> Self {
        Self::OpReturn { data }
    }
}

/// Whether this participant's commit already exists on chain or needs
/// to be built by this call.
#[derive(Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub enum CommitSource {
    /// The commit already exists. Caller supplies the outpoint + prevout.
    Existing {
        #[ts(as = "String")]
        outpoint: bitcoin::OutPoint,
        #[ts(as = "TxOutSchema")]
        prevout: bitcoin::TxOut,
    },
    /// The commit needs to be built (by this call or a later one).
    /// Caller supplies funding for the commit tx.
    Build {
        address: String,
        funding_utxo_ids: Vec<String>,
    },
}

/// A non-Kontor input (key-path spend) bringing extra value into the
/// reveal — beyond what the tap-leaf participants contribute.
#[derive(Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct ExtraInput {
    #[ts(as = "String")]
    pub outpoint: bitcoin::OutPoint,
    #[ts(as = "TxOutSchema")]
    pub prevout: bitcoin::TxOut,
}

/// One output kind in a reveal tx. Appears either on a participant
/// (paired with that input's index, for SACP alignment) or in
/// `extra_outputs` (appended after all participant outputs in order).
///
/// `Change` is the only variant whose value is computed by the
/// indexer (= leftover after fees + fixed outputs). It may only appear
/// at the tx's *last* output position; the indexer errors if a non-last
/// Change would be sub-dust (skipping it would shift later outputs and
/// break SACP positioning).
#[derive(Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub enum RevealOutput {
    /// Fixed-value output. Caller specifies the exact value.
    Fixed { script_pubkey: String, value: u64 },
    /// Auto-computed change. Value = sum(inputs) − sum(other outputs) − fee.
    /// Must be the last output of the tx; sub-dust is silently dropped.
    Change { script_pubkey: String },
    /// Inscription envelope output committing to `insts` in a tap leaf
    /// with `internal_key` as the internal key. `value` is the output's
    /// sat amount.
    ChainedEnvelope {
        insts: Insts,
        value: u64,
        internal_key: String,
    },
    /// OP_RETURN with arbitrary data.
    OpReturn { data: Vec<u8> },
}

/// One commit transaction built by `compose_commit` / `compose`. There's
/// one entry per `CommitSource::Build` participant in the input `Reveal`,
/// in participant order.
#[derive(Serialize, Deserialize, Builder, Clone, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct CommitTx {
    #[ts(as = "String")]
    pub transaction: bitcoin::Transaction,
    pub transaction_hex: String,
    pub psbt_hex: String,
    /// Display-order txid — taproot witness data is segregated, so this
    /// equals the txid of the signed tx too. Provided so the SDK can
    /// reference this commit as a UTXO source without parsing the hex.
    pub txid: String,
    /// Value (sats) of the commit's change output at vout 1, or `None`
    /// when the leftover was sub-dust and silently dropped to fee.
    /// Compose computes this exactly (selected funding sum minus
    /// tap-output value minus commit fee), so the SDK gets it for free
    /// without parsing the signed commit hex.
    #[ts(type = "number | null")]
    pub change_value: Option<u64>,
}

/// Response from `compose_commit`: one `CommitTx` per Build participant,
/// plus the input `Reveal` with each Build participant's `CommitSource`
/// converted to `Existing` (outpoint + prevout filled in from the built
/// commit). The caller signs + broadcasts the commits, then later passes
/// the returned `reveal` to `compose_reveal` to build the reveal PSBT.
#[derive(Serialize, Deserialize, Builder, Clone, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct CommitOutputs {
    pub commits: Vec<CommitTx>,
    pub reveal: Reveal,
}

/// Response from `compose`: built commits (one per Build participant)
/// plus the built reveal PSBT. The caller signs each commit's input,
/// signs the reveal's tap-script-spend inputs (using
/// `RevealOutputs.commit_tap_leaf_scripts`), and broadcasts the package.
#[derive(Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct ComposeOutputs {
    pub commits: Vec<CommitTx>,
    pub reveal: RevealOutputs,
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

#[derive(Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct TxOutSchema {
    #[ts(type = "number")]
    pub value: u64,
    pub script_pubkey: String,
}

#[derive(Builder, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub struct RevealOutputs {
    #[ts(as = "String")]
    pub transaction: bitcoin::Transaction,
    pub transaction_hex: String,
    pub psbt_hex: String,
    /// Display-order txid. Taproot witness data is segregated, so the
    /// txid of the unsigned reveal here equals the signed-tx txid the
    /// SDK eventually broadcasts. Lets the SDK reference reveal
    /// outputs as UTXOs without parsing the hex.
    pub txid: String,
    /// Per-output kind + any extra info, in tx output order (same
    /// length as `transaction.output`). Each variant carries the
    /// output's value in sats — derivable from the tx but exposed
    /// here so the SDK can extract change UTXOs / inspect output
    /// values without parsing the raw hex.
    pub output_info: Vec<RevealOutputInfo>,
}

/// Per-output annotation describing what kind of output occupies each
/// position in the reveal tx. Mirrors the input `RevealOutput` enum.
/// Each variant carries the output's value in sats so the SDK can
/// extract change UTXOs / read fixed payouts without re-parsing the tx
/// hex; `ChainedEnvelope` additionally carries the tap leaf script the
/// chained output commits to (the future spender needs it).
#[derive(Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "../../../sdk/src/bindings.d.ts")]
pub enum RevealOutputInfo {
    Fixed {
        #[ts(type = "number")]
        value: u64,
    },
    Change {
        #[ts(type = "number")]
        value: u64,
    },
    ChainedEnvelope {
        #[ts(type = "number")]
        value: u64,
        tap_leaf_script: TapLeafScript,
    },
    /// Empty OP_RETURN — value is always 0 sats, so no field carried.
    OpReturn,
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
