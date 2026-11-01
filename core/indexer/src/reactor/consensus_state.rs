use std::collections::BTreeMap;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use bitcoin::Txid;
use libsql::Connection;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::batches::batch_is_ordered;
use super::mempool::Mempool;
use super::mempool_fee_index::MempoolFeeIndex;

use malachitebft_app_channel::Channels;
use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::core::Round;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_core_types::{HeightParams, LinearTimeouts};
use malachitebft_engine::host::Next;

use prost::Message;

use crate::bitcoin_follower::block::BlockInput;
use crate::consensus::codec::decode_commit_certificate;
use crate::consensus::finality_types::*;
use crate::consensus::signing::{Ed25519Provider, PublicKey};
use crate::consensus::{
    Address, CommitCertificate, Ctx, Genesis, Height, PartStreamsMap, ProposalData, ProposalFin,
    ProposalInit, ProposalPart, ProposalParts, Validator, ValidatorSet, Value, proto,
};
use crate::database::certified_history::{self, Status};
use crate::database::queries::{
    get_checkpoint_latest, get_transaction_by_txid, min_unsettled_batch_tx_height,
    select_block_at_height, select_existing_txids, select_unfinalized_batches,
};
use crate::protocol::coordinator::certified_input::EraContext;
pub use crate::protocol::coordinator::decision::DeferredDecision;
use crate::protocol::coordinator::v1::build_finality_events;

const MAX_EARLY_PROPOSALS: usize = 16;
const MAX_UNVERIFIED_EARLY_PROPOSALS: usize = 4;
const MAX_EARLY_PROPOSAL_BYTES: usize = 8 * 1024 * 1024;

/// Result from processing a consensus message.
pub enum ConsensusResult {
    /// No action needed by the reactor.
    None,
    /// A batch was decided and executed — the reactor should emit a websocket event.
    BatchProcessed { txids: Vec<String> },
}

/// A GetValue reply that we're holding until transactions arrive.
pub struct PendingProposal {
    pub height: Height,
    pub round: Round,
    pub reply: tokio::sync::oneshot::Sender<LocallyProposedValue<Ctx>>,
    pub hard_deadline: Instant,
}

/// All consensus-related state for the reactor.
pub struct ConsensusState {
    pub(super) pending_decision: Option<super::certified::PendingDecision>,
    pub(crate) protocol_context: EraContext,
    pub signing_provider: Ed25519Provider,
    pub address: Address,
    pub mempool: Mempool,
    /// Mempool-based fee estimator. Owned by ConsensusState; the reactor's
    /// mempool event loop mutates it directly, and `validate_transaction`
    /// borrows it via `&MempoolFeeIndex` from the call site.
    pub mempool_fee_index: MempoolFeeIndex,
    pub current_height: Height,
    pub current_round: Round,
    pub round_started_at: Instant,
    // The round's proposer, exactly as the engine chose it in StartedRound. Used
    // to authenticate proposal parts. It MUST come from the engine, not be
    // recomputed via `select_proposer`: the validator set is refreshed on every
    // block decision (order not canonical), so a recomputation done at
    // proposal-receipt time can disagree with the choice the engine made at
    // round start — a flaky "wrong proposer" rejection that stalls consensus.
    pub current_proposer: Option<Address>,
    // Reassembles received proposal-part streams so the whole proposal can be
    // authenticated (proposer + Fin signature) before any of it is trusted.
    pub part_streams: PartStreamsMap,
    // Proposed values not yet decided, grouped by height then round. Grouping by
    // height lets `handle_finalized` find the decided value by value_id within the
    // height (the decided round can differ from the round we filed it under) and
    // drop every losing-round proposal for a height in one step once it's decided.
    pub undecided: BTreeMap<Height, BTreeMap<Round, ProposedValue<Ctx>>>,

    // Optional observation state, never authoritative for execution.
    pub unfinalized_batches: Vec<UnfinalizedBatch>,

    // Blocks received from the poller, keyed by height. Consumed when a
    // Value::Block decision is finalized.
    pub pending_blocks: BTreeMap<u64, BlockInput>,

    // Cached validator set — updated after each block decision.
    // Used by height_params() to provide Malachite with the current set.
    pub current_validator_set: ValidatorSet,

    // Observation channels (optional, for testing)
    pub observation: Option<ObservationChannels>,

    // Consensus timeouts — defaults to LinearTimeouts::default() (3s propose).
    pub timeouts: LinearTimeouts,

    // Held GetValue reply — waiting for pending_transactions to arrive.
    pub pending_proposal: Option<PendingProposal>,

    // A decided block may arrive after its certificate; finish its lifecycle
    // before choosing the next height's validator set.
    pub pending_next_height: Option<(Height, tokio::sync::oneshot::Sender<Next<Ctx>>)>,
    pub early_proposals: Vec<(ProposalParts, usize)>,

    // Malachite engine channels and handle.
    pub channels: Channels<Ctx>,
    pub engine_handle: malachitebft_app_channel::EngineHandle,
    pub validator_index: Option<usize>,
}

pub struct ObservationChannels {
    pub decided_tx: mpsc::Sender<DecidedBatch>,
    pub finality_tx: mpsc::Sender<FinalityEvent>,
    pub state_tx: mpsc::Sender<StateEvent>,
}

// --- Finality tracking ---

/// The batch's txids that did NOT confirm on Bitcoin by its deadline.
///
/// Deliberately takes no tip: the verdict must be a function of the batch and the
/// `blocks`/`transactions` tables alone. Testing only that `confirmed_height` is
/// SET would make it a function of WHEN a node evaluates instead — `confirmed_height
/// <= last_height` always holds (a block sets `last_height` before it executes), so
/// a tx confirmed one block past the deadline reads missing to a node evaluating at
/// the deadline and confirmed to one evaluating later. Two honest nodes then
/// disagree about the same batch and one rolls back while the other finalizes it.
///
/// Fallible on purpose. "No row" and "could not read the table" are different
/// facts: the first is a verdict, the second is this node's own I/O failing, and
/// folding them together turns a transient SQLITE_BUSY or WAL hiccup into a
/// consensus decision. The damage is not transient — the resulting rollback
/// deletes the transaction's row and the replay drops it from the batch, so it is
/// later re-executed as an unbatched block transaction at a different height than
/// every peer used, and nothing detects the divergence because the decided value
/// carries no state root. Propagating instead costs a retry on the next tip move —
/// but ONLY because `probe_at_deadline` runs this against a borrow before
/// `check_finality` drains anything. Probing mid-drain would lose the whole tracking
/// set to a transient read error, which is #515 again from a new direction.
/// This matches `execute_block`'s handling of the same query and the reasoning
/// already written down in `clear_on_rollback`.
/// Authenticate a reassembled proposal: its `Init` proposer must be
/// `expected_proposer` (the proposer the ENGINE selected for this round), and the
/// `Fin` signature must cover `(height, round, data)` under that proposer's key.
///
/// The proposer identity is passed IN, never recomputed here via
/// `select_proposer`: the validator set is refreshed on every block decision and
/// carries no canonical order, so recomputing at proposal-receipt time races the
/// engine's round-start choice and rejects the genuine proposer. The public-key
/// lookup below is by address, so it is order-independent. Free function so the
/// check is unit-testable without a live `ConsensusState`.
pub(super) fn authenticate_proposal(
    validator_set: &ValidatorSet,
    expected_proposer: Address,
    parts: &ProposalParts,
) -> Result<(), String> {
    if parts.round == Round::Nil {
        return Err("proposal round is nil".to_string());
    }

    if parts.proposer != expected_proposer {
        return Err(format!(
            "wrong proposer: got {}, expected {expected_proposer}",
            parts.proposer
        ));
    }

    let fin = parts.fin().ok_or_else(|| "missing Fin part".to_string())?;
    let data = parts
        .data()
        .ok_or_else(|| "missing Data part".to_string())?;
    let proposer = validator_set
        .get_by_address(&parts.proposer)
        .ok_or_else(|| "proposer not in validator set".to_string())?;

    let hash = proposal_sign_hash(parts.height, parts.round, data);
    if proposer.public_key.verify(&hash, &fin.signature).is_err() {
        return Err("invalid proposal signature".to_string());
    }
    Ok(())
}

pub(super) fn proposal_sign_hash(height: Height, round: Round, data: &ProposalData) -> [u8; 32] {
    data.signing_digest(height, round)
}

async fn missing_txids(conn: &libsql::Connection, batch: &UnfinalizedBatch) -> Result<Vec<Txid>> {
    let mut missing = Vec::new();
    for txid in &batch.txids {
        let row = get_transaction_by_txid(conn, &txid.to_string())
            .await
            .with_context(|| format!("Failed to read transaction {txid} for a finality verdict"))?;
        let confirmed =
            row.is_some_and(|r| r.confirmed_height.is_some_and(|h| h <= batch.deadline));
        if !confirmed {
            missing.push(*txid);
        }
    }
    Ok(missing)
}

/// Probe every batch whose deadline has passed, in the caller's evaluation order.
///
/// Borrows rather than consuming ON PURPOSE. This is the only fallible step in the
/// verdict, and doing it against a borrow is what lets `check_finality` fail without
/// having already dismantled its own tracking set.
async fn probe_at_deadline(
    conn: &libsql::Connection,
    batches: &[UnfinalizedBatch],
    tip: u64,
) -> Result<Vec<Vec<Txid>>> {
    // Takes `batches` ALREADY in evaluation order (`check_finality` sorts in place
    // before calling) and filters stably, so the results line up with the caller's
    // partition by construction rather than by a second sort that has to agree.
    let mut missing_per_batch = Vec::new();
    for batch in batches.iter().filter(|b| b.deadline <= tip) {
        missing_per_batch.push(missing_txids(conn, batch).await?);
    }
    Ok(missing_per_batch)
}

/// Rebuild the in-memory finality-tracking set from disk at startup.
///
/// A batch is still tracked iff its anchor sits in the window ending at `tip`, so
/// this reconstructs exactly what a node that never restarted would be holding.
async fn load_unfinalized_batches(
    conn: &libsql::Connection,
    tip: u64,
) -> Result<Vec<UnfinalizedBatch>> {
    // The window floor assumes every deadline below it was already settled. A crash
    // between a tip advance and the settle that should have followed breaks that:
    // `advance` can execute several blocks inside one drain before `settle_finality`
    // runs, so the tip can pass a deadline that no verdict was ever rendered on, and
    // a fixed floor would then drop that batch from tracking permanently. Extend the
    // floor down to the oldest batch transaction still unconfirmed — the exact set
    // that can still be owed a verdict — so the range stays indexed rather than
    // becoming a full scan of `batches`.
    // A failed probe PROPAGATES rather than falling back to the window floor:
    // the fallback silently narrows the band, dropping exactly the crash-window
    // batches the extension exists to re-arm — permanently, since every later
    // reload repeats the same fold. Failing here is recoverable (restart,
    // re-probe); a batch dropped from tracking is not.
    let floor = min_unsettled_batch_tx_height(conn, FINALITY_WINDOW)
        .await
        .context("Failed to probe the unsettled-batch floor")?
        .map_or(tracking_floor(tip), |oldest| {
            oldest.min(tracking_floor(tip))
        });
    let rows = select_unfinalized_batches(conn, floor)
        .await
        .context("Failed to query unfinalized batches")?;
    let mut batches = Vec::with_capacity(rows.len());
    for row in rows {
        let anchor_hash = row
            .anchor_hash
            .parse::<bitcoin::BlockHash>()
            .with_context(|| format!("Bad anchor hash for batch {}", row.consensus_height))?;
        let txids = row
            .txids
            .iter()
            .map(|t| t.parse::<Txid>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("Bad txid for batch {}", row.consensus_height))?;
        batches.push(UnfinalizedBatch {
            consensus_height: Height::new(row.consensus_height),
            anchor_height: row.anchor_height,
            anchor_hash,
            txids,
            deadline: deadline_for(row.anchor_height),
        });
    }
    Ok(batches)
}

pub(super) async fn certified_startup(
    conn: &libsql::Connection,
) -> Result<(EraContext, Height, ValidatorSet)> {
    let frontier = certified_history::frontier(conn).await?;
    ensure!(
        frontier.status == Status::Ready,
        "certified history unavailable"
    );
    ensure!(
        frontier.closed_height == frontier.authenticated_height,
        "unfinished certified closure must recover before consensus startup"
    );
    let protocol_context = frontier
        .context
        .context("missing certified protocol context")?;
    if frontier.closed_height > 0 {
        let recovered = certified_history::closure::recover(conn, frontier.closed_height).await?;
        let completed =
            certified_history::completion::completed(conn, frontier.closed_height).await?;
        ensure!(
            Some(completed.id()?) == frontier.closure_id && completed.context == protocol_context,
            "startup closure frontier differs"
        );
        ensure!(
            recovered.head == completed.stage_head && recovered.remaining.is_empty(),
            "startup stage chain differs from completed closure"
        );
        ensure!(
            certified_history::closure::canonical_position(conn, protocol_context.chain).await?
                == completed.output,
            "startup canonical state differs from completed closure"
        );
    }
    let next = frontier
        .closed_height
        .checked_add(1)
        .context("consensus height exhausted")?;
    let authority = certified_history::committee(conn, next).await?;
    ensure!(
        authority.context == protocol_context,
        "historical committee context differs"
    );
    authority.validate()?;
    let current_validator_set = ValidatorSet::try_new(
        authority
            .members
            .iter()
            .map(|member| {
                Ok(Validator::new(
                    PublicKey::from_bytes(member.key)?,
                    member.power,
                ))
            })
            .collect::<Result<Vec<_>>>()?,
    )?;
    Ok((protocol_context, Height::new(next), current_validator_set))
}

impl ConsensusState {
    pub async fn new(
        conn: libsql::Connection,
        signing_provider: Ed25519Provider,
        genesis: Genesis,
        address: Address,
        last_block_height: u64,
        channels: Channels<Ctx>,
        engine_handle: malachitebft_app_channel::EngineHandle,
        validator_index: Option<usize>,
        mempool_fee_index: MempoolFeeIndex,
    ) -> Result<Self> {
        let (protocol_context, current_height, current_validator_set) =
            certified_startup(&conn).await?;
        ensure!(
            genesis.validator_set == current_validator_set,
            "engine startup committee differs from certified authority"
        );

        // Divergence probe, diagnostic only. A batch-executed transaction still
        // unconfirmed below the finality window is past the point where a rollback
        // can act on it, and if it later confirms this node dedups where a peer
        // executes — same ops, different heights, forked checkpoints. Deliberately a
        // WARNING rather than a startup refusal: the predicate has legitimate
        // transient hits (a node stopped between a deadline passing and its check),
        // and bricking a healthy validator is worse than the fork it screens for.
        match min_unsettled_batch_tx_height(&conn, FINALITY_WINDOW).await {
            Ok(Some(height)) if height < tracking_floor(last_block_height) => warn!(
                height,
                floor = tracking_floor(last_block_height),
                "Unconfirmed batch transaction below the finality window — this node may have \
                 diverged from its peers; compare checkpoints and re-sync if they differ"
            ),
            Ok(_) => {}
            Err(e) => warn!(error = %e, "Divergence probe failed"),
        }

        Ok(Self {
            pending_decision: None,
            protocol_context,
            signing_provider,
            address,
            mempool: Mempool::default(),
            mempool_fee_index,
            current_height,
            current_round: Round::new(0),
            round_started_at: Instant::now(),
            current_proposer: None,
            part_streams: PartStreamsMap::new(),
            undecided: BTreeMap::new(),
            unfinalized_batches: Vec::new(),
            pending_blocks: BTreeMap::new(),
            current_validator_set,
            observation: None,
            timeouts: LinearTimeouts::default(),
            pending_proposal: None,
            pending_next_height: None,
            early_proposals: Vec::new(),
            channels,
            engine_handle,
            validator_index,
        })
    }

    pub(super) async fn refresh_finality_observation(
        &mut self,
        conn: &Connection,
        tip: u64,
    ) -> Result<()> {
        self.unfinalized_batches = if self.observation.is_some() {
            load_unfinalized_batches(conn, tip).await?
        } else {
            Vec::new()
        };
        Ok(())
    }

    fn validator_set(&self) -> ValidatorSet {
        self.current_validator_set.clone()
    }

    pub(super) fn height_params(&self) -> HeightParams<Ctx> {
        HeightParams::new(self.validator_set(), self.timeouts, None)
    }

    fn stream_id(&self) -> StreamId {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.current_height.as_u64().to_be_bytes());
        bytes.extend_from_slice(
            &self
                .current_round
                .as_u32()
                .expect("stream_id called during active round, current_round must not be Nil")
                .to_be_bytes(),
        );
        StreamId::new(bytes.into())
    }

    pub(super) fn stream_proposal(
        &self,
        value: &LocallyProposedValue<Ctx>,
        pol_round: Round,
    ) -> Vec<StreamMessage<ProposalPart>> {
        let data_part = ProposalData::new(value.value.clone());

        // The Fin signature covers Init(height,round) + Data. `verify_proposal_parts`
        // recomputes the same preimage — keep both on `proposal_sign_hash` so they
        // cannot drift.
        let hash = proposal_sign_hash(value.height, value.round, &data_part);
        let signature = self.signing_provider.sign(&hash);

        let parts = vec![
            ProposalPart::Init(ProposalInit::new(
                value.height,
                value.round,
                pol_round,
                self.address,
            )),
            ProposalPart::Data(data_part),
            ProposalPart::Fin(ProposalFin::new(signature)),
        ];

        let stream_id = self.stream_id();
        let mut msgs = Vec::with_capacity(parts.len() + 1);

        for (seq, part) in parts.into_iter().enumerate() {
            msgs.push(StreamMessage::new(
                stream_id.clone(),
                seq as u64,
                StreamContent::Data(part),
            ));
        }
        msgs.push(StreamMessage::new(
            stream_id,
            msgs.len() as u64,
            StreamContent::Fin,
        ));

        msgs
    }

    /// Authenticate a reassembled proposal before any of it is trusted:
    ///
    /// 1. the `Init` proposer must be `expected_proposer` — the proposer the
    ///    ENGINE chose for this round (from `StartedRound`), and
    /// 2. the `Fin` signature must cover `(height, round, data)` under that
    ///    proposer's public key.
    ///
    /// Returns the rejection reason on failure so the caller can log and reply
    /// `None`. This is what a bare `Data` part (the old shortcut) could never
    /// satisfy: only the proposer's key produces a matching `Fin`.
    pub(super) fn verify_proposal_parts(
        &self,
        expected_proposer: Address,
        parts: &ProposalParts,
    ) -> Result<(), String> {
        authenticate_proposal(&self.current_validator_set, expected_proposer, parts)
    }

    pub(super) fn buffer_early_proposal(&mut self, parts: ProposalParts) {
        let height = self.current_height;
        let round = self.current_round;
        let same_height = parts.height == height;
        let next_height = height.as_u64().checked_add(1) == Some(parts.height.as_u64());
        let early_round = if round == Round::Nil {
            parts.round == Round::new(0)
        } else {
            parts.round.as_i64() == round.as_i64() + 1
                || (parts.round == round && self.current_proposer.is_none())
        };
        if parts.round == Round::Nil
            || !(same_height && early_round || next_height && parts.round == Round::new(0))
        {
            return;
        }

        // A next-height signer may join during execution of the previous block.
        // Reserve only a small part of the buffer for keys we cannot check yet;
        // every entry is authenticated again with the engine's eventual set.
        let known = self
            .current_validator_set
            .get_by_address(&parts.proposer)
            .is_some();
        if known {
            if self.verify_proposal_parts(parts.proposer, &parts).is_err() {
                return;
            }
        } else if same_height && round != Round::Nil {
            return;
        }

        if self.early_proposals.iter().any(|(p, _)| {
            p.height == parts.height
                && p.round == parts.round
                && p.proposer == parts.proposer
                && p.parts == parts.parts
        }) {
            return;
        }
        let bytes = parts.parts.iter().fold(0usize, |total, part| {
            total.saturating_add(part.to_sign_bytes().len())
        });
        if !known {
            let (count, unverified_bytes) = self
                .early_proposals
                .iter()
                .filter(|(p, _)| {
                    self.current_validator_set
                        .get_by_address(&p.proposer)
                        .is_none()
                })
                .fold((0, 0usize), |(count, total), (_, bytes)| {
                    (count + 1, total + bytes)
                });
            if count >= MAX_UNVERIFIED_EARLY_PROPOSALS
                || bytes > (MAX_EARLY_PROPOSAL_BYTES / 8).saturating_sub(unverified_bytes)
            {
                return;
            }
        }
        let buffered: usize = self.early_proposals.iter().map(|(_, bytes)| bytes).sum();
        if self.early_proposals.len() < MAX_EARLY_PROPOSALS
            && bytes <= MAX_EARLY_PROPOSAL_BYTES.saturating_sub(buffered)
        {
            debug!(%height, %round, proposal_height = %parts.height, proposal_round = %parts.round,
                "Buffering early proposal");
            self.early_proposals.push((parts, bytes));
        }
    }

    pub(super) fn take_early_proposal(
        &mut self,
        height: Height,
        round: Round,
        proposer: Address,
    ) -> Option<ProposalParts> {
        let mut accepted = None;
        self.early_proposals.retain(|(parts, _)| {
            if parts.height == height
                && parts.round == round
                && accepted.is_none()
                && authenticate_proposal(&self.current_validator_set, proposer, parts).is_ok()
            {
                debug!(%height, %round, %proposer, "Replaying early proposal");
                accepted = Some(parts.clone());
            }
            // Intermediate StartedRound messages must not erase later slots.
            (parts.height, parts.round) > (height, round)
        });
        accepted
    }

    pub async fn check_finality(
        &mut self,
        conn: &libsql::Connection,
        last_height: u64,
    ) -> Result<Vec<FinalityEvent>> {
        let mut events = Vec::new();
        let tip = last_height;

        // ONE definition of the evaluation order, established before anything reads
        // the set. `from_anchor` is taken from the FIRST failing batch, which is the
        // minimal failing anchor only because `anchor_height` is the PRIMARY key
        // here; sorting by `consensus_height` alone would silently break it. Sorting
        // in place means the probe and the partition below cannot disagree, rather
        // than sorting twice and asserting afterwards that they matched.
        self.unfinalized_batches
            .sort_by_key(|b| (b.anchor_height, b.consensus_height));

        // PROBE BEFORE TAKING THE SET APART. `missing_txids` is fallible, and
        // draining first would mean an unreadable table costs us the whole tracking
        // set — every pending deadline gone from memory, which is the #515 hole
        // reopened by the very code meant to close it. Borrowing for the probe makes
        // the early return leave `unfinalized_batches` exactly as it was, so the next
        // tip move simply retries.
        let missing_per_batch = probe_at_deadline(conn, &self.unfinalized_batches, tip).await?;

        // Every probe succeeded, so it is now safe to consume the set. The partition
        // is stable, so `at_deadline` inherits the sort above.
        let mut still_pending = Vec::new();
        let mut at_deadline = Vec::new();
        for batch in self.unfinalized_batches.drain(..) {
            if batch.deadline <= tip {
                at_deadline.push(batch);
            } else {
                still_pending.push(batch);
            }
        }

        let (built, surviving) = build_finality_events(
            &at_deadline,
            &missing_per_batch,
            std::mem::take(&mut still_pending),
        );
        events.extend(built);
        self.unfinalized_batches = surviving;
        Ok(events)
    }

    pub(super) fn emit_finality_events(&self, events: &[FinalityEvent]) {
        if let Some(obs) = &self.observation {
            for event in events {
                let _ = obs.finality_tx.try_send(event.clone());
            }
        }
    }

    pub fn emit_state_event(&self, event: StateEvent) {
        if let Some(obs) = &self.observation {
            let _ = obs.state_tx.try_send(event);
        }
    }

    /// The latest checkpoint hash — used ONLY to populate observation
    /// `StateEvent`s, so it short-circuits when nothing is observing. Every
    /// production node runs without observation channels (they are test-only
    /// wiring), and this is called on the consensus write connection per
    /// executed block, per decided batch, and per rollback — a wasted SQL round
    /// trip each time otherwise.
    pub async fn get_checkpoint(&self, conn: &libsql::Connection) -> Option<[u8; 32]> {
        self.observation.as_ref()?;
        match get_checkpoint_latest(conn).await {
            Ok(Some(row)) => {
                if let Ok(decoded) = hex::decode(&row.hash)
                    && decoded.len() == 32
                {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&decoded);
                    return Some(bytes);
                }
                None
            }
            _ => None,
        }
    }

    pub async fn block_hash_at_height(
        &self,
        conn: &libsql::Connection,
        height: u64,
    ) -> Option<bitcoin::BlockHash> {
        match select_block_at_height(conn, height).await {
            Ok(Some(row)) => Some(row.hash),
            _ => None,
        }
    }

    pub(super) async fn get_decided_range(
        &self,
        conn: &libsql::Connection,
        start: Height,
        end: Height,
    ) -> Result<Vec<(Value, CommitCertificate<Ctx>)>> {
        let frontier = certified_history::frontier(conn).await?;
        let mut results = Vec::new();
        for height in start.as_u64().max(1)..=end.as_u64().min(frontier.authenticated_height) {
            let certified = certified_history::load(conn, height).await?;
            let certificate =
                decode_commit_certificate(proto::CommitCertificate::decode(certified.proof())?)?;
            results.push((Value::from_input(certified.input().clone())?, certificate));
        }
        Ok(results)
    }

    pub(super) async fn min_decided_height(
        &self,
        conn: &libsql::Connection,
    ) -> Result<Option<Height>> {
        let frontier = certified_history::frontier(conn).await?;
        Ok((frontier.authenticated_height > 0).then(|| Height::new(1)))
    }

    /// Run finality checks. Returns the events produced and, if a rollback is needed,
    /// `(rollback_anchor, missing)` — the missing txids attributed to the decided
    /// batch each failed in (`Vec<BatchExclusion>`), deliberately never flattened:
    /// a flat set is how a global txid ban gets built by accident.
    ///
    /// Does NOT emit the events — the caller does, after deciding it can actually
    /// perform the rollback. The tracking set IS drained here either way; a caller
    /// that declines the rollback is expected to halt, which this node does.
    pub async fn run_finality_checks(
        &mut self,
        conn: &libsql::Connection,
        last_height: u64,
    ) -> Result<(Vec<FinalityEvent>, Option<(u64, Vec<BatchExclusion>)>)> {
        let finality_events = self.check_finality(conn, last_height).await?;
        // At most one Rollback per pass — `check_finality` folds every failing
        // at-deadline batch into a single event. Taking the FIRST rather than the
        // last matters if that ever regresses: last-wins would keep the highest
        // `from_anchor` and silently discard the lower ones' exclusions.
        debug_assert!(
            finality_events
                .iter()
                .filter(|e| matches!(e, FinalityEvent::Rollback { .. }))
                .count()
                <= 1,
            "check_finality must emit at most one Rollback"
        );
        let result = finality_events.iter().find_map(|event| match event {
            FinalityEvent::Rollback {
                from_anchor,
                missing,
                ..
            } => Some((*from_anchor, missing.clone())),
            _ => None,
        });
        // Deliberately NOT emitted here. A rollback the caller then refuses — because
        // it would reach below the prune watermark — must not be announced as though
        // it happened. The caller emits once it has committed to acting.
        Ok((finality_events, result))
    }

    /// Validate batch-level rules. Returns a rejection reason if any rule
    /// fails — the single gate every batch passes, at both propose time
    /// (`make_value_snapshot`) and proposal-acceptance time
    /// (`validate_and_accept_proposal`).
    pub(super) async fn validate_batch(
        &self,
        conn: &libsql::Connection,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        transactions: &[bitcoin::Transaction],
        last_height: u64,
        last_hash: bitcoin::BlockHash,
    ) -> Result<Option<&'static str>> {
        if !self.pending_blocks.is_empty() {
            return Ok(Some("block is pending"));
        }
        if anchor_height != last_height {
            return Ok(Some("anchor height mismatch"));
        }
        if anchor_hash != last_hash {
            return Ok(Some("anchor hash mismatch"));
        }
        // Dependency order is a consensus rule: a tx that spends another
        // batch tx's output must follow it. Rejecting here means a child
        // (e.g. a detach) can never be decided ahead of the parent (the
        // attach) that funds its escrow — so batch execution can trust
        // the decided order without re-sorting or re-checking.
        if !batch_is_ordered(transactions) {
            return Ok(Some("transactions not in dependency order"));
        }
        let txids: Vec<String> = transactions
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect();
        let existing = select_existing_txids(conn, &txids)
            .await
            .context("Failed to query existing txids")?;
        if !existing.is_empty() {
            return Ok(Some("contains already-processed transactions"));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        UnfinalizedBatch, build_finality_events, load_unfinalized_batches, missing_txids,
        probe_at_deadline,
    };
    use crate::consensus::Height;
    use crate::consensus::finality_types::FinalityEvent;
    use crate::database::queries::{confirm_transaction, insert_block, insert_transaction};
    use crate::test_utils::{new_mock_block_hash, new_test_db};
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, Txid};

    fn txid(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    /// A tracked batch at `anchor`, deadline `anchor + 6`, carrying `txids`.
    fn batch(consensus_height: u64, anchor: u64, txids: &[u8]) -> UnfinalizedBatch {
        UnfinalizedBatch {
            consensus_height: Height::new(consensus_height),
            anchor_height: anchor,
            anchor_hash: BlockHash::all_zeros(),
            txids: txids.iter().copied().map(txid).collect(),
            deadline: anchor + 6,
        }
    }

    /// Flattens `missing` for the assertions that only care about the union. The
    /// per-batch attribution itself is asserted by
    /// `every_missing_txid_is_attributed_to_its_own_batch`.
    fn rollback_of(events: &[FinalityEvent]) -> (u64, Vec<Height>, Vec<Txid>) {
        let mut found = events.iter().filter_map(|e| match e {
            FinalityEvent::Rollback {
                from_anchor,
                invalidated_batches,
                missing,
            } => Some((
                *from_anchor,
                invalidated_batches.clone(),
                missing.iter().flat_map(|m| m.txids.clone()).collect(),
            )),
            _ => None,
        });
        let first = found.next().expect("expected a Rollback event");
        assert!(found.next().is_none(), "expected exactly one Rollback");
        first
    }

    fn finalized_heights(events: &[FinalityEvent]) -> Vec<Height> {
        events
            .iter()
            .filter_map(|e| match e {
                FinalityEvent::BatchFinalized {
                    consensus_height, ..
                } => Some(*consensus_height),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn all_confirmed_finalizes_every_batch_and_rolls_back_nothing() {
        let at_deadline = vec![batch(1, 100, &[1]), batch(2, 100, &[2])];
        let missing = vec![vec![], vec![]];
        let pending = vec![batch(3, 105, &[3])];

        let (events, surviving) = build_finality_events(&at_deadline, &missing, pending);

        assert_eq!(
            finalized_heights(&events),
            vec![Height::new(1), Height::new(2)]
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, FinalityEvent::Rollback { .. }))
        );
        assert_eq!(surviving.len(), 1, "pending batch must stay tracked");
    }

    /// The #515 shape: two non-empty batches sharing one anchor, both failing.
    /// A per-batch exclusion set would empty one and leave the other full, so the
    /// replay re-arms the same deadline and the rollback never converges.
    #[test]
    fn exclusion_set_unions_every_failing_batch_in_the_band() {
        let at_deadline = vec![batch(557, 312469, &[1, 2, 3]), batch(628, 312469, &[4, 5])];
        let missing = vec![vec![txid(1), txid(2), txid(3)], vec![txid(4), txid(5)]];

        let (events, _) = build_finality_events(&at_deadline, &missing, Vec::new());
        let (from_anchor, invalidated, excluded) = rollback_of(&events);

        assert_eq!(from_anchor, 312469);
        assert_eq!(invalidated, vec![Height::new(557), Height::new(628)]);
        assert_eq!(
            excluded,
            vec![txid(1), txid(2), txid(3), txid(4), txid(5)],
            "both failing batches' txids must be excluded"
        );
    }

    /// A batch that PASSES but sorts at or after the first failure is still torn
    /// out by the rollback, so it must be invalidated rather than finalized —
    /// announcing it as final would contradict the rollback in the same pass.
    #[test]
    fn passing_batch_after_the_first_failure_is_invalidated_not_finalized() {
        let at_deadline = vec![
            batch(10, 100, &[1]), // passes, before the failure
            batch(11, 101, &[2]), // fails
            batch(12, 102, &[3]), // passes, but after
        ];
        let missing = vec![vec![], vec![txid(2)], vec![]];

        let (events, _) = build_finality_events(&at_deadline, &missing, Vec::new());
        let (from_anchor, invalidated, _) = rollback_of(&events);
        let finalized = finalized_heights(&events);

        assert_eq!(from_anchor, 101);
        assert_eq!(finalized, vec![Height::new(10)]);
        assert_eq!(invalidated, vec![Height::new(11), Height::new(12)]);
        for h in &finalized {
            assert!(
                !invalidated.contains(h),
                "{h} was both finalized and invalidated"
            );
        }
    }

    /// A PASSING batch that shares the failing batch's ANCHOR is torn out by the
    /// same rollback: the truncation goes to `from_anchor - 1`, deleting its
    /// anchor block, and the replay reloads everything anchored at or above
    /// `from_anchor`. Sorting puts it before the failure (lower consensus
    /// height), but index order is not the finalize boundary — anchor order is.
    /// Finalizing it would announce permanence for state the same pass deletes.
    #[test]
    fn passing_batch_sharing_the_failing_anchor_is_invalidated_not_finalized() {
        let at_deadline = vec![
            batch(10, 100, &[1]), // passes, same anchor as the failure
            batch(11, 100, &[2]), // fails
        ];
        let missing = vec![vec![], vec![txid(2)]];

        let (events, _) = build_finality_events(&at_deadline, &missing, Vec::new());
        let (from_anchor, invalidated, excluded) = rollback_of(&events);

        assert_eq!(from_anchor, 100);
        assert!(
            finalized_heights(&events).is_empty(),
            "a batch the rollback is about to tear out must not be finalized"
        );
        assert_eq!(invalidated, vec![Height::new(10), Height::new(11)]);
        assert_eq!(
            excluded,
            vec![txid(2)],
            "the passing batch replays in full — no exclusions for it"
        );
    }

    /// `from_anchor` comes from the first FAILING batch, which is minimal among
    /// failures only because `anchor_height` is the primary sort key.
    #[test]
    fn from_anchor_skips_passing_batches_at_lower_anchors() {
        let at_deadline = vec![batch(20, 100, &[1]), batch(21, 101, &[2])];
        let missing = vec![vec![], vec![txid(2)]];

        let (events, _) = build_finality_events(&at_deadline, &missing, Vec::new());
        let (from_anchor, _, _) = rollback_of(&events);

        assert_eq!(from_anchor, 101, "the passing batch at 100 must survive");
    }

    #[test]
    fn pending_batches_at_or_above_the_anchor_are_invalidated() {
        let at_deadline = vec![batch(30, 200, &[1])];
        let missing = vec![vec![txid(1)]];
        let pending = vec![
            batch(31, 199, &[2]),
            batch(32, 200, &[3]),
            batch(33, 201, &[4]),
        ];

        let (events, surviving) = build_finality_events(&at_deadline, &missing, pending);
        let (_, invalidated, _) = rollback_of(&events);

        assert_eq!(
            surviving
                .iter()
                .map(|b| b.consensus_height)
                .collect::<Vec<_>>(),
            vec![Height::new(31)],
            "only the batch anchored below from_anchor survives"
        );
        assert_eq!(
            invalidated,
            vec![Height::new(30), Height::new(32), Height::new(33)]
        );
    }

    /// The determinism property: a tx confirmed AFTER the deadline must read as
    /// missing no matter how far the tip has since advanced. Testing only that
    /// `confirmed_height` is set would make the verdict depend on when a node
    /// happens to evaluate, and two honest nodes would diverge.
    #[tokio::test]
    async fn confirmation_is_bounded_by_the_deadline() {
        let (_reader, writer, _dir) = new_test_db().await.unwrap();
        let conn = writer.connection();

        // Batch anchored at 10 → deadline 16. One tx confirms at 16 (in time),
        // the other at 17 (one block late).
        for height in [10, 16, 17] {
            insert_block(
                &conn,
                indexer_types::BlockRow::builder()
                    .height(height)
                    .hash(new_mock_block_hash(height as u32))
                    .relevant(true)
                    .build(),
            )
            .await
            .unwrap();
        }
        for (n, confirmed_at) in [(1u8, 16u64), (2u8, 17u64)] {
            insert_transaction(
                &conn,
                indexer_types::TransactionRow::builder()
                    .height(10)
                    .txid(txid(n).to_string())
                    .build(),
            )
            .await
            .unwrap();
            confirm_transaction(&conn, &txid(n).to_string(), confirmed_at, 0)
                .await
                .unwrap();
        }

        let b = batch(500, 10, &[1, 2]);
        assert_eq!(b.deadline, 16);
        assert_eq!(
            missing_txids(&conn, &b).await.expect("probe must read"),
            vec![txid(2)],
            "the tx confirmed at deadline+1 must count as missing"
        );

        // The same batch against the same tables gives the same answer regardless
        // of how far the chain has moved on — there is no tip input at all.
        assert_eq!(
            missing_txids(&conn, &b).await.expect("probe must read"),
            vec![txid(2)]
        );
    }

    #[tokio::test]
    async fn a_txid_with_no_row_counts_as_missing() {
        let (_reader, writer, _dir) = new_test_db().await.unwrap();
        let conn = writer.connection();
        let b = batch(500, 10, &[9]);
        assert_eq!(
            missing_txids(&conn, &b).await.expect("probe must read"),
            vec![txid(9)]
        );
    }

    /// "No row" is a verdict; "could not read the table" is this node's own I/O
    /// failing. Folding the second into the first turns a transient DB fault into a
    /// consensus rollback that excludes a transaction which DID confirm — and the
    /// damage outlives the fault, because the replay drops that tx and it is later
    /// re-executed as an unbatched block transaction at a height no peer used.
    /// Nothing detects the divergence: the decided value carries no state root.
    #[tokio::test]
    async fn an_unreadable_table_yields_an_error_not_a_verdict() {
        let (_reader, writer, _dir) = new_test_db().await.unwrap();
        let conn = writer.connection();

        // Stand-in for any read failure: with the table gone, the query errors
        // rather than returning "no such transaction".
        conn.execute("DROP TABLE transactions", ())
            .await
            .expect("drop transactions");

        let b = batch(500, 10, &[1]);
        assert!(
            missing_txids(&conn, &b).await.is_err(),
            "a failed read must propagate — reporting the txid as missing would \
             render a consensus verdict on a table this node could not read"
        );
    }

    /// The rehydration floor extension exists to re-arm batches whose deadline
    /// passed with no verdict rendered (a crash inside one drain). Folding a
    /// failed probe into "use the plain window floor" silently narrows the
    /// tracking band — dropping exactly those crash-window batches from tracking,
    /// permanently, since every later reload repeats the same fold. A failed read
    /// is recoverable by restart; a silently narrowed band is not.
    #[tokio::test]
    async fn a_failed_floor_probe_is_an_error_not_a_narrower_band() {
        let (_reader, writer, _dir) = new_test_db().await.unwrap();
        let conn = writer.connection();

        // Break ONLY the probe's query: it reads `height`, which nothing else on
        // the rehydration path touches (the `executed_batch_txids` view carries
        // batch_height/txid/id).
        conn.execute(
            "ALTER TABLE transactions RENAME COLUMN height TO height_hidden",
            (),
        )
        .await
        .expect("rename column");

        assert!(
            load_unfinalized_batches(&conn, 100).await.is_err(),
            "a failed floor probe must propagate — rehydrating from a silently \
             narrowed band drops crash-window batches from tracking permanently"
        );
    }

    /// `check_finality` sorts the tracking set IN PLACE once and both the probe and
    /// the partition then walk that same order — so they agree by construction rather
    /// than by a second sort that has to match. This pins the two properties that
    /// makes rest on: the probe filters by deadline, and it preserves input order.
    ///
    /// It matters because `from_anchor` is taken from the first failure. If the probe
    /// reordered relative to the partition, verdicts would land against the wrong
    /// batches and the rollback would target the wrong anchor.
    #[tokio::test]
    async fn the_probe_filters_by_deadline_and_preserves_input_order() {
        let (_reader, writer, _dir) = new_test_db().await.unwrap();
        let conn = writer.connection();

        // As `check_finality` hands it over: already in evaluation order.
        let mut tracked = vec![
            batch(502, 30, &[3]),
            batch(500, 20, &[1]),
            batch(500, 10, &[2]),
        ];
        tracked.sort_by_key(|b| (b.anchor_height, b.consensus_height));

        let probed = probe_at_deadline(&conn, &tracked, 999)
            .await
            .expect("probe must read");
        let probed_txids: Vec<_> = probed.into_iter().map(|m| m[0]).collect();
        let expected: Vec<_> = tracked.iter().map(|b| b.txids[0]).collect();
        assert_eq!(
            probed_txids, expected,
            "the probe must return results in the caller's order, ties included"
        );

        // Only the batches whose deadline has passed. `batch(_, anchor, _)` sets
        // deadline = anchor + 6, so a tip of 26 covers anchor 20 but not 30.
        let due = probe_at_deadline(&conn, &tracked, 26)
            .await
            .expect("probe must read");
        assert_eq!(
            due.len(),
            2,
            "only the two at-deadline batches may be probed"
        );
    }

    // C1: proposal-part authentication. A reassembled proposal is trusted only
    // if its Init proposer is the round's scheduled proposer AND the Fin
    // signature verifies under that proposer's key — the property a lone forged
    // Data part could never satisfy.
    mod proposal_auth {
        use super::super::{authenticate_proposal, proposal_sign_hash};
        use crate::consensus::Value;
        use crate::consensus::signing::PrivateKey;
        use crate::consensus::test_fixtures::context;
        use crate::consensus::{
            Address, Height, ProposalData, ProposalFin, ProposalInit, ProposalPart, ProposalParts,
            Validator, ValidatorSet,
        };
        use bitcoin::BlockHash;
        use bitcoin::hashes::Hash;
        use malachitebft_core_types::Round;

        fn key(seed: u8) -> PrivateKey {
            PrivateKey::from([seed; 32])
        }

        fn four_validators() -> (ValidatorSet, Vec<PrivateKey>) {
            let keys = vec![key(1), key(2), key(3), key(4)];
            let vs = ValidatorSet::new(keys.iter().map(|k| Validator::new(k.public_key(), 1)));
            (vs, keys)
        }

        fn addr(k: &PrivateKey) -> Address {
            Address::from_public_key(&k.public_key())
        }

        fn data() -> ProposalData {
            ProposalData::new(
                Value::new_batch_raw(context(), 5, BlockHash::all_zeros(), vec![]).unwrap(),
            )
        }

        fn parts(
            height: Height,
            round: Round,
            init_proposer: Address,
            signer: &PrivateKey,
            data: ProposalData,
        ) -> ProposalParts {
            let hash = proposal_sign_hash(height, round, &data);
            let signature = signer.sign(&hash);
            ProposalParts {
                height,
                round,
                proposer: init_proposer,
                parts: vec![
                    ProposalPart::Init(ProposalInit::new(height, round, Round::Nil, init_proposer)),
                    ProposalPart::Data(data),
                    ProposalPart::Fin(ProposalFin::new(signature)),
                ],
            }
        }

        #[test]
        fn accepts_the_expected_proposer_with_a_valid_signature() {
            let (vs, keys) = four_validators();
            let (height, round) = (Height::new(1), Round::new(0));
            let parts = parts(height, round, addr(&keys[0]), &keys[0], data());
            // The engine's proposer for this round is keys[0].
            assert!(authenticate_proposal(&vs, addr(&keys[0]), &parts).is_ok());
        }

        #[test]
        fn rejects_a_proposer_other_than_the_engine_selected_one() {
            let (vs, keys) = four_validators();
            let (height, round) = (Height::new(1), Round::new(0));
            // A different validator forges a fully self-consistent, self-signed
            // stream — Init.proposer and the Fin signature both keys[1] — but the
            // engine chose keys[0] for this round.
            let parts = parts(height, round, addr(&keys[1]), &keys[1], data());
            let err = authenticate_proposal(&vs, addr(&keys[0]), &parts).unwrap_err();
            assert!(err.contains("wrong proposer"), "{err}");
        }

        #[test]
        fn rejects_a_signature_from_another_key() {
            let (vs, keys) = four_validators();
            let (height, round) = (Height::new(1), Round::new(0));
            // Init claims the expected proposer (keys[0]) but the Fin is signed by
            // someone else — the squatter cannot produce the proposer's signature.
            let parts = parts(height, round, addr(&keys[0]), &keys[1], data());
            let err = authenticate_proposal(&vs, addr(&keys[0]), &parts).unwrap_err();
            assert!(err.contains("invalid proposal signature"), "{err}");
        }

        #[test]
        fn rejects_data_mutated_after_signing() {
            let (vs, keys) = four_validators();
            let (height, round) = (Height::new(1), Round::new(0));
            // Sign over the honest data, then swap the Data part for a different
            // anchor — the witness-carrying batch a malleator would substitute.
            let mut p = parts(height, round, addr(&keys[0]), &keys[0], data());
            p.parts[1] = ProposalPart::Data(ProposalData::new(
                Value::new_batch_raw(context(), 99, BlockHash::all_zeros(), vec![]).unwrap(),
            ));
            let err = authenticate_proposal(&vs, addr(&keys[0]), &p).unwrap_err();
            assert!(err.contains("invalid proposal signature"), "{err}");
        }
    }
}
