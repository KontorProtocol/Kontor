use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::batches::batch_is_ordered;
use super::mempool_fee_index::MempoolFeeIndex;

use malachitebft_app_channel::Channels;
use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::core::Round;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_core_types::{HeightParams, LinearTimeouts};

use prost::Message;
use sha3::Digest;

use crate::consensus::codec::decode_commit_certificate;
use crate::consensus::finality_types::*;
use crate::consensus::signing::Ed25519Provider;
use crate::consensus::{
    Address, Ctx, Genesis, Height, ProposalData, ProposalFin, ProposalInit, ProposalPart,
    ValidatorSet, Value,
};
use crate::database::queries::{
    delete_unexecuted_batch_suffix, get_checkpoint_latest, get_transaction_by_txid,
    min_unsettled_batch_tx_height, select_batches_from_anchor, select_batches_in_range,
    select_block_at_height, select_existing_txids, select_latest_consensus_height,
    select_min_batch_height, select_unconfirmed_batch_txs, select_unfinalized_batches,
};

/// Result from processing a consensus message.
pub enum ConsensusResult {
    /// No action needed by the reactor.
    None,
    /// A block was decided — the reactor should execute it.
    Block(indexer_types::Block, DeferredDecision),
    /// A batch was decided and executed — the reactor should emit a websocket event.
    BatchProcessed { txids: Vec<String> },
}

pub struct DeferredDecision {
    pub consensus_height: Height,
    pub value: Value,
    pub certificate: Vec<u8>,
    /// The txid list as DECIDED, retained when a rollback exclusion has narrowed
    /// `value` to the subset this node will actually execute.
    ///
    /// `batch_txids` must record what CONSENSUS decided, not what we ran: a peer
    /// syncing this height re-derives the exclusions itself by applying the same
    /// deadline rules, so it needs the full decided content. Recording the narrowed
    /// list would serve a value that no longer matches its own certificate.
    ///
    /// `None` when nothing was excluded, i.e. the two are the same list.
    pub certified_txids: Option<Vec<Txid>>,
}

/// A GetValue reply that we're holding until transactions arrive.
pub struct PendingProposal {
    pub height: Height,
    pub round: Round,
    pub reply: tokio::sync::oneshot::Sender<LocallyProposedValue<Ctx>>,
    pub timeout: Duration,
    pub created_at: Instant,
}

impl PendingProposal {
    /// Deadline at which we must propose (even an empty batch) before
    /// Malachite's propose timeout fires. Uses 80% of the propose timeout.
    pub fn hard_deadline(&self) -> Instant {
        self.created_at + self.timeout * 4 / 5
    }
}

/// All consensus-related state for the reactor.
pub struct ConsensusState {
    pub signing_provider: Ed25519Provider,
    pub address: Address,
    pub pending_transactions: HashMap<Txid, (bitcoin::Transaction, indexer_types::Transaction)>,
    /// Mempool-based fee estimator. Owned by ConsensusState; the reactor's
    /// mempool event loop mutates it directly, and `validate_transaction`
    /// borrows it via `&MempoolFeeIndex` from the call site.
    pub mempool_fee_index: MempoolFeeIndex,
    pub current_height: Height,
    pub current_round: Round,
    // Proposed values not yet decided, grouped by height then round. Grouping by
    // height lets `handle_finalized` find the decided value by value_id within the
    // height (the decided round can differ from the round we filed it under) and
    // drop every losing-round proposal for a height in one step once it's decided.
    pub undecided: BTreeMap<Height, BTreeMap<Round, ProposedValue<Ctx>>>,

    // Finality tracking
    pub unfinalized_batches: Vec<UnfinalizedBatch>,

    // Decided values waiting for block data or anchor block processing.
    // Used during sync (decisions arrive before blocks from poller) and
    // rollback replay (decisions replayed from DB while blocks redeliver).
    pub deferred_decisions: VecDeque<DeferredDecision>,

    // Blocks received from the poller, keyed by height. Consumed when a
    // Value::Block decision is finalized.
    pub pending_blocks: BTreeMap<u64, indexer_types::Block>,

    // Cached validator set — updated after each block decision.
    // Used by height_params() to provide Malachite with the current set.
    pub current_validator_set: ValidatorSet,

    // Observation channels (optional, for testing)
    pub observation: Option<ObservationChannels>,

    // Consensus timeouts — defaults to LinearTimeouts::default() (3s propose).
    pub timeouts: LinearTimeouts,

    // Held GetValue reply — waiting for pending_transactions to arrive.
    pub pending_proposal: Option<PendingProposal>,

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

/// Probe every batch whose deadline has passed, in the order `check_finality` will
/// evaluate them: `anchor_height` primary, so the first failure is the minimal
/// failing anchor.
///
/// Borrows rather than consuming ON PURPOSE. This is the only fallible step in the
/// verdict, and doing it against a borrow is what lets `check_finality` fail without
/// having already dismantled its own tracking set.
async fn probe_at_deadline(
    conn: &libsql::Connection,
    batches: &[UnfinalizedBatch],
    tip: u64,
) -> Result<Vec<Vec<Txid>>> {
    let mut order: Vec<&UnfinalizedBatch> = batches.iter().filter(|b| b.deadline <= tip).collect();
    order.sort_by_key(|b| (b.anchor_height, b.consensus_height));

    let mut missing_per_batch = Vec::with_capacity(order.len());
    for batch in order {
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
    let floor = match min_unsettled_batch_tx_height(conn, FINALITY_WINDOW).await {
        Ok(Some(oldest)) => oldest.min(tracking_floor(tip)),
        Ok(None) => tracking_floor(tip),
        Err(e) => {
            warn!(error = %e, "Unconfirmed-height probe failed; using the window floor");
            tracking_floor(tip)
        }
    };
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

/// Decide what an at-deadline set means, given each batch's unconfirmed txids.
/// Returns the events to emit and the batches that stay tracked.
///
/// `at_deadline` must be sorted by `(anchor_height, consensus_height)` and
/// `missing_per_batch` index-aligned with it. Split out as a pure function so the
/// partition — the part that decides whether nodes converge — is testable without
/// a database or a live `ConsensusState`.
fn build_finality_events(
    at_deadline: &[UnfinalizedBatch],
    missing_per_batch: &[Vec<Txid>],
    still_pending: Vec<UnfinalizedBatch>,
) -> (Vec<FinalityEvent>, Vec<UnfinalizedBatch>) {
    debug_assert_eq!(at_deadline.len(), missing_per_batch.len());
    let mut events = Vec::new();

    let Some(first_fail) = missing_per_batch.iter().position(|m| !m.is_empty()) else {
        for batch in at_deadline {
            info!(
                consensus_height = %batch.consensus_height,
                anchor = batch.anchor_height,
                "Batch finalized"
            );
            events.push(FinalityEvent::BatchFinalized {
                consensus_height: batch.consensus_height,
                anchor_height: batch.anchor_height,
            });
        }
        return (events, still_pending);
    };

    // Only batches strictly ahead of the first failure finalize. Everything from it
    // onward is replayed by this same rollback — the sort guarantees they all have
    // anchor_height >= from_anchor — so they are invalidated whether or not their
    // own txids confirmed. Finalizing one of them would announce a batch that is
    // about to be torn out, and dropping it from tracking silently left convergence
    // to an implicit replay invariant (#426).
    for batch in &at_deadline[..first_fail] {
        info!(
            consensus_height = %batch.consensus_height,
            anchor = batch.anchor_height,
            "Batch finalized"
        );
        events.push(FinalityEvent::BatchFinalized {
            consensus_height: batch.consensus_height,
            anchor_height: batch.anchor_height,
        });
    }

    let from_anchor = at_deadline[first_fail].anchor_height;
    let mut invalidated: Vec<Height> = at_deadline[first_fail..]
        .iter()
        .map(|b| b.consensus_height)
        .collect();

    // The exclusion set must cover every batch the rollback replays, not just the
    // first to fail: the replay reloads each one with its FULL certified content
    // (`batch_txids` is append-only and the exclusion filter is in-memory), so a
    // batch left out re-executes, re-arms the identical deadline, and rolls back
    // again with the complementary set — a cycle that never converges.
    let missing: Vec<Txid> = missing_per_batch[first_fail..]
        .iter()
        .flatten()
        .copied()
        .collect();

    let mut surviving = Vec::new();
    for pending in still_pending {
        if pending.anchor_height >= from_anchor {
            invalidated.push(pending.consensus_height);
        } else {
            surviving.push(pending);
        }
    }

    warn!(
        from_anchor,
        invalidated = ?invalidated,
        missing = missing.len(),
        "Cascade invalidation triggered"
    );

    events.push(FinalityEvent::Rollback {
        from_anchor,
        invalidated_batches: invalidated,
        missing_txids: missing,
    });

    (events, surviving)
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
        let current_validator_set = genesis.validator_set;

        // Forget the decided-but-unexecuted SUFFIX of consensus history —
        // committed to the batches table but never executed before the node
        // shut down; those consensus heights re-sync from peers. Children are
        // deleted first (the FKs carry no cascade — deliberately, see
        // schema.sql). A failure here must be LOUD: the old `if let Ok`
        // silently resumed consensus above decisions this node never executed
        // (#424).
        let (deleted, resume_floor) = delete_unexecuted_batch_suffix(&conn, last_block_height)
            .await
            .context("Failed to delete unexecuted batch suffix")?;
        if deleted > 0 {
            info!(
                deleted,
                resume_floor, last_block_height, "Deleted unexecuted batch suffix"
            );
        }

        let current_height = match select_latest_consensus_height(&conn).await {
            Ok(Some(h)) => {
                let resume = Height::new(h + 1);
                info!(%resume, "Resuming consensus from DB");
                resume
            }
            _ => Height::new(1),
        };

        // Rebuild finality tracking. Without this a restart inside the window drops
        // every pending deadline, so the node never performs a rollback its peers do
        // and its `transactions` table keeps rows theirs no longer have — the
        // divergence behind #515. Runs AFTER the suffix cleanup above, both so we
        // never re-track a batch it just deleted and because that cleanup is what
        // bounds the band on a lagging node (the anchor-mismatch record-only branch
        // writes rows at the PROPOSED higher anchor).
        let unfinalized_batches = load_unfinalized_batches(&conn, last_block_height)
            .await
            .context("Failed to rehydrate finality tracking")?;
        if !unfinalized_batches.is_empty() {
            info!(
                count = unfinalized_batches.len(),
                tip = last_block_height,
                "Rehydrated finality tracking"
            );
        }

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
            signing_provider,
            address,
            pending_transactions: std::collections::HashMap::new(),
            mempool_fee_index,
            current_height,
            current_round: Round::new(0),
            undecided: BTreeMap::new(),
            unfinalized_batches,
            deferred_decisions: VecDeque::new(),
            pending_blocks: BTreeMap::new(),
            current_validator_set,
            observation: None,
            timeouts: LinearTimeouts::default(),
            pending_proposal: None,
            channels,
            engine_handle,
            validator_index,
        })
    }

    /// Clear consensus state that is invalidated by a reorg rollback.
    /// Pending blocks, cached blocks, and in-flight batch data are all stale.
    pub async fn clear_on_rollback(
        &mut self,
        conn: &libsql::Connection,
        to_height: u64,
    ) -> Result<()> {
        self.pending_blocks.clear();
        self.deferred_decisions.clear();
        self.pending_proposal = None;
        // Finality tracking is RE-DERIVED, not cleared. Batches anchored at or below
        // the fork are untouched by the rollback — their `transactions` rows carry
        // `height = anchor_height` and survive the cascade — so discarding their
        // deadlines reopens exactly the #515 hole on the reorg path. Re-deriving
        // rather than filtering in memory also drops the batches whose anchor block
        // was replaced: the query joins the block CURRENTLY at that height by hash.
        // Propagate rather than clear on failure: an empty tracking set is exactly
        // the #515 divergence condition, and reaching it from a transient error
        // (SQLITE_BUSY, a WAL hiccup) would be silent. The sole caller sits in
        // `process_block_event`, which already returns `Result`, and the startup
        // path treats the same failure as fatal.
        self.unfinalized_batches = load_unfinalized_batches(conn, to_height)
            .await
            .context("Failed to re-derive finality tracking after rollback")?;
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
        let mut hasher = sha3::Keccak256::new();
        hasher.update(value.height.as_u64().to_be_bytes());
        hasher.update(value.round.as_i64().to_be_bytes());

        let data_part = match &value.value {
            Value::Batch {
                anchor_height,
                anchor_hash,
                txs,
                ..
            } => {
                hasher.update(anchor_height.to_be_bytes());
                hasher.update(anchor_hash.to_byte_array());
                for tx in txs {
                    hasher.update(tx.txid().to_byte_array());
                }
                ProposalData::new_batch(*anchor_height, *anchor_hash, value.value.batch_raw_txs())
            }
            Value::Block { height, hash } => {
                hasher.update(height.to_be_bytes());
                hasher.update(hash.to_byte_array());
                ProposalData::new_block(*height, *hash)
            }
        };

        let hash = hasher.finalize();
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

    pub async fn check_finality(
        &mut self,
        conn: &libsql::Connection,
        last_height: u64,
    ) -> Result<Vec<FinalityEvent>> {
        let mut events = Vec::new();
        let tip = last_height;

        // PROBE BEFORE TAKING THE SET APART. `missing_txids` is fallible, and
        // draining first would mean an unreadable table costs us the whole tracking
        // set — every pending deadline gone from memory, which is the #515 hole
        // reopened by the very code meant to close it. Borrowing for the probe makes
        // the early return leave `unfinalized_batches` exactly as it was, so the next
        // tip move simply retries.
        let missing_per_batch = probe_at_deadline(conn, &self.unfinalized_batches, tip).await?;

        // Every probe succeeded, so it is now safe to consume the set.
        let mut still_pending = Vec::new();
        let mut at_deadline = Vec::new();
        for batch in self.unfinalized_batches.drain(..) {
            if batch.deadline <= tip {
                at_deadline.push(batch);
            } else {
                still_pending.push(batch);
            }
        }

        // `from_anchor` below is taken from the FIRST failing batch, which is the
        // minimal failing anchor only because `anchor_height` is the PRIMARY sort
        // key here. Re-sorting by `consensus_height` alone would silently break it.
        //
        // This must reproduce `probe_at_deadline`'s order exactly, or the verdicts
        // line up against the wrong batches. It does: both collect the at-deadline
        // batches in ascending original-index order and then stable-sort on the same
        // key, so ties resolve identically.
        at_deadline.sort_by_key(|b| (b.anchor_height, b.consensus_height));
        debug_assert_eq!(
            at_deadline.len(),
            missing_per_batch.len(),
            "probe and partition disagree about which batches are at deadline"
        );

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

    pub async fn get_checkpoint(&self, conn: &libsql::Connection) -> Option<[u8; 32]> {
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

    pub(super) async fn get_decided_from_anchor(
        &self,
        conn: &libsql::Connection,
        from_anchor: u64,
    ) -> Result<Vec<DeferredDecision>> {
        let batches = select_batches_from_anchor(conn, from_anchor)
            .await
            .context("Failed to query batches from anchor")?;

        batches
            .into_iter()
            .map(|b| {
                let anchor_hash = b
                    .anchor_hash
                    .parse::<bitcoin::BlockHash>()
                    .context("Failed to parse anchor hash from DB")?;
                let value = if b.is_block {
                    Value::new_block(b.anchor_height, anchor_hash)
                } else {
                    let txids: Vec<Txid> = b
                        .txids
                        .iter()
                        .map(|s| s.parse().context("Failed to parse txid from DB"))
                        .collect::<Result<Vec<_>>>()?;
                    Value::new_batch(b.anchor_height, anchor_hash, txids)
                };
                Ok(DeferredDecision {
                    consensus_height: Height::new(b.consensus_height),
                    value,
                    certificate: b.certificate,
                    // Loaded straight from the decided record, so `value` already
                    // holds the certified content — nothing to preserve separately.
                    certified_txids: None,
                })
            })
            .collect()
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

    /// Raw transactions we still hold for a decided batch, for sync to attach.
    ///
    /// Deliberately unbounded by the finality window. Gating on it made every
    /// historical batch sync as txids only, and a peer that has to resolve a txid
    /// tries its mempool, then its DB, then bitcoind — none of which can produce a
    /// transaction that never confirmed and was excluded by a finality rollback.
    /// `resolve_batch_txs` then bails and the reactor exits, so a chain that had
    /// ever performed an exclusion was not reliably re-syncable from genesis.
    ///
    /// Serving whatever remains is self-limiting: `unconfirmed_batch_txs` rows are
    /// deleted on confirmation and by the startup suffix cleanup, so a batch whose
    /// transactions all confirmed has none and the only rows ever served are the
    /// otherwise-unresolvable ones.
    async fn load_raw_txs_if_unfinalized(
        &self,
        conn: &libsql::Connection,
        consensus_height: u64,
    ) -> Result<Option<Vec<bitcoin::Transaction>>> {
        let raw_bytes = select_unconfirmed_batch_txs(conn, consensus_height)
            .await
            .context("Failed to query unconfirmed batch txs")?;
        let txs: Vec<bitcoin::Transaction> = raw_bytes
            .iter()
            .map(|raw| {
                bitcoin::consensus::deserialize(raw)
                    .context("Failed to deserialize batch tx from DB")
            })
            .collect::<Result<Vec<_>>>()?;
        if txs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(txs))
        }
    }

    fn batch_to_decided(
        &self,
        b: &crate::database::types::BatchQueryResult,
    ) -> Result<(Value, crate::consensus::CommitCertificate<Ctx>)> {
        let anchor_hash = b
            .anchor_hash
            .parse::<bitcoin::BlockHash>()
            .context("Failed to parse anchor hash from DB")?;

        let value = if b.is_block {
            Value::new_block(b.anchor_height, anchor_hash)
        } else {
            let txids: Vec<Txid> = b
                .txids
                .iter()
                .map(|s| s.parse().context("Failed to parse txid from DB"))
                .collect::<Result<Vec<_>>>()?;
            Value::new_batch(b.anchor_height, anchor_hash, txids)
        };

        let proto = crate::consensus::proto::CommitCertificate::decode(b.certificate.as_slice())
            .context("Failed to decode commit certificate protobuf")?;
        let certificate =
            decode_commit_certificate(proto).context("Failed to decode commit certificate")?;

        Ok((value, certificate))
    }

    pub(super) async fn get_decided_range(
        &self,
        conn: &libsql::Connection,
        start: Height,
        end: Height,
    ) -> Result<Vec<(Value, crate::consensus::CommitCertificate<Ctx>)>> {
        let batches = select_batches_in_range(conn, start.as_u64(), end.as_u64())
            .await
            .context("Failed to query batches for sync range")?;

        let mut results = Vec::new();
        for b in &batches {
            let (mut value, cert) = self.batch_to_decided(b)?;

            if !b.is_block
                && let Some(raw_txs) = self
                    .load_raw_txs_if_unfinalized(conn, b.consensus_height)
                    .await?
            {
                value.set_raw_txs(raw_txs);
            }

            results.push((value, cert));
        }
        Ok(results)
    }

    pub(super) async fn min_decided_height(
        &self,
        conn: &libsql::Connection,
    ) -> Result<Option<Height>> {
        Ok(select_min_batch_height(conn)
            .await
            .context("Failed to query min batch height")?
            .map(Height::new))
    }

    /// Run finality checks. Returns the events produced and, if a rollback is needed,
    /// `(rollback_anchor, excluded_txids)`.
    ///
    /// Does NOT emit the events — the caller does, after deciding it can actually
    /// perform the rollback. The tracking set IS drained here either way; a caller
    /// that declines the rollback is expected to halt, which this node does.
    pub async fn run_finality_checks(
        &mut self,
        conn: &libsql::Connection,
        last_height: u64,
    ) -> Result<(Vec<FinalityEvent>, Option<(u64, HashSet<Txid>)>)> {
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
                missing_txids,
                ..
            } => {
                let excluded: HashSet<Txid> = missing_txids.iter().copied().collect();
                Some((*from_anchor, excluded))
            }
            _ => None,
        });
        // Deliberately NOT emitted here. A rollback the caller then refuses — because
        // it would reach below the prune watermark — must not be announced as though
        // it happened. The caller emits once it has committed to acting.
        Ok((finality_events, result))
    }

    /// Validate batch-level rules. Returns a rejection reason if any rule
    /// fails — the single gate every batch passes, at both propose time
    /// (`make_value`) and proposal-acceptance time
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
        if self.deferred_decisions.iter().any(|d| d.value.is_block()) {
            return Ok(Some("deferred block decision waiting"));
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
    use super::{UnfinalizedBatch, build_finality_events, missing_txids, probe_at_deadline};
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

    fn rollback_of(events: &[FinalityEvent]) -> (u64, Vec<Height>, Vec<Txid>) {
        let mut found = events.iter().filter_map(|e| match e {
            FinalityEvent::Rollback {
                from_anchor,
                invalidated_batches,
                missing_txids,
            } => Some((
                *from_anchor,
                invalidated_batches.clone(),
                missing_txids.clone(),
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

    /// The probe and the partition must agree on ORDER, or verdicts land against the
    /// wrong batches — and `from_anchor` is taken from the first failure, so a
    /// mismatch silently rolls back to the wrong anchor. They are two separate sorts
    /// over two separate collections; this pins that they agree, including on ties.
    #[tokio::test]
    async fn probe_order_matches_the_partition_order() {
        let (_reader, writer, _dir) = new_test_db().await.unwrap();
        let conn = writer.connection();

        // Deliberately out of order, with an anchor tie broken by consensus height.
        let tracked = vec![
            batch(502, 30, &[3]),
            batch(500, 20, &[1]),
            batch(500, 10, &[2]),
        ];
        let probed = probe_at_deadline(&conn, &tracked, 999)
            .await
            .expect("probe must read");

        let mut partitioned: Vec<_> = tracked.iter().filter(|b| b.deadline <= 999).collect();
        partitioned.sort_by_key(|b| (b.anchor_height, b.consensus_height));

        let probed_txids: Vec<_> = probed.into_iter().map(|m| m[0]).collect();
        let expected: Vec<_> = partitioned.iter().map(|b| b.txids[0]).collect();
        assert_eq!(
            probed_txids, expected,
            "probe results must line up with the partition, ties included"
        );
    }
}
