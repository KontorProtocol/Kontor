use std::collections::HashSet;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_core_types::{Round, Validity};
use malachitebft_engine::host::Next;
use metrics::{counter, gauge};
use tracing::{debug, error, info, warn};

use crate::consensus::finality_types::{
    DecidedBatch, FINALITY_WINDOW, StateEvent, UnfinalizedBatch, deadline_for,
};
use crate::consensus::{Address, CommitCertificate, Ctx, Height, ProposalData, Value};
use crate::database::certified_history::{self, branch, replay_input, work};
use crate::database::queries::{
    delete_unconfirmed_batch_txs_below, insert_batch, insert_batch_txids, insert_transaction,
    insert_unconfirmed_batch_tx, min_unfinalized_batch_height, select_block_at_height,
    select_decision_exclusions, select_existing_txids,
};
use crate::metrics::{CONSENSUS_HEIGHT, DEFERRED_DECISIONS, ITEMS_INDEXED};
use crate::protocol::canonical_application::{ApplicationSource, DecisionExclusions};
use crate::protocol::canonical_input::CanonicalInput;
use crate::protocol::coordinator::application_closure::{StageOutcome, WorkItem};
use crate::protocol::coordinator::certified_input::{Command, ExactInput, MAX_BATCH_BYTES};
use crate::protocol::coordinator::closure_execution::begin_stage;
use crate::protocol::coordinator::linked::PreparedTransaction;
pub(super) use crate::protocol::coordinator::v1::batch_is_ordered;
use crate::protocol::coordinator::v1::dependency_sort;

use futures_util::future::BoxFuture;

use super::Reactor;
use super::consensus_state;
use super::execution::ExecutionContext;
use super::executor::{Executor, TxPolicy};
use super::mempool_fee_index::MempoolFeeIndex;
use crate::protocol::coordinator::selection::ExecutionSelection;

/// Multiplier applied to `MempoolFeeIndex::fastest_fee()` to derive the
/// per-batch acceptance threshold, as an integer ratio: 9/10 means we accept
/// txs at or above 90% of the median fee rate in projected block 0. Integer
/// math because this feeds proposal validation — a consensus-adjacent path
/// where float rounding is a determinism hazard (#429).
const FEE_THRESHOLD_NUM: u64 = 9;
const FEE_THRESHOLD_DEN: u64 = 10;

/// A consensus I/O job: bitcoind validation running OFF the event loop as an
/// owned future, paired with what to do with its verdicts. The loop races EVERY
/// in-flight job (`select_all`) as one arm of its root `select!`, so the reactor
/// keeps executing blocks, draining mempool events, and settling finality while
/// bitcoind is slow — and a stalled job never parks another whose reply the
/// engine is waiting on. Dropping the loop drops the in-flight RPCs, so shutdown
/// costs nothing (see `Executor::validate_txs`).
///
/// State is read twice, never held across the I/O: a SNAPSHOT phase collects
/// candidates and cheap-rejects on the loop, and the APPLY phase re-checks
/// every state predicate before acting on the verdicts — an answer is judged
/// when it is USED, not when the I/O started.
pub(super) struct IoJob {
    /// The transactions ride THROUGH the future and come back paired with
    /// their verdicts — the apply site never zips two vectors (a short one
    /// would silently truncate) and never re-clones the candidate set.
    pub(super) verdicts: BoxFuture<'static, Result<Vec<(bitcoin::Transaction, TxPolicy)>>>,
    pub(super) apply: IoApply,
}

pub(super) enum IoApply {
    /// `make_value_snapshot`'s candidate set: on apply, fulfill the held
    /// GetValue reply (if it still stands) with the surviving transactions.
    BuildProposal {
        selection: ExecutionSelection,
        anchor_height: u64,
        anchor_hash: BlockHash,
    },
    /// An incoming batch proposal: on apply, accept (file under `undecided`,
    /// release the engine's reply with `Some`) or reject (`None`).
    ValidateProposal {
        value: Value,
        selection: ExecutionSelection,
        height: Height,
        round: Round,
        /// The authenticated proposer, carried through so the stored
        /// `ProposedValue` is attributed to it rather than to this node.
        proposer: Address,
        anchor_height: u64,
        anchor_hash: BlockHash,
        /// Parses aligned with the future's pairs — same source order.
        parsed: Vec<PreparedTransaction>,
        reply: tokio::sync::oneshot::Sender<Option<ProposedValue<Ctx>>>,
    },
}

/// A candidate set whose bitcoind verdicts came back after the proposal they
/// were meant for was already answered (the deadline proposed empty, or the
/// engine moved on). Banked for the NEXT proposal instead of burned: with the
/// verdicts discarded, a validation latency persistently above the proposal
/// deadline re-validates the same pool every round and proposes empty forever
/// while user transactions sit pooled. Anchor-tagged, judged at USE: consumed
/// only if the anchor still matches, and membership in the pool is re-checked
/// then (see `try_fulfill_pending_proposal`).
pub(super) struct ValidatedCandidates {
    pub(super) selection: ExecutionSelection,
    pub(super) anchor_height: u64,
    pub(super) anchor_hash: BlockHash,
    pub(super) txs: Vec<bitcoin::Transaction>,
}

struct ProposalSnapshot {
    selection: ExecutionSelection,
    txs: Vec<bitcoin::Transaction>,
    threshold: u64,
}

/// Compute the per-batch fee acceptance threshold (sat/vB). Hoisted out
/// of `validate_transaction` so callers compute it once per validation
/// pass rather than per-tx.
///
/// Floored at `min_fee` so the threshold can never drop below
/// bitcoind's actual mempool floor — even if `fastest_fee` is somehow
/// stale, zero, or recently reset to a low value (e.g., after a ZMQ
/// reconnect's Sync). Defense in depth against effectively disabling
/// fee validation.
fn compute_fee_threshold(fee_index: &MempoolFeeIndex) -> u64 {
    let raw = fee_index.fastest_fee().saturating_mul(FEE_THRESHOLD_NUM) / FEE_THRESHOLD_DEN;
    raw.max(fee_index.min_fee())
}

/// What `process_decided_batch` did with a decided batch. Callers must not
/// announce `RecordedOnly` batches as processed — their transactions were
/// never executed here.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum BatchOutcome {
    /// Executed and committed at its anchor.
    Executed,
    /// Recorded for sync/bookkeeping only (unparseable input or anchor mismatch).
    RecordedOnly,
}

impl BatchOutcome {
    /// The txids to announce as processed for this outcome.
    ///
    /// An exhaustive match rather than `== Executed` at each call site: a future
    /// variant added without revisiting them would silently take the "nothing
    /// happened" branch, dropping the `BatchProcessed` heartbeat that drives the
    /// info publisher and therefore API availability.
    pub(super) fn announced_txids(
        &self,
        batch_txs: &[bitcoin::Transaction],
    ) -> Option<Vec<String>> {
        match self {
            BatchOutcome::Executed => Some(
                batch_txs
                    .iter()
                    .map(|tx| tx.compute_txid().to_string())
                    .collect(),
            ),
            // Empty batches still announce (with no txids): BatchProcessed is the
            // "chain moved" heartbeat, and on a quiet chain empty deadline batches
            // are the only events produced. A non-empty record-only skip stays
            // silent — nothing executed, and claiming otherwise is the audit bug.
            BatchOutcome::RecordedOnly if batch_txs.is_empty() => Some(Vec::new()),
            BatchOutcome::RecordedOnly => None,
        }
    }
}

pub(super) struct AppliedBatch {
    pub(super) outcome: BatchOutcome,
    pub(super) parsed_count: usize,
    pub(super) executed_ops: u64,
}

impl<E: Executor> ExecutionContext<E> {
    /// Persist a decided batch's certified content, idempotently: the
    /// immutable txid list (`batch_txids`, what sync serves for this
    /// consensus height) and the raw txs (`unconfirmed_batch_txs`, what
    /// replay and unfinalized-batch sync resolve from). Written for executed
    /// AND record-only batches — the certificate covers both.
    ///
    /// BOTH tables record the DECIDED list when a rollback has narrowed this
    /// batch (`certified`, when the caller has it): `batch_txids` because that is
    /// what the certificate covers and a syncing peer re-derives the exclusions
    /// itself, and `unconfirmed_batch_txs` because an excluded transaction never
    /// confirmed — this node's copy of its body is the only one a peer can ever
    /// obtain, so dropping it leaves the height unresolvable.
    ///
    /// Note `insert_batch_txids` is `INSERT OR IGNORE` on `(batch_height, position)`,
    /// which protects an already-complete list from being overwritten — but only
    /// where rows already exist. A node where this batch was never executed has
    /// none, so what we pass here is what becomes the record.
    async fn record_batch_txs(
        &mut self,
        conn: &libsql::Connection,
        consensus_height: Height,
        batch_txs: &[bitcoin::Transaction],
        certified: Option<&[bitcoin::Transaction]>,
    ) -> Result<()> {
        // Both lists come from the DECIDED set when a replay has narrowed this batch:
        // `batch_txids` because that is what consensus agreed (I4), and the raw
        // bodies because an EXCLUDED transaction never confirmed, so this node's copy
        // is the only one a syncing peer can ever obtain. Recording only what we
        // executed leaves that height permanently unresolvable.
        let decided: &[bitcoin::Transaction] = certified.unwrap_or(batch_txs);
        let txids: Vec<String> = decided
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect();
        insert_batch_txids(conn, consensus_height.as_u64(), &txids)
            .await
            .context("Failed to insert batch txids")?;
        for raw_tx in decided {
            let txid = raw_tx.compute_txid();
            let serialized = bitcoin::consensus::serialize(raw_tx);
            insert_unconfirmed_batch_tx(
                conn,
                &txid.to_string(),
                consensus_height.as_u64(),
                &serialized,
            )
            .await
            .context("Failed to insert unconfirmed batch tx")?;
        }
        Ok(())
    }

    /// Record a decided batch WITHOUT executing it: the `batches` row plus its
    /// certified content, so a syncing peer can still fetch what consensus
    /// decided. The single "recorded, not run" path — both the anchor-mismatch
    /// skip and the unparseable-tx skip funnel through here so they cannot drift.
    async fn record_batch_for_sync(
        &mut self,
        conn: &libsql::Connection,
        consensus_height: Height,
        anchor_height: u64,
        anchor_hash: BlockHash,
        certificate: &[u8],
        batch_txs: &[bitcoin::Transaction],
        certified: Option<&[bitcoin::Transaction]>,
    ) -> Result<BatchOutcome> {
        insert_batch(
            conn,
            consensus_height.as_u64(),
            anchor_height,
            &anchor_hash.to_string(),
            certificate,
            false,
        )
        .await
        .context("Failed to record batch for sync")?;
        self.record_batch_txs(conn, consensus_height, batch_txs, certified)
            .await?;
        Ok(BatchOutcome::RecordedOnly)
    }

    pub(super) async fn process_decided_batch(
        &mut self,
        anchor_height: u64,
        anchor_hash: BlockHash,
        consensus_height: Height,
        certificate: &[u8],
        batch_txs: &[bitcoin::Transaction],
        // The DECIDED transactions, when a rollback exclusion has narrowed
        // `batch_txs`. Recorded instead of the executed set — see `record_batch_txs`.
        certified: Option<&[bitcoin::Transaction]>,
    ) -> Result<AppliedBatch> {
        let conn = self.db_conn();
        let closure_height = certified_history::frontier(&conn)
            .await?
            .authenticated_height;
        let stage = begin_stage(
            &self.owner_service,
            &self.session,
            self.network,
            closure_height,
        )
        .await?
        .context("batch application has no pending closure stage")?;
        let remaining = stage.remaining_after();
        let result = async {
            let frozen = match stage.action() {
                WorkItem::Execute { decision } if decision == consensus_height.as_u64() => None,
                WorkItem::Replay { decision, input } if decision == consensus_height.as_u64() => {
                    let origin = work::published(&conn, remaining.plan).await?.origin;
                    Some(replay_input::get(&conn, input, origin, decision).await?)
                }
                _ => bail!("batch application differs from closure work item"),
            };
            let retained = certified_history::load(&conn, consensus_height.as_u64()).await?;
            let expected = ExactInput::batch(
                self.protocol_context,
                anchor_height,
                anchor_hash,
                certified.unwrap_or(batch_txs),
            )?;
            ensure!(
                *retained.input() == expected,
                "batch application differs from retained certified bytes"
            );
            if let Some(frozen) = &frozen {
                ensure!(
                    frozen.transactions(certified.unwrap_or(batch_txs))? == batch_txs,
                    "batch execution subset differs from frozen replay input"
                );
                ensure!(
                    self.last_height == anchor_height && self.last_hash == Some(anchor_hash),
                    "selected replay batch has a different anchor"
                );
            }
            let selection = stage.selection();
            // A decided batch may only EXECUTE against the exact chain state it was
            // anchored to: the local tip must sit at `anchor_height` with
            // `anchor_hash`. Anything else — a deferred drain whose anchor fell
            // behind, or a replay whose anchor block was reorged away — is recorded
            // for sync/bookkeeping but NOT executed: executing against a different
            // tip writes state (and a checkpoint) at a height the chain disagrees
            // about, i.e. silent divergence. A skipped batch's txids then simply
            // never confirm here and the finality window resolves it.
            let local_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());
            if anchor_height != self.last_height || anchor_hash != local_hash {
                warn!(
                    anchor_height,
                    %anchor_hash,
                    last_height = self.last_height,
                    %local_hash,
                    consensus_height = %consensus_height,
                    "Skipping decided batch — anchor does not match local tip; recording only"
                );
                let outcome = self
                    .record_batch_for_sync(
                        &conn,
                        consensus_height,
                        anchor_height,
                        anchor_hash,
                        certificate,
                        batch_txs,
                        certified,
                    )
                    .await?;
                return Ok((outcome, StageOutcome::ReplacedAnchorBatch, 0usize, 0u64));
            }

            // Execute in decided order. `validate_batch` enforces dependency
            // order at propose/accept time, so a decided batch — carrying 2/3+
            // signatures — is already ordered; no re-sort or re-check here.
            //
            // A parse failure here is a DETERMINISTIC content fact — parsing decided
            // bytes reads no chain state, so every node fails identically — which per
            // I5 must be handled the same everywhere and must NOT be node-fatal: a
            // `?` here halts the whole chain (each node exits, re-syncs the same value,
            // exits again). Proposal validation normally rejects unparseable txs before
            // they are decided; if one is decided anyway, record the batch for sync and
            // skip execution uniformly, rather than crash-looping the network.
            let parsed_txs: Vec<PreparedTransaction> = {
                let mut parsed = Vec::with_capacity(batch_txs.len());
                let mut bad: Option<Txid> = None;
                for btx in batch_txs {
                    match self
                        .executor
                        .prepare_transaction(&self.recognizer, selection, btx)?
                    {
                        Some(p) => parsed.push(p),
                        None => {
                            bad = Some(btx.compute_txid());
                            break;
                        }
                    }
                }
                if let Some(txid) = bad {
                    error!(
                        %txid,
                        consensus_height = %consensus_height,
                        "Decided batch contains an unparseable transaction — recording for sync \
                         and skipping execution (deterministic; every node does the same)"
                    );
                    let outcome = self
                        .record_batch_for_sync(
                            &conn,
                            consensus_height,
                            anchor_height,
                            anchor_hash,
                            certificate,
                            batch_txs,
                            certified,
                        )
                        .await?;
                    return Ok((outcome, StageOutcome::UnrecognizedBatch, 0usize, 0u64));
                }
                parsed
            };

            let input = CanonicalInput::bitcoin(certified.unwrap_or(batch_txs))?;
            let exclusions = if let Some(frozen) = frozen {
                frozen.exclusions
            } else {
                let mut applicable = select_decision_exclusions(&conn, consensus_height.as_u64())
                    .await?
                    .iter()
                    .map(|value| value.parse::<Txid>().map(|id| id.to_byte_array()))
                    .collect::<Result<Vec<_>, _>>()?;
                applicable.sort_unstable();
                DecisionExclusions::for_batch(
                    consensus_height.as_u64(),
                    certified.unwrap_or(batch_txs),
                    batch_txs,
                    &applicable,
                )?
            };
            insert_batch(
                &conn,
                consensus_height.as_u64(),
                anchor_height,
                &anchor_hash.to_string(),
                certificate,
                false,
            )
            .await
            .context("Failed to insert batch")?;

            // Store the certified txid list + raw txs for replay/sync recovery
            self.record_batch_txs(&conn, consensus_height, batch_txs, certified)
                .await?;

            for t in &parsed_txs {
                let tx_id = insert_transaction(
                    &conn,
                    indexer_types::TransactionRow::builder()
                        .height(anchor_height)
                        .batch_height(consensus_height.as_u64())
                        .txid(t.txid.to_string())
                        .build(),
                )
                .await
                .context("Failed to insert transaction")?;

                // Canonical batch processing discards the per-op failure vec —
                // deterministic op failures are already telemetered via warn! in
                // execute_op. Only non-deterministic errors (Result::Err) abort.
                let _failures = self
                    .executor
                    .execute_prepared(
                        selection,
                        &self.session,
                        self.network,
                        anchor_height,
                        tx_id,
                        t,
                    )
                    .await
                    .context("execute_transaction failed")?;
            }

            self.record_application(
                anchor_height,
                ApplicationSource::Batch {
                    anchor_height,
                    anchor_hash: anchor_hash.to_byte_array(),
                    exclusions,
                },
                Some(input),
            )
            .await?;
            let executed_ops = parsed_txs
                .iter()
                .flat_map(|tx| tx.inputs.iter())
                .map(|(_, count)| *count)
                .sum::<u64>();
            Ok((
                BatchOutcome::Executed,
                StageOutcome::Applied,
                parsed_txs.len(),
                executed_ops,
            ))
        }
        .await;
        let result = result.map(|(outcome, stage_outcome, count, ops)| {
            ((outcome, count, ops), stage_outcome, remaining)
        });
        let ((outcome, parsed_count, executed_ops), _) = stage.finish(result).await?;
        Ok(AppliedBatch {
            outcome,
            parsed_count,
            executed_ops,
        })
    }
}

impl<E: Executor> Reactor<E> {
    pub(super) async fn process_decided_batch(
        &mut self,
        anchor_height: u64,
        anchor_hash: BlockHash,
        consensus_height: Height,
        certificate: &[u8],
        batch_txs: &[bitcoin::Transaction],
        certified: Option<&[bitcoin::Transaction]>,
    ) -> Result<BatchOutcome> {
        let started_at = Instant::now();
        let applied = self
            .execution
            .process_decided_batch(
                anchor_height,
                anchor_hash,
                consensus_height,
                certificate,
                batch_txs,
                certified,
            )
            .await?;
        Ok(self
            .observe_batch(
                applied,
                anchor_height,
                anchor_hash,
                consensus_height,
                batch_txs,
                started_at,
            )
            .await)
    }

    pub(super) async fn observe_batch(
        &mut self,
        applied: AppliedBatch,
        anchor_height: u64,
        anchor_hash: BlockHash,
        consensus_height: Height,
        batch_txs: &[bitcoin::Transaction],
        started_at: Instant,
    ) -> BatchOutcome {
        let AppliedBatch {
            outcome,
            parsed_count,
            executed_ops,
        } = applied;
        let conn = self.db_conn();
        if outcome == BatchOutcome::RecordedOnly {
            return outcome;
        }
        // Optional test observations never select canonical finality work.
        let txids: Vec<Txid> = batch_txs.iter().map(|tx| tx.compute_txid()).collect();
        if self.consensus.observation.is_some() && !txids.is_empty() {
            self.consensus.unfinalized_batches.push(UnfinalizedBatch {
                consensus_height,
                anchor_height,
                anchor_hash,
                txids,
                deadline: deadline_for(anchor_height),
            });
        }
        gauge!(CONSENSUS_HEIGHT).set(consensus_height.as_u64() as f64);
        // Counter increments only after commit so we count ops persisted,
        // not ops attempted (mirrors the block path; simulation can't reach
        // here so it never inflates the metric).
        if executed_ops > 0 {
            counter!(ITEMS_INDEXED).increment(executed_ops);
        }

        let checkpoint = self.consensus.get_checkpoint(&conn).await;
        self.consensus.emit_state_event(StateEvent::BatchApplied {
            consensus_height,
            anchor_height,
            txid_count: parsed_count,
            checkpoint,
        });

        info!(
            anchor = anchor_height,
            consensus_height = %consensus_height,
            duration_ms = started_at.elapsed().as_millis() as u64,
            "Batch processing complete"
        );

        BatchOutcome::Executed
    }

    // A replacement can be at or below the applied tip. The certified branch,
    // rather than the local cursor, distinguishes replacements from duplicates.
    pub(super) async fn pending_block_value(&mut self) -> Result<Option<Value>> {
        let conn = self.db_conn();
        for block in self.consensus.pending_blocks.values() {
            let input = block.exact_input(self.consensus.protocol_context)?;
            match branch::validate(
                &conn,
                self.consensus.protocol_context,
                &input.descriptor().command,
            )
            .await
            {
                Ok(()) => return Ok(Some(Value::from_input(input)?)),
                Err(error) if error.downcast_ref::<branch::Rejected>().is_some() => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn batch_proposal_value(
        &self,
        height: u64,
        hash: BlockHash,
        mut txs: Vec<bitcoin::Transaction>,
    ) -> Result<Value> {
        let mut bytes = 4usize;
        let count = txs
            .iter()
            .take_while(|tx| {
                match bytes
                    .checked_add(4)
                    .and_then(|size| size.checked_add(tx.total_size()))
                {
                    Some(size) if size <= MAX_BATCH_BYTES => {
                        bytes = size;
                        true
                    }
                    _ => false,
                }
            })
            .count();
        // Admission takes a dependency-ordered prefix. It never changes work
        // already certified, and leaves the remainder in the proposal pool.
        txs.truncate(count);
        Ok(Value::new_batch_raw(
            self.consensus.protocol_context,
            height,
            hash,
            txs,
        )?)
    }

    /// The state-only half of building a BATCH proposal: candidates judged
    /// entirely on the loop (pool, DB, fee index) with no bitcoind
    /// round-trips. They then go through the I/O phase as an [`IoJob`].
    async fn make_value_snapshot(&mut self) -> Result<Option<ProposalSnapshot>> {
        let selection = self.preparation_selection().await?;
        let conn = self.db_conn();

        // Pre-filter already-processed txids to avoid unnecessary validation
        let pending_txids: Vec<Txid> = self.consensus.mempool.candidates.keys().copied().collect();
        let txid_strs: Vec<String> = pending_txids.iter().map(|t| t.to_string()).collect();
        let existing = select_existing_txids(&conn, &txid_strs)
            .await
            .context("Failed to query existing txids")?;
        let unbatched_set: HashSet<Txid> = pending_txids
            .into_iter()
            .filter(|t| !existing.contains(&t.to_string()))
            .collect();

        // Remove already-processed txids from the pool
        for txid_str in &existing {
            if let Ok(txid) = txid_str.parse::<Txid>() {
                self.consensus.mempool.suppress(&txid);
            }
        }

        // Candidate filter: state predicates only. Everything that needs
        // bitcoind happens in the I/O phase, off this loop. Iterate by key —
        // the pool is keyed by txid, so `compute_txid()` per entry (a
        // double-SHA256 over the serialized tx) would recompute what we already
        // hold.
        let mut txs = Vec::new();
        let mut invalid_txids = Vec::new();
        for (txid, (raw_tx, parsed)) in &self.consensus.mempool.candidates {
            if !unbatched_set.contains(txid) {
                continue;
            }
            if parsed.eligible_for(&selection) {
                txs.push(raw_tx.clone());
            } else {
                invalid_txids.push(*txid);
            }
        }
        for txid in &invalid_txids {
            self.consensus.mempool.suppress(txid);
        }
        if txs.is_empty() {
            return Ok(None);
        }
        // Dependency-order the candidates BEFORE the I/O phase, not after. The
        // I/O phase relays each accepted tx before validating the next
        // (`validate_txs`), and a child's mempool-acceptance check only passes on
        // a bitcoind that already holds its parent — so the parent must be relayed
        // first, which requires it to come first HERE. The pool enumerates in
        // arbitrary order; sorting at apply (as an earlier version did) is too
        // late, a child ahead of its parent is already rejected on relay.
        let order = dependency_sort(&txs);
        let txs: Vec<bitcoin::Transaction> = order.into_iter().map(|i| txs[i].clone()).collect();
        // Compute the fee threshold once for this candidate set (the index is
        // a snapshot during this pass) and carry it into the I/O phase.
        let threshold = compute_fee_threshold(&self.consensus.mempool_fee_index);
        Ok(Some(ProposalSnapshot {
            selection,
            txs,
            threshold,
        }))
    }

    /// Judge an incoming proposal, answering the engine through `reply` —
    /// immediately for block proposals and cheap rejections, or after the
    /// bitcoind I/O phase for a batch that passes the state predicates. The
    /// engine waits on the oneshot either way, exactly as it used to wait on
    /// this method running the RPCs inline; what changed is that THIS loop no
    /// longer waits with it.
    pub(super) async fn validate_and_accept_proposal(
        &mut self,
        data: &ProposalData,
        proposer: Address,
        height: Height,
        round: Round,
        reply: tokio::sync::oneshot::Sender<Option<ProposedValue<Ctx>>>,
    ) -> Result<()> {
        let conn = self.db_conn();
        let last_height = self.execution.last_height;
        let last_hash = self.execution.last_hash.unwrap_or(BlockHash::all_zeros());

        if data.value().descriptor().context != self.consensus.protocol_context {
            let _ = reply.send(None);
            return Ok(());
        }
        if let Err(error) = branch::validate(
            &conn,
            self.consensus.protocol_context,
            data.value().command(),
        )
        .await
        {
            if error.downcast_ref::<branch::Rejected>().is_none() {
                return Err(error);
            }
            warn!(%error, "Rejecting proposal outside certified Bitcoin branch");
            let _ = reply.send(None);
            return Ok(());
        }
        let value = match data.value().command() {
            Command::Block {
                height: bh, hash, ..
            } => {
                if let Some(block) = self.consensus.pending_blocks.get(bh) {
                    if block.hash != *hash
                        || block.exact_input(self.consensus.protocol_context)?
                            != *data.value().input()
                    {
                        warn!(
                            block_height = bh,
                            proposed = %hash,
                            local = %block.hash,
                            "Rejecting block proposal: hash mismatch"
                        );
                        let _ = reply.send(None);
                        return Ok(());
                    }
                } else {
                    // "Not yet received" and "already processed" are opposite
                    // conditions with opposite remedies — one resolves itself
                    // when the poller catches up, the other never does — and
                    // they were indistinguishable in the logs. Naming them costs
                    // one lookup on a path that is already rejecting.
                    match select_block_at_height(&conn, *bh).await {
                        Ok(Some(row)) if row.hash == *hash => warn!(
                            block_height = bh,
                            %hash,
                            last_height,
                            "Rejecting block proposal: height already processed"
                        ),
                        Ok(Some(row)) => warn!(
                            block_height = bh,
                            proposed = %hash,
                            executed = %row.hash,
                            "Rejecting block proposal: height processed with a different hash (reorg)"
                        ),
                        Ok(None) => warn!(
                            block_height = bh,
                            last_height, "Rejecting block proposal: block not yet received"
                        ),
                        Err(e) => warn!(
                            error = %e,
                            block_height = bh,
                            "Rejecting block proposal: block lookup failed"
                        ),
                    }
                    let _ = reply.send(None);
                    return Ok(());
                }
                data.value().clone()
            }
            Command::Batch {
                anchor_height,
                anchor_hash,
            } => {
                let transactions = data.value().batch_raw_txs();
                // SNAPSHOT phase: every state predicate, judged now for the
                // fast reject. Re-judged at apply time — see `IoJob`.
                if let Some(reason) = self
                    .consensus
                    .validate_batch(
                        &conn,
                        *anchor_height,
                        *anchor_hash,
                        &transactions,
                        last_height,
                        last_hash,
                    )
                    .await?
                {
                    warn!("Rejecting batch proposal: {reason}");
                    let _ = reply.send(None);
                    return Ok(());
                }
                let selection = self.preparation_selection().await?;
                let mut parsed_txs = Vec::with_capacity(transactions.len());
                for tx in &transactions {
                    let txid = tx.compute_txid();
                    // Parse the PROPOSAL'S OWN bytes, never the pool's cached copy.
                    // Kontor ops live in the taproot witness, which the txid does
                    // not commit to, so a same-txid variant sitting in this node's
                    // mempool would otherwise be judged (and later voted on) in
                    // place of the witness the proposer actually streamed.
                    let parsed = if let Some(p) = self.execution.executor.prepare_transaction(
                        &self.execution.recognizer,
                        &selection,
                        tx,
                    )? {
                        p
                    } else {
                        warn!(%txid, "Rejecting proposal: transaction failed to parse");
                        let _ = reply.send(None);
                        return Ok(());
                    };
                    if !parsed.eligible_for(&selection) {
                        warn!(%txid, "Rejecting proposal: transaction not batchable");
                        let _ = reply.send(None);
                        return Ok(());
                    }
                    parsed_txs.push(parsed);
                }
                let threshold = compute_fee_threshold(&self.consensus.mempool_fee_index);
                let verdicts = self
                    .execution
                    .executor
                    .validate_txs(transactions.clone(), threshold);
                self.io_jobs.push_back(IoJob {
                    verdicts,
                    apply: IoApply::ValidateProposal {
                        value: data.value().clone(),
                        selection,
                        height,
                        round,
                        proposer,
                        anchor_height: *anchor_height,
                        anchor_hash: *anchor_hash,
                        parsed: parsed_txs,
                        reply,
                    },
                });
                return Ok(());
            }
        };

        let proposed = ProposedValue {
            height,
            round,
            valid_round: Round::Nil,
            proposer,
            value,
            validity: Validity::Valid,
        };
        self.consensus
            .undecided
            .entry(height)
            .or_default()
            .insert(round, proposed.clone());
        let _ = reply.send(Some(proposed));
        Ok(())
    }

    pub(super) async fn try_fulfill_pending_proposal(&mut self) -> Result<bool> {
        let last_height = self.execution.last_height;
        let last_hash = self.execution.last_hash.unwrap_or(BlockHash::all_zeros());

        let past_deadline = match &self.consensus.pending_proposal {
            Some(p) => Instant::now() >= p.hard_deadline,
            None => return Ok(false),
        };

        // Block proposals require only local branch checks, so pending bitcoind
        // validation must not delay them.
        if let Some(value) = self.pending_block_value().await? {
            self.fulfill_pending_with(value).await?;
            return Ok(true);
        }

        if branch::tip(&self.db_conn()).await?.is_none() {
            return Ok(false);
        }

        // A candidate set already validated for THIS anchor — banked when the
        // deadline consumed the proposal it was meant for. Judged at use:
        // anchor and exact witness must still match the pool,
        // and `validate_batch` re-runs; anything stale falls through to a
        // fresh snapshot.
        if let Some(banked) = self.validated_candidates.take()
            && banked
                .selection
                .can_reuse_preparation(&self.preparation_selection().await?)
            && banked.anchor_height == last_height
            && banked.anchor_hash == last_hash
        {
            let mut kept = banked.txs;
            kept.retain(|tx| self.consensus.mempool.contains_candidate(tx));
            if !kept.is_empty() {
                let order = dependency_sort(&kept);
                let txs: Vec<bitcoin::Transaction> =
                    order.into_iter().map(|i| kept[i].clone()).collect();
                let conn = self.db_conn();
                if self
                    .consensus
                    .validate_batch(&conn, last_height, last_hash, &txs, last_height, last_hash)
                    .await?
                    .is_none()
                {
                    self.fulfill_pending_with(self.batch_proposal_value(
                        last_height,
                        last_hash,
                        txs,
                    )?)
                    .await?;
                    return Ok(true);
                }
            }
        }
        // One build job at a time — a second snapshot while one is in flight
        // would validate the same pool twice and race it on apply.
        let build_in_flight = self
            .io_jobs
            .iter()
            .any(|j| matches!(j.apply, IoApply::BuildProposal { .. }));
        let mut idle_retry = false;
        if !build_in_flight {
            match self.make_value_snapshot().await? {
                Some(ProposalSnapshot {
                    selection,
                    txs,
                    threshold,
                }) => {
                    info!(
                        candidates = txs.len(),
                        "Validating candidate batch off-loop; reply deferred"
                    );
                    let verdicts = self.execution.executor.validate_txs(txs, threshold);
                    self.io_jobs.push_back(IoJob {
                        verdicts,
                        apply: IoApply::BuildProposal {
                            selection,
                            anchor_height: last_height,
                            anchor_hash: last_hash,
                        },
                    });
                }
                None => {
                    // Round zero already offered a batching window. On a retry,
                    // peers may have started their timers before this proposer;
                    // another idle wait can make the replacement arrive too late.
                    idle_retry = self
                        .consensus
                        .pending_proposal
                        .as_ref()
                        .is_some_and(|p| p.round > Round::new(0));
                }
            }
        }
        if past_deadline || idle_retry {
            // The deadline outranks a validation still in flight. The old code
            // could not honor it — it was inside the RPCs when the deadline
            // passed — so "empty at the deadline" only fired when there was
            // nothing to validate. Now it always fires on time; a candidate
            // set still validating answers a LATER round, and its apply keeps
            // only the pool hygiene.
            info!(past_deadline, idle_retry, "Proposing empty batch");
            self.fulfill_pending_with(self.batch_proposal_value(last_height, last_hash, vec![])?)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Answer the held GetValue with `value`: file it under `undecided`,
    /// stream the parts, release the engine's reply. No-op if nothing is held
    /// (the deadline or a competing path already answered).
    async fn fulfill_pending_with(&mut self, value: Value) -> Result<()> {
        branch::validate(
            &self.db_conn(),
            self.consensus.protocol_context,
            value.command(),
        )
        .await?;
        let Some(pending) = self.consensus.pending_proposal.take() else {
            return Ok(());
        };
        let proposed = ProposedValue {
            height: pending.height,
            round: pending.round,
            valid_round: Round::Nil,
            proposer: self.consensus.address,
            value: value.clone(),
            validity: Validity::Valid,
        };
        self.consensus
            .undecided
            .entry(pending.height)
            .or_default()
            .insert(pending.round, proposed);
        let proposal = LocallyProposedValue::new(pending.height, pending.round, value);
        self.send_proposal_parts(&proposal, Round::Nil).await?;
        let _ = pending.reply.send(proposal);
        Ok(())
    }

    /// The APPLY phase of a finished [`IoJob`]: act on the verdicts, but only
    /// after re-judging every state predicate against wherever the chain moved
    /// while the I/O ran. `Err` from the I/O is infrastructure (bitcoind
    /// unreachable after retries) and fatal — I5, same as it was when the RPCs
    /// ran inline.
    pub(super) async fn apply_io_verdicts(
        &mut self,
        apply: IoApply,
        verdicts: Result<Vec<(bitcoin::Transaction, TxPolicy)>>,
    ) -> Result<()> {
        let verdicts = verdicts?;
        match apply {
            IoApply::BuildProposal {
                selection,
                anchor_height,
                anchor_hash,
            } => {
                if !selection.can_reuse_preparation(&self.preparation_selection().await?) {
                    return self.try_fulfill_pending_proposal().await.map(|_| ());
                }
                // Pool hygiene counts even when the proposal below is stale.
                let mut kept = Vec::with_capacity(verdicts.len());
                for (tx, verdict) in verdicts {
                    match verdict {
                        TxPolicy::Accepted => kept.push(tx),
                        TxPolicy::Rejected(reason) => {
                            let txid = tx.compute_txid();
                            warn!(%txid, %reason, "Dropping candidate transaction");
                            self.consensus.mempool.reject(&tx);
                        }
                    }
                }
                // The pool may have moved on while the I/O ran: an RBF
                // replacement or eviction arrived through the mempool arm —
                // which now runs freely during validation — and a superseded tx
                // draws nil votes (txn-mempool-conflict) or, decided, a batch
                // that can never confirm. A txid omits witness data, so compare the
                // complete raw input rather than just its membership key.
                kept.retain(|tx| self.consensus.mempool.contains_candidate(tx));
                if self.consensus.pending_proposal.is_none() {
                    // The deadline already answered with an empty batch, or the
                    // engine moved on. BANK the verdicts for the next GetValue
                    // rather than burning them — see `ValidatedCandidates`.
                    if !kept.is_empty()
                        && anchor_height == self.execution.last_height
                        && anchor_hash == self.execution.last_hash.unwrap_or(BlockHash::all_zeros())
                    {
                        debug!(
                            count = kept.len(),
                            "Banking validated candidates for the next proposal"
                        );
                        self.validated_candidates = Some(ValidatedCandidates {
                            selection,
                            anchor_height,
                            anchor_hash,
                            txs: kept,
                        });
                    }
                    return Ok(());
                }
                if anchor_height != self.execution.last_height
                    || anchor_hash != self.execution.last_hash.unwrap_or(BlockHash::all_zeros())
                {
                    // The tip moved mid-validation: this snapshot answers a
                    // question nobody is asking anymore. Re-snapshot against
                    // the new tip; the deadline machinery still bounds us.
                    debug!("Anchor moved during validation; re-snapshotting");
                    return self.try_fulfill_pending_proposal().await.map(|_| ());
                }
                if kept.is_empty() {
                    return Ok(());
                }
                // Propose in dependency order — the pool enumerates in
                // arbitrary order, but `validate_batch` rejects a batch with a
                // child ahead of its parent.
                let order = dependency_sort(&kept);
                let txs: Vec<bitcoin::Transaction> =
                    order.into_iter().map(|i| kept[i].clone()).collect();
                let conn = self.db_conn();
                if let Some(reason) = self
                    .consensus
                    .validate_batch(
                        &conn,
                        anchor_height,
                        anchor_hash,
                        &txs,
                        self.execution.last_height,
                        self.execution.last_hash.unwrap_or(BlockHash::all_zeros()),
                    )
                    .await?
                {
                    info!("Not proposing batch: {reason}");
                    return Ok(());
                }
                self.fulfill_pending_with(self.batch_proposal_value(
                    anchor_height,
                    anchor_hash,
                    txs,
                )?)
                .await
            }
            IoApply::ValidateProposal {
                value,
                selection,
                height,
                round,
                proposer,
                anchor_height,
                anchor_hash,
                parsed,
                reply,
            } => {
                if value.descriptor().context != self.consensus.protocol_context
                    || !selection.can_reuse_preparation(&self.preparation_selection().await?)
                {
                    let _ = reply.send(None);
                    return Ok(());
                }
                if let Err(error) = branch::validate(
                    &self.db_conn(),
                    self.consensus.protocol_context,
                    value.command(),
                )
                .await
                {
                    if error.downcast_ref::<branch::Rejected>().is_none() {
                        return Err(error);
                    }
                    let _ = reply.send(None);
                    return Ok(());
                }
                for (tx, verdict) in &verdicts {
                    if let TxPolicy::Rejected(reason) = verdict {
                        warn!(
                            txid = %tx.compute_txid(),
                            %reason,
                            "Rejecting proposal: transaction failed validation"
                        );
                        let _ = reply.send(None);
                        return Ok(());
                    }
                }
                let transactions: Vec<bitcoin::Transaction> =
                    verdicts.into_iter().map(|(tx, _)| tx).collect();
                ensure!(
                    transactions == value.batch_raw_txs(),
                    "proposal validation changed exact inputs"
                );
                // Freshness: the snapshot's state predicates, re-judged. The
                // anchor gate in `validate_batch` is what turns "the tip moved
                // while we validated" into a plain rejection instead of a vote
                // for a stale anchor.
                let conn = self.db_conn();
                if let Some(reason) = self
                    .consensus
                    .validate_batch(
                        &conn,
                        anchor_height,
                        anchor_hash,
                        &transactions,
                        self.execution.last_height,
                        self.execution.last_hash.unwrap_or(BlockHash::all_zeros()),
                    )
                    .await?
                {
                    warn!("Rejecting batch proposal: {reason}");
                    let _ = reply.send(None);
                    return Ok(());
                }
                for (tx, parsed) in transactions.iter().zip(parsed) {
                    self.consensus.mempool.cache_proposal(tx, parsed);
                }
                let proposed = ProposedValue {
                    height,
                    round,
                    valid_round: Round::Nil,
                    proposer,
                    value,
                    validity: Validity::Valid,
                };
                self.consensus
                    .undecided
                    .entry(height)
                    .or_default()
                    .insert(round, proposed.clone());
                let _ = reply.send(Some(proposed));
                Ok(())
            }
        }
    }

    pub(super) async fn advance(&mut self) -> Result<()> {
        let conn = self.db_conn();
        let frontier = certified_history::frontier(&conn).await?;
        ensure!(
            frontier.status == certified_history::Status::Ready,
            "execution history is not ready"
        );
        if frontier.authenticated_height > frontier.closed_height {
            ensure!(
                frontier.closed_height.checked_add(1) == Some(frontier.authenticated_height),
                "unfinished decision history has a gap"
            );
            // A durable decision ends proposal work even if Finalized is still queued.
            self.consensus.pending_proposal = None;
            self.validated_candidates = None;
            gauge!(DEFERRED_DECISIONS).set(1.0);
            self.apply_certified_closure(frontier.authenticated_height)
                .await?;
            self.prune_finalized_bodies(&conn).await;
        }
        gauge!(DEFERRED_DECISIONS).set(0.0);
        self.resume_next_height().await
    }

    async fn resume_next_height(&mut self) -> Result<()> {
        let Some((height, _)) = &self.consensus.pending_next_height else {
            return Ok(());
        };
        let height = *height;
        let Some(next) = self
            .consensus
            .closed_next_height(&self.db_conn(), height)
            .await?
        else {
            return Ok(());
        };
        let (_, reply) = self
            .consensus
            .pending_next_height
            .take()
            .context("next-height callback disappeared")?;
        self.maybe_prune_state().await;
        // Durable completion survives cancellation of this particular engine callback.
        let _ = reply.send(next);
        Ok(())
    }

    async fn prune_finalized_bodies(&mut self, conn: &libsql::Connection) {
        let floor =
            match min_unfinalized_batch_height(conn, FINALITY_WINDOW, self.execution.last_height)
                .await
            {
                Ok(Some(h)) => h,
                // All batches are final — reclaim every body (consensus_height <= current).
                Ok(None) => self.consensus.current_height.as_u64() + 1,
                Err(e) => {
                    warn!(error = %e, "failed to read the finalized-body floor; skipping prune");
                    return;
                }
            };
        match delete_unconfirmed_batch_txs_below(conn, floor).await {
            Ok(n) if n > 0 => debug!(floor, deleted = n, "pruned finalized batch bodies"),
            Ok(_) => {}
            Err(e) => warn!(error = %e, floor, "failed to prune finalized batch bodies"),
        }
    }

    pub(super) async fn handle_get_value(
        &mut self,
        height: Height,
        round: Round,
        timeout: std::time::Duration,
        reply: tokio::sync::oneshot::Sender<LocallyProposedValue<Ctx>>,
    ) -> Result<()> {
        info!(%height, %round, "Building value to propose");

        if let Some(existing) = self
            .consensus
            .undecided
            .get(&height)
            .and_then(|rounds| rounds.get(&round))
        {
            let proposal =
                LocallyProposedValue::new(existing.height, existing.round, existing.value.clone());
            self.send_proposal_parts(&proposal, Round::Nil).await?;
            reply
                .send(proposal)
                .map_err(|_| anyhow::anyhow!("Failed to send GetValue reply"))?;
        } else {
            // Malachite's timer is already running when GetValue reaches us.
            // Count from StartedRound so queueing cannot extend our wait past
            // the engine's deadline; reserve the last 20% for dissemination.
            self.consensus.pending_proposal = Some(consensus_state::PendingProposal {
                height,
                round,
                reply,
                hard_deadline: self.consensus.round_started_at + timeout * 4 / 5,
            });
            if !self.try_fulfill_pending_proposal().await? {
                info!(%height, %round, "Nothing to propose yet, holding the reply");
            }
        }
        Ok(())
    }

    pub(super) async fn handle_finalized(
        &mut self,
        certificate: CommitCertificate<Ctx>,
        reply: tokio::sync::oneshot::Sender<Next<Ctx>>,
    ) -> Result<consensus_state::ConsensusResult> {
        ensure!(
            self.consensus.pending_next_height.is_none(),
            "previous finalized callback is still awaiting execution"
        );
        let value = self
            .consensus
            .finalized_value(&self.db_conn(), &certificate)
            .await?;
        self.consensus.undecided.remove(&certificate.height);
        if let Some(obs) = &self.consensus.observation {
            let _ = obs.decided_tx.try_send(DecidedBatch {
                validator_index: self.consensus.validator_index,
                consensus_height: certificate.height,
                value,
            });
        }
        self.consensus.current_round = Round::Nil;
        self.consensus.pending_proposal = None;
        self.consensus.pending_next_height = Some((certificate.height, reply));
        Ok(consensus_state::ConsensusResult::None)
    }
}

#[cfg(test)]
mod tests {
    use super::{batch_is_ordered, dependency_sort};
    use crate::consensus::{Height, Value};
    use crate::database::queries::{
        delete_unconfirmed_batch_txs_below, insert_batch, insert_unconfirmed_batch_tx,
    };
    use crate::protocol::coordinator::v1::build_replay_queue;
    use crate::reactor::consensus_state::DeferredDecision;
    use crate::reactor::{Reactor, lite_executor::LiteExecutor};
    use crate::test_utils::{new_mock_block_hash, new_test_db};
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::collections::VecDeque;

    /// Put batches held during a drain pass back at the FRONT of the queue, in their
    /// original order, so nothing is reordered relative to what follows them.
    fn restore_waiting(
        queue: &mut VecDeque<DeferredDecision>,
        waiting: &mut VecDeque<DeferredDecision>,
    ) {
        while let Some(decision) = waiting.pop_back() {
            queue.push_front(decision);
        }
    }

    /// A tx spending each outpoint in `parents`, with one output. `nonce`
    /// perturbs the output value so distinct txs get distinct txids.
    fn tx(parents: &[OutPoint], nonce: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: parents
                .iter()
                .map(|&previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(1000 + nonce),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    /// The first output of `tx`, as an outpoint a child can spend.
    fn spend(tx: &Transaction) -> OutPoint {
        OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        }
    }

    #[tokio::test]
    async fn retained_body_resolution_uses_the_decided_batch() {
        let (_reader, writer, _temp) = new_test_db().await.unwrap();
        let conn = writer.connection();
        let mut first = tx(&[OutPoint::null()], 1);
        first.input[0].witness = Witness::from_slice(&[b"first witness"]);
        let mut second = first.clone();
        second.input[0].witness = Witness::from_slice(&[b"second witness"]);
        let txid = first.compute_txid();
        assert_eq!(second.compute_txid(), txid);
        assert_ne!(second.compute_wtxid(), first.compute_wtxid());
        for (height, transaction) in [(10, &first), (11, &second)] {
            insert_batch(
                &conn,
                height,
                1,
                &new_mock_block_hash(1).to_string(),
                &[],
                false,
            )
            .await
            .unwrap();
            insert_unconfirmed_batch_tx(&conn, &txid.to_string(), height, &serialize(transaction))
                .await
                .unwrap();
        }
        for (height, expected) in [(10, Some(first)), (11, Some(second.clone())), (12, None)] {
            assert_eq!(
                Reactor::<LiteExecutor>::resolve_tx_from_db(&conn, &txid, height).await,
                expected
            );
        }
        delete_unconfirmed_batch_txs_below(&conn, 11).await.unwrap();
        assert_eq!(
            Reactor::<LiteExecutor>::resolve_tx_from_db(&conn, &txid, 10).await,
            None
        );
        assert_eq!(
            Reactor::<LiteExecutor>::resolve_tx_from_db(&conn, &txid, 11).await,
            Some(second)
        );
    }

    #[test]
    fn batch_is_ordered_rejects_child_before_parent() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);
        assert!(!batch_is_ordered(&[child.clone(), parent.clone()]));
        assert!(batch_is_ordered(&[parent, child]));
    }

    #[test]
    fn batch_is_ordered_accepts_independent_txs_in_any_order() {
        let a = tx(&[OutPoint::null()], 1);
        let b = tx(&[OutPoint::null()], 2);
        assert!(batch_is_ordered(&[a.clone(), b.clone()]));
        assert!(batch_is_ordered(&[b, a]));
    }

    #[test]
    fn dependency_sort_lifts_parent_ahead_of_child() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);
        // Batch deliberately mis-ordered: child at index 0, parent at 1.
        let batch = vec![child, parent];
        let order = dependency_sort(&batch);
        let position = |i: usize| order.iter().position(|&x| x == i).unwrap();
        assert!(position(1) < position(0));
    }

    #[test]
    fn dependency_sort_resolves_a_three_tx_chain() {
        let a = tx(&[OutPoint::null()], 1);
        let b = tx(&[spend(&a)], 2);
        let c = tx(&[spend(&b)], 3);
        // Reverse order in — sort must walk it back to a, b, c.
        let batch = vec![c, b, a];
        let order = dependency_sort(&batch);
        assert_eq!(order, vec![2, 1, 0]);
        let sorted: Vec<Transaction> = order.iter().map(|&i| batch[i].clone()).collect();
        assert!(batch_is_ordered(&sorted));
    }

    #[test]
    fn dependency_sort_preserves_order_of_independent_txs() {
        let a = tx(&[OutPoint::null()], 1);
        let b = tx(&[OutPoint::null()], 2);
        let c = tx(&[OutPoint::null()], 3);
        assert_eq!(dependency_sort(&[a, b, c]), vec![0, 1, 2]);
    }

    /// Decisions are identified by consensus height, not by position.
    fn decision(consensus_height: u64) -> DeferredDecision {
        DeferredDecision {
            consensus_height: Height::new(consensus_height),
            value: Value::new_batch_raw(0, bitcoin::BlockHash::all_zeros(), vec![]),
            certificate: Vec::new(),
            execution_txs: None,
        }
    }

    fn heights(q: &VecDeque<DeferredDecision>) -> Vec<u64> {
        q.iter().map(|d| d.consensus_height.as_u64()).collect()
    }

    /// Pair a decision with the transactions it carries, as `prepare_replay` does
    /// after resolving them.
    fn carrying(
        consensus_height: u64,
        txs: Vec<Transaction>,
    ) -> (DeferredDecision, Vec<Transaction>) {
        let mut d = decision(consensus_height);
        d.value = Value::new_batch_raw(0, bitcoin::BlockHash::all_zeros(), txs.clone());
        (d, txs)
    }

    fn empty(consensus_height: u64) -> (DeferredDecision, Vec<Transaction>) {
        (decision(consensus_height), Vec::new())
    }

    /// `carrying` with an explicit anchor height, so a test can pin the
    /// EXECUTION order (which is anchor order) independently of the queue order.
    fn carrying_at(
        consensus_height: u64,
        anchor_height: u64,
        txs: Vec<Transaction>,
    ) -> (DeferredDecision, Vec<Transaction>) {
        let mut d = decision(consensus_height);
        d.value = Value::new_batch_raw(anchor_height, bitcoin::BlockHash::all_zeros(), txs.clone());
        (d, txs)
    }

    /// Exclusions attributed to the decision they were dropped from.
    fn excl(pairs: &[(u64, Txid)]) -> HashMap<u64, HashSet<String>> {
        let mut m: HashMap<u64, HashSet<String>> = HashMap::new();
        for (height, txid) in pairs {
            m.entry(*height).or_default().insert(txid.to_string());
        }
        m
    }

    fn queue_of(
        replayed: Vec<(DeferredDecision, Vec<Transaction>)>,
        survivors: Vec<(DeferredDecision, Vec<Transaction>)>,
    ) -> VecDeque<DeferredDecision> {
        build_replay_queue(replayed, survivors, &HashMap::new()).0
    }

    /// THE regression this function exists for. A rollback excludes transaction X
    /// because it never confirmed. A batch that was QUEUED (not yet executed, so it
    /// has no `batches` row and is not in the replay set) carries Y, which spends
    /// X's output. If the exclusion pass only sees the replay set, Y survives and
    /// later executes against state the rollback wiped — while a peer that had
    /// already executed that batch does drop Y, because for that peer it IS in the
    /// replay set. Same consensus height, different transactions executed.
    #[test]
    fn build_replay_queue_excludes_descendants_carried_by_survivors() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);
        let unrelated = tx(&[OutPoint::null()], 3);

        let excluded = excl(&[(10, parent.compute_txid())]);
        let (queue, closure) = build_replay_queue(
            vec![carrying(10, vec![parent.clone()])],
            vec![carrying(14, vec![child.clone(), unrelated.clone()])],
            &excluded,
        );

        assert!(
            closure.contains(&child.compute_txid()),
            "the closure must reach a descendant carried by a survivor"
        );
        let survivor_txs = queue[1].value.batch_raw_txs();
        assert_eq!(
            survivor_txs.len(),
            1,
            "survivor must keep only the unrelated tx, got {survivor_txs:?}"
        );
        assert_eq!(survivor_txs[0].compute_txid(), unrelated.compute_txid());
    }

    /// Filtering must narrow what we EXECUTE without losing what was DECIDED.
    ///
    /// `batch_txids` records consensus's decision, and a peer syncing that height
    /// re-derives the exclusions itself by applying the same deadline rules — so it
    /// needs the full list. A node where this batch was a survivor has no rows yet,
    /// so whatever it records lands as if certified; recording the narrowed list
    /// would leave it serving a value that no longer matches its own certificate.
    #[test]
    fn build_replay_queue_preserves_the_decided_txids_when_it_filters() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);
        let kept = tx(&[OutPoint::null()], 3);

        let excluded = excl(&[(10, parent.compute_txid())]);
        let (queue, _) = build_replay_queue(
            vec![carrying(10, vec![parent.clone()])],
            vec![carrying(14, vec![child.clone(), kept.clone()])],
            &excluded,
        );

        let survivor = &queue[1];
        assert_eq!(
            survivor.value.batch_raw_txs().len(),
            1,
            "the descendant must not execute"
        );
        assert_eq!(
            survivor.decided_txids(),
            vec![child.compute_txid(), kept.compute_txid()],
            "the DECIDED list must be preserved in full for the record"
        );
    }

    /// The narrowing can take a batch all the way to EMPTY — every transaction it
    /// carried descends from an excluded one. That combination (no txs to execute,
    /// but a decided list to record) is the input `process_decided_batch` must not
    /// mistake for an ordinary empty batch: the certificate still certifies those
    /// txids, and a peer syncing this height re-derives the exclusions itself, so it
    /// needs the decided content. Pinning it here because it is the only place the
    /// combination is produced.
    #[test]
    fn build_replay_queue_narrows_a_batch_to_empty_but_keeps_its_decided_list() {
        let parent = tx(&[OutPoint::null()], 1);
        let child_a = tx(&[spend(&parent)], 2);
        let child_b = tx(&[spend(&parent)], 3);

        let excluded = excl(&[(10, parent.compute_txid())]);
        let (queue, _) = build_replay_queue(
            vec![carrying(10, vec![parent.clone()])],
            vec![carrying(14, vec![child_a.clone(), child_b.clone()])],
            &excluded,
        );

        let survivor = &queue[1];
        assert!(
            survivor.value.batch_raw_txs().is_empty(),
            "every tx descends from the excluded parent, so nothing may execute"
        );
        assert_eq!(
            survivor.decided_txids(),
            vec![child_a.compute_txid(), child_b.compute_txid()],
            "an emptied batch still has a decided list, and it must survive"
        );
    }

    /// THE regression for attempt 2. An exclusion belongs to the DECISION it was made
    /// in, not to the transaction. A tx dropped at one height can re-enter the
    /// mempool, be decided in a LATER batch against a fresh deadline, and execute
    /// there legitimately — a global ban strips it from that batch too, so this node
    /// skips a transaction the network ran. That is a state divergence, worse than the
    /// oscillation the carry-forward exists to prevent.
    #[test]
    fn build_replay_queue_does_not_exclude_a_txid_at_a_different_height() {
        let t = tx(&[OutPoint::null()], 1);
        let other = tx(&[OutPoint::null()], 2);

        let (queue, _) = build_replay_queue(
            vec![carrying(10, vec![t.clone()])],
            vec![carrying(14, vec![t.clone(), other.clone()])],
            &excl(&[(10, t.compute_txid())]),
        );

        assert!(
            queue[0].value.batch_raw_txs().is_empty(),
            "the decision it was excluded from must drop it"
        );
        let later: Vec<Txid> = queue[1]
            .value
            .batch_raw_txs()
            .iter()
            .map(|x| x.compute_txid())
            .collect();
        assert!(
            later.contains(&t.compute_txid()),
            "a DIFFERENT decision carrying the same txid must still execute it"
        );
    }

    /// The descendant closure must not be seeded by a tx that is executing fine
    /// somewhere. If P is excluded at one height but kept at another, its child C is
    /// not orphaned — stripping C would skip a transaction whose parent the network
    /// executed.
    #[test]
    fn build_replay_queue_keeps_a_child_whose_parent_is_kept_elsewhere() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);

        let (queue, _) = build_replay_queue(
            vec![carrying(10, vec![parent.clone()])],
            vec![
                carrying(14, vec![parent.clone()]),
                carrying(15, vec![child.clone()]),
            ],
            &excl(&[(10, parent.compute_txid())]),
        );

        assert!(
            !queue[2].value.batch_raw_txs().is_empty(),
            "the child must survive — its parent executes at another height"
        );
    }

    /// The keep guard is POSITIONAL. A parent excluded at one height and re-decided
    /// at a LATER queue position only re-creates its outputs from that position
    /// onward — a child sitting BETWEEN the exclusion and the re-decide executes
    /// before the parent is rebuilt, so it must still drop (#427). An order-blind
    /// "kept anywhere" guard let exactly this child through.
    #[test]
    fn build_replay_queue_drops_a_child_ordered_before_its_parents_re_decide() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);

        let (queue, dropped) = build_replay_queue(
            vec![carrying(10, vec![parent.clone()])],
            vec![
                carrying(14, vec![child.clone()]),
                carrying(20, vec![parent.clone()]),
            ],
            &excl(&[(10, parent.compute_txid())]),
        );

        assert!(
            queue[1].value.batch_raw_txs().is_empty(),
            "the child executes before the parent's re-decide rebuilds its output, \
             so it must drop"
        );
        assert!(dropped.contains(&child.compute_txid()));
        assert_eq!(
            queue[2].value.batch_raw_txs().len(),
            1,
            "the re-decided parent itself still executes at its own height"
        );
    }

    /// The positional rule cuts the other way too: a child ordered BEFORE its
    /// parent's position never saw the parent's effects in the ORIGINAL execution
    /// either (the parent had not run yet), so the replay must reproduce that and
    /// keep it. Dropping it would diverge from every node that executed the
    /// original sequence.
    #[test]
    fn build_replay_queue_keeps_a_child_ordered_before_its_parents_exclusion() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);

        let (queue, dropped) = build_replay_queue(
            vec![
                carrying(5, vec![child.clone()]),
                carrying(10, vec![parent.clone()]),
            ],
            Vec::new(),
            &excl(&[(10, parent.compute_txid())]),
        );

        assert_eq!(
            queue[0].value.batch_raw_txs().len(),
            1,
            "the child ran before the parent in the original sequence, so the \
             parent's exclusion cannot retroactively orphan it"
        );
        assert!(!dropped.contains(&child.compute_txid()));
    }

    /// A parent excluded at a height that is NOT in the queue was excluded below
    /// `from_anchor` — before every queue position — so its outputs are missing
    /// from the start and its in-queue children must drop (#427). Pins the
    /// out-of-queue seeding the positional walk must not lose.
    #[test]
    fn build_replay_queue_drops_a_child_of_a_parent_excluded_outside_the_queue() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);

        let (queue, dropped) = build_replay_queue(
            vec![carrying(10, vec![child.clone()])],
            Vec::new(),
            &excl(&[(3, parent.compute_txid())]),
        );

        assert!(
            queue[0].value.batch_raw_txs().is_empty(),
            "the parent's exclusion below the replay window still orphans the child"
        );
        assert!(dropped.contains(&child.compute_txid()));
    }

    /// A within-batch dependency chain collapses transitively from the excluded
    /// parent down, while an independent tx in the same batch survives.
    #[test]
    fn build_replay_queue_drops_a_whole_chain_within_one_batch() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);
        let grandchild = tx(&[spend(&child)], 3);
        let independent = tx(&[OutPoint::null()], 4);

        let (queue, excluded) = build_replay_queue(
            vec![carrying(
                10,
                vec![
                    parent.clone(),
                    child.clone(),
                    grandchild.clone(),
                    independent.clone(),
                ],
            )],
            Vec::new(),
            &excl(&[(10, parent.compute_txid())]),
        );

        let kept: Vec<Txid> = queue[0]
            .value
            .batch_raw_txs()
            .iter()
            .map(|t| t.compute_txid())
            .collect();
        assert_eq!(kept, vec![independent.compute_txid()]);
        assert_eq!(
            excluded,
            [
                parent.compute_txid(),
                child.compute_txid(),
                grandchild.compute_txid()
            ]
            .into()
        );
    }

    /// But a child whose parent is excluded and appears NOWHERE else must still drop:
    /// it would execute against state the rollback wiped (#427). The re-decide keep
    /// must not be widened into "never treat an excluded parent as missing".
    #[test]
    fn build_replay_queue_still_drops_a_child_of_an_absent_parent() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);

        let (queue, dropped) = build_replay_queue(
            vec![carrying(10, vec![parent.clone()])],
            vec![carrying(14, vec![child.clone()])],
            &excl(&[(10, parent.compute_txid())]),
        );

        assert!(
            queue[1].value.batch_raw_txs().is_empty(),
            "a descendant of an excluded, otherwise-absent parent must not execute"
        );
        assert!(dropped.contains(&child.compute_txid()));
    }

    /// The availability walk must give the SAME answer on two nodes that split the
    /// same decisions differently between the replay set and the survivors — because
    /// that split is node-local (a lagging node holds as a survivor what a caught-up
    /// node already executed), while the drop set must be a shared input or two
    /// honest nodes diverge from one rollback.
    ///
    /// Parent P is excluded below `from_anchor` (out of queue), then re-decided by D
    /// at a HIGHER anchor than child C's batch — so in execution (anchor) order C
    /// runs before P is rebuilt and must drop, whichever side of the queue split D
    /// and C land on. The pre-fix queue-order walk kept C whenever D happened to sit
    /// ahead of it in the queue.
    #[test]
    fn build_replay_queue_availability_is_anchor_order_not_queue_order() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);
        // P excluded at height 3, which is NOT in either queue → seeds the walk.
        let rows = || excl(&[(3, parent.compute_txid())]);
        // C's batch anchors at 100; D re-decides P at 105 (executes AFTER C).
        let child_batch = || carrying_at(10, 100, vec![child.clone()]);
        let redecide = || carrying_at(20, 105, vec![parent.clone()]);

        // Node A: C is in the replay set, D is a survivor behind it.
        let (_, dropped_a) = build_replay_queue(vec![child_batch()], vec![redecide()], &rows());
        // Node B: D is in the replay set, C is a survivor behind it.
        let (_, dropped_b) = build_replay_queue(vec![redecide()], vec![child_batch()], &rows());

        assert!(
            dropped_a.contains(&child.compute_txid()),
            "C executes before P is rebuilt, so it must drop"
        );
        assert_eq!(
            dropped_a, dropped_b,
            "the drop set must not depend on the node-local replay/survivor split"
        );
    }

    /// The mirror: a child ordered BEFORE its parent's re-decide in EXECUTION order
    /// keeps, again independent of the queue split. C's batch anchors ABOVE D here,
    /// so P is rebuilt first and C's input exists.
    #[test]
    fn build_replay_queue_keeps_a_child_executed_after_its_parents_redecide() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);
        let rows = || excl(&[(3, parent.compute_txid())]);
        let child_batch = || carrying_at(10, 110, vec![child.clone()]);
        let redecide = || carrying_at(20, 105, vec![parent.clone()]);

        let (_, dropped_a) = build_replay_queue(vec![child_batch()], vec![redecide()], &rows());
        let (_, dropped_b) = build_replay_queue(vec![redecide()], vec![child_batch()], &rows());

        assert!(
            !dropped_a.contains(&child.compute_txid()),
            "P is rebuilt at anchor 105 before C runs at 110, so C keeps"
        );
        assert_eq!(dropped_a, dropped_b, "and the answer is split-independent");
    }

    /// An unmarked decision is untouched — the record-only case, which has certified
    /// txids and no execution and must NOT be mistaken for an exclusion.
    #[test]
    fn build_replay_queue_leaves_an_unmarked_decision_intact() {
        let a = tx(&[OutPoint::null()], 1);
        let b = tx(&[OutPoint::null()], 2);
        let (queue, excluded) = build_replay_queue(
            vec![carrying(10, vec![a.clone(), b.clone()])],
            Vec::new(),
            &HashMap::new(),
        );
        assert_eq!(queue[0].value.batch_raw_txs().len(), 2);
        assert!(excluded.is_empty());
    }

    /// Narrowing must not destroy the EXCLUDED transactions' bodies.
    ///
    /// A batch in the replay set already persisted its bodies when it first
    /// executed. A SURVIVOR — queued, never executed, so with no rows at all — has
    /// persisted nothing, and `build_replay_queue` is holding the fully-resolved
    /// bodies at the exact moment it drops them. Recording the excluded txids in
    /// `batch_txids` while discarding their bodies leaves that consensus height
    /// unresolvable: a syncing peer gets `BatchTx::Id`, cannot resolve it from pool,
    /// DB or bitcoind (it never confirmed), and `resolve_batch_txs` bails — killing
    /// the peer's reactor.
    #[test]
    fn build_replay_queue_keeps_the_excluded_transactions_bodies() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);
        let kept = tx(&[OutPoint::null()], 3);

        let excluded = excl(&[(10, parent.compute_txid())]);
        let (queue, _) = build_replay_queue(
            vec![carrying(10, vec![parent.clone()])],
            vec![carrying(14, vec![child.clone(), kept.clone()])],
            &excluded,
        );

        let survivor = &queue[1];
        assert_eq!(
            survivor.value.batch_raw_txs().len(),
            1,
            "only the kept tx may EXECUTE"
        );
        let servable: HashSet<Txid> = survivor
            .decided_txs()
            .iter()
            .map(|t| t.compute_txid())
            .collect();
        assert_eq!(
            servable,
            [child.compute_txid(), kept.compute_txid()].into(),
            "but the body of the EXCLUDED tx must still be servable — it is the one \
             a peer can obtain from nowhere else"
        );
    }

    /// A batch can be narrowed by MORE THAN ONE rollback. On the second pass the
    /// carried transactions are already the first pass's survivors, so recomputing
    /// the decided list from them would silently drop whatever the first pass
    /// excluded — and `batch_txids` would stop matching the certificate. The first
    /// decided list is the true one and must win.
    #[test]
    fn build_replay_queue_keeps_the_first_decided_list_across_repeated_filtering() {
        let first = tx(&[OutPoint::null()], 1);
        let second = tx(&[OutPoint::null()], 2);
        let survivor_tx = tx(&[OutPoint::null()], 3);
        let decided_all = vec![first.clone(), second.clone(), survivor_tx.clone()];
        let decided_ids: Vec<Txid> = decided_all.iter().map(|t| t.compute_txid()).collect();

        // Pass one already ran: `first` was excluded, and the decision carries the
        // full decided list alongside the narrowed transactions.
        let (mut decision, _) = carrying(14, vec![second.clone(), survivor_tx.clone()]);
        decision.execution_txs = Some(decided_all.clone());

        // Pass two excludes `second`.
        let excluded = excl(&[(14, second.compute_txid())]);
        let (queue, _) = build_replay_queue(
            Vec::new(),
            vec![(decision, vec![second.clone(), survivor_tx.clone()])],
            &excluded,
        );

        assert_eq!(
            queue[0].value.batch_raw_txs().len(),
            1,
            "only the untouched tx should remain executable"
        );
        assert_eq!(
            queue[0].decided_txids(),
            decided_ids,
            "the ORIGINAL decided list must survive a second narrowing"
        );
    }

    /// Nothing excluded means nothing to preserve — the value is already the
    /// decided content and a redundant copy would just be a second answer.
    #[test]
    fn build_replay_queue_leaves_certified_txs_unset_when_nothing_is_filtered() {
        let a = tx(&[OutPoint::null()], 1);
        let (queue, _) = build_replay_queue(
            vec![carrying(10, vec![a.clone()])],
            Vec::new(),
            &HashMap::new(),
        );
        assert!(queue[0].execution_txs.is_none());
    }

    /// A queued decision BELOW the replay set's max must SURVIVE. Anchors go
    /// non-monotone across a rollback, so height H can defer on a high anchor while
    /// H+1 executes on a lower one and gets a `batches` row — putting H below the
    /// replay set. H has no row, so dropping it leaves a permanent, unrefillable
    /// gap in the consensus-height sequence.
    #[test]
    fn build_replay_queue_keeps_a_queued_decision_below_the_replay_set() {
        let queue = queue_of(vec![empty(11), empty(12)], vec![empty(10), empty(13)]);
        let mut present = heights(&queue);
        present.sort_unstable();
        assert_eq!(present, vec![10, 11, 12, 13], "nothing may be dropped");
    }

    /// …but behind the replay set, not ahead of it. A survivor BLOCK decision whose
    /// block has not arrived parks the drain, and the replay set — stuck behind it —
    /// is what would have delivered that block.
    #[test]
    fn build_replay_queue_never_orders_a_survivor_ahead_of_the_replay_set() {
        assert_eq!(
            heights(&queue_of(
                vec![empty(11), empty(12)],
                vec![empty(10), empty(13)]
            )),
            vec![11, 12, 10, 13],
        );
    }

    #[test]
    fn build_replay_queue_preserves_relative_order_within_each_side() {
        assert_eq!(
            heights(&queue_of(
                vec![empty(5), empty(9)],
                vec![empty(6), empty(7)]
            )),
            vec![5, 9, 6, 7]
        );
    }

    #[test]
    fn build_replay_queue_prefers_the_replayed_copy_of_a_shared_height() {
        let mut replayed_copy = decision(4);
        replayed_copy.certificate = vec![0xAA];
        let queue = queue_of(vec![(replayed_copy, Vec::new())], vec![empty(4)]);
        assert_eq!(heights(&queue), vec![4]);
        assert_eq!(queue[0].certificate, vec![0xAA]);
    }

    #[test]
    fn build_replay_queue_handles_either_side_empty() {
        assert_eq!(heights(&queue_of(Vec::new(), vec![empty(3)])), vec![3]);
        assert_eq!(heights(&queue_of(vec![empty(3)], Vec::new())), vec![3]);
        assert!(queue_of(Vec::new(), Vec::new()).is_empty());
    }

    /// Batches held during a drain pass go back at the FRONT, in their original
    /// order. Anything still queued behind them was already ordered after them, so
    /// restoring out of order — or after the queue instead of before it — would
    /// reorder decisions relative to each other.
    #[test]
    fn restore_waiting_puts_held_batches_back_in_front_in_order() {
        let mut queue: VecDeque<_> = [decision(30), decision(31)].into();
        let mut waiting: VecDeque<_> = [decision(10), decision(11), decision(12)].into();

        restore_waiting(&mut queue, &mut waiting);

        assert_eq!(heights(&queue), vec![10, 11, 12, 30, 31]);
        assert!(waiting.is_empty(), "held set must be drained");
    }

    #[test]
    fn restore_waiting_is_a_noop_when_nothing_was_held() {
        let mut queue: VecDeque<_> = [decision(7)].into();
        let mut waiting: VecDeque<_> = VecDeque::new();
        restore_waiting(&mut queue, &mut waiting);
        assert_eq!(heights(&queue), vec![7]);
    }
}
