use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use indexer_types::Event;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_core_types::{Round, Validity};
use malachitebft_engine::host::Next;
use metrics::{counter, gauge};
use prost::Message;
use tracing::{debug, error, info, warn};

use crate::consensus::codec::encode_commit_certificate;
use crate::consensus::finality_types::{DecidedBatch, StateEvent, UnfinalizedBatch, deadline_for};
use crate::consensus::{CommitCertificate, Ctx, Height, ProposalData, Value};
use crate::database::queries::{
    insert_batch, insert_batch_txids, insert_excluded_batch_txids, insert_transaction,
    insert_unconfirmed_batch_tx, select_applicable_exclusions, select_block_at_height,
    select_existing_txids,
};
use crate::metrics::{CONSENSUS_HEIGHT, ITEMS_INDEXED};

use futures_util::future::BoxFuture;

use super::consensus_state;
use super::executor::{Executor, TxPolicy, is_batchable};
use super::mempool_fee_index::MempoolFeeIndex;
use super::{MAX_DEFERRED_DECISIONS, Reactor};

/// Multiplier applied to `MempoolFeeIndex::fastest_fee()` to derive the
/// per-batch acceptance threshold, as an integer ratio: 9/10 means we accept
/// txs at or above 90% of the median fee rate in projected block 0. Integer
/// math because this feeds proposal validation — a consensus-adjacent path
/// where float rounding is a determinism hazard (#429).
const FEE_THRESHOLD_NUM: u64 = 9;
const FEE_THRESHOLD_DEN: u64 = 10;

/// A consensus I/O job: bitcoind validation running OFF the event loop as an
/// owned future, paired with what to do with its verdicts. The loop polls the
/// front job as an arm of its root `select!`, so the reactor keeps executing
/// blocks, draining mempool events, and settling finality while bitcoind is
/// slow — and dropping the loop drops the in-flight RPC, so shutdown costs
/// nothing (see `Executor::validate_txs`).
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
        anchor_height: u64,
        anchor_hash: BlockHash,
    },
    /// An incoming batch proposal: on apply, accept (file under `undecided`,
    /// release the engine's reply with `Some`) or reject (`None`).
    ValidateProposal {
        height: Height,
        round: Round,
        anchor_height: u64,
        anchor_hash: BlockHash,
        /// Parses aligned with the future's pairs — same source order.
        parsed: Vec<indexer_types::Transaction>,
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
    pub(super) anchor_height: u64,
    pub(super) anchor_hash: BlockHash,
    pub(super) txs: Vec<bitcoin::Transaction>,
}

/// What the batch-candidate snapshot found.
enum ProposalSnapshot {
    /// Batch candidates that need the bitcoind I/O phase.
    Batch {
        txs: Vec<bitcoin::Transaction>,
        threshold: u64,
    },
    Nothing,
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

/// Topologically sort a batch's transactions so a tx that spends another
/// batch tx's output comes after that producer. The proposer collects
/// candidate txs from the mempool in arbitrary order; sorting here lets it
/// propose a batch that already satisfies the dependency-order consensus
/// rule (`batch_is_ordered`) rather than having peers vote it down.
///
/// Returns batch indices in proposal order. Kahn's algorithm, breaking
/// ties by lowest original index. Falls back to identity order if a cycle
/// is somehow present (impossible for valid Bitcoin transactions, but the
/// sort must still total).
fn dependency_sort(txs: &[bitcoin::Transaction]) -> Vec<usize> {
    let index_of: HashMap<Txid, usize> = txs
        .iter()
        .enumerate()
        .map(|(i, tx)| (tx.compute_txid(), i))
        .collect();

    let mut in_degree = vec![0usize; txs.len()];
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); txs.len()];
    for (i, tx) in txs.iter().enumerate() {
        let mut parents: HashSet<usize> = HashSet::new();
        for input in &tx.input {
            if let Some(&p) = index_of.get(&input.previous_output.txid)
                && p != i
            {
                parents.insert(p);
            }
        }
        in_degree[i] = parents.len();
        for p in parents {
            children[p].push(i);
        }
    }

    let mut ready: BinaryHeap<Reverse<usize>> = (0..txs.len())
        .filter(|&i| in_degree[i] == 0)
        .map(Reverse)
        .collect();
    let mut ordered = Vec::with_capacity(txs.len());
    while let Some(Reverse(i)) = ready.pop() {
        ordered.push(i);
        for &c in &children[i] {
            in_degree[c] -= 1;
            if in_degree[c] == 0 {
                ready.push(Reverse(c));
            }
        }
    }

    if ordered.len() != txs.len() {
        return (0..txs.len()).collect();
    }
    ordered
}

/// Check that a batch's transactions are in a valid dependency order:
/// every tx that spends another batch tx's output appears *after* that
/// producer.
///
/// The rule constrains only that parent-before-child relation — it does
/// not canonicalize the batch. Independent transactions (sharing no UTXO)
/// may appear in any order, chosen by the proposer. Note this is a
/// Bitcoin-UTXO dependency, not a contract-state one: two UTXO-independent
/// txs can still touch the same contract state, so their order — fixed in
/// the decided value — can change results. That ordering is the
/// proposer's prerogative, like tx order within a block; the rule enforces
/// only the structural requirement that an escrow exists before it is
/// spent (otherwise a detach simply finds nothing to detach).
///
/// The dependency-order rule of `ConsensusState::validate_batch`; lives
/// here next to `dependency_sort`, the proposer-side helper that produces
/// an order this accepts.
pub(super) fn batch_is_ordered(txs: &[bitcoin::Transaction]) -> bool {
    let index_of: HashMap<Txid, usize> = txs
        .iter()
        .enumerate()
        .map(|(i, tx)| (tx.compute_txid(), i))
        .collect();
    for (i, tx) in txs.iter().enumerate() {
        for input in &tx.input {
            if let Some(&p) = index_of.get(&input.previous_output.txid)
                && p > i
            {
                return false;
            }
        }
    }
    true
}

/// Put batches held during a drain pass back at the FRONT of the queue, in their
/// original order, so nothing is reordered relative to what follows them.
fn restore_waiting(
    queue: &mut VecDeque<consensus_state::DeferredDecision>,
    waiting: &mut VecDeque<consensus_state::DeferredDecision>,
) {
    while let Some(decision) = waiting.pop_back() {
        queue.push_front(decision);
    }
}

/// Assemble the post-rollback replay queue: merge the replay set with the decisions
/// already queued, and drop excluded transactions — plus anything descending from
/// them — from the batches in the result. Returns the queue and every txid dropped
/// this pass, which the caller also purges from the proposal pool.
///
/// MERGE, not overwrite: the replay set comes from `select_batches_from_anchor`,
/// which returns only heights that already have a `batches` row, while a queued
/// decision is queued precisely BECAUSE its anchor was unprocessed and so has no
/// row. Overwriting drops it permanently — `current_height` has already advanced
/// past it and `delete_unexecuted_batch_suffix` can only trim a SUFFIX, so the gap
/// is unrefillable locally or by sync.
///
/// The replay set goes FIRST and survivors keep their relative order behind it —
/// deliberately NOT sorted by consensus height. A survivor BLOCK decision whose
/// block has not arrived still parks the drain and stops it (batches merely step
/// aside; blocks cannot, since they must apply in sequence). The replay set is
/// precisely what raises the tip back up after a rollback, so a survivor ordered
/// ahead of it can stall the decisions that would make that survivor ready.
///
/// The two inputs should be disjoint by height; where they are not, the replayed
/// copy wins because it was loaded from the decided record.
fn build_replay_queue(
    replayed: Vec<(consensus_state::DeferredDecision, Vec<bitcoin::Transaction>)>,
    survivors: Vec<(consensus_state::DeferredDecision, Vec<bitcoin::Transaction>)>,
    // Exclusions PER consensus height, already re-verified against the chain.
    applicable: &HashMap<u64, HashSet<String>>,
) -> (VecDeque<consensus_state::DeferredDecision>, HashSet<Txid>) {
    let replayed_heights: Vec<Height> = replayed.iter().map(|(d, _)| d.consensus_height).collect();
    let survivors: Vec<_> = survivors
        .into_iter()
        .filter(|(d, _)| !replayed_heights.contains(&d.consensus_height))
        .collect();

    // MERGE FIRST, then exclude. The closure has to run over the whole sequence that
    // will actually execute: a descendant of an excluded tx can sit in a survivor,
    // since a survivor is queued precisely because its anchor is HIGHER — which is
    // where a child of an earlier transaction lives.
    let merged: Vec<_> = replayed.into_iter().chain(survivors).collect();

    let dropped_at = |decision: &consensus_state::DeferredDecision, txid: &Txid| -> bool {
        applicable
            .get(&decision.consensus_height.as_u64())
            .is_some_and(|s| s.contains(&txid.to_string()))
    };

    // Outputs the ORIGINAL execution had produced by each queue position that this
    // replay will NOT have: every excluded tx, from the position it was dropped at,
    // until (if ever) a later decision re-decides and keeps it. The queue order IS
    // the execution order, so availability is a positional fact, not a global one:
    //
    // - A keep re-creates the parent's outputs only from its own position onward.
    //   A child sitting BETWEEN an excluded parent and its re-decided copy executes
    //   before the parent is rebuilt, so it drops — an order-blind "kept anywhere"
    //   guard let exactly that child through (#427 through the re-decide door).
    // - Conversely, a child ordered BEFORE its parent's position never saw the
    //   parent's effects in the original execution either, so it keeps; the replay
    //   reproduces the original sequence position by position.
    //
    // Exclusions recorded at heights not in this queue happened below `from_anchor`
    // — before every position here — so they are unavailable from the start: the
    // rollback wiped the parent's effects and nothing in the queue rebuilds them
    // (#427's original shape).
    let queued_heights: HashSet<u64> = merged
        .iter()
        .map(|(d, _)| d.consensus_height.as_u64())
        .collect();
    let mut unavailable: HashSet<Txid> = applicable
        .iter()
        .filter(|(height, _)| !queued_heights.contains(height))
        .flat_map(|(_, txids)| txids.iter().filter_map(|t| t.parse::<Txid>().ok()))
        .collect();

    let mut all_excluded: HashSet<Txid> = HashSet::new();
    let mut queue = VecDeque::with_capacity(merged.len());

    for (mut decision, txs) in merged {
        if let Value::Batch {
            anchor_height,
            anchor_hash,
            ..
        } = &decision.value
        {
            let (anchor_height, anchor_hash) = (*anchor_height, *anchor_hash);
            let mut kept = Vec::with_capacity(txs.len());
            for tx in &txs {
                let txid = tx.compute_txid();
                if dropped_at(&decision, &txid) {
                    all_excluded.insert(txid);
                    unavailable.insert(txid);
                } else if tx
                    .input
                    .iter()
                    .any(|i| unavailable.contains(&i.previous_output.txid))
                {
                    // A descendant of a tx that is missing AT THIS POSITION. Dropped
                    // in memory, deliberately NOT recorded in `excluded_batch_txids`:
                    // a descendant's drop is only justified while its parent stays
                    // excluded, and a durable row outlives that justification — the
                    // read predicate re-checks the CHILD's confirmation, never the
                    // parent's recovery, so a recorded child would stay dropped after
                    // a reorg heals the parent while every fresh syncer executes it.
                    // Re-deriving from the durable base rows each pass costs at most
                    // one extra rollback (a leaked child re-arms its own deadline and
                    // becomes a base row); a wrong durable drop is a divergence.
                    all_excluded.insert(txid);
                    unavailable.insert(txid);
                } else {
                    kept.push(tx.clone());
                    // A re-decided copy of a previously excluded tx: from here on
                    // its outputs exist again, so later children survive.
                    unavailable.remove(&txid);
                }
            }
            // Narrowing what we execute must not narrow what we record as decided —
            // see `DeferredDecision::certified_txs`. The BODIES are retained, not just
            // the txids: an excluded tx never confirmed, so this is the only copy left
            // and a peer can get it nowhere else.
            //
            // `get_or_insert`, not assignment: a batch can be narrowed by more than
            // one rollback, and on the second pass `txs` is already the first pass's
            // survivors for a SURVIVOR decision (a replayed one is reloaded from the
            // certified list each pass). The earliest list is the decided one.
            if kept.len() != txs.len() {
                decision.certified_txs.get_or_insert(txs);
            }
            decision.value = Value::new_batch_raw(anchor_height, anchor_hash, kept);
        }
        queue.push_back(decision);
    }

    (queue, all_excluded)
}

/// What `process_decided_batch` did with a decided batch. Callers must not
/// announce `RecordedOnly` batches as processed — their transactions were
/// never executed here.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum BatchOutcome {
    /// Executed and committed at its anchor.
    Executed,
    /// Recorded for sync/bookkeeping only (empty batch, or anchor mismatch).
    RecordedOnly,
}

impl BatchOutcome {
    /// The txids to announce as processed for this outcome.
    ///
    /// An exhaustive match rather than `== Executed` at each call site: a future
    /// variant added without revisiting them would silently take the "nothing
    /// happened" branch, dropping the `BatchProcessed` heartbeat that drives the
    /// info publisher and therefore API availability.
    fn announced_txids(&self, batch_txs: &[bitcoin::Transaction]) -> Option<Vec<String>> {
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

impl<E: Executor> Reactor<E> {
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
    ) -> Result<BatchOutcome> {
        let started_at = Instant::now();
        let conn = self.db_conn();

        info!(
            %consensus_height,
            anchor_height,
            %anchor_hash,
            num_txs = batch_txs.len(),
            "Processing decided batch"
        );

        // Empty batch — just record for sync, no execution or finality tracking
        if batch_txs.is_empty() {
            insert_batch(
                &conn,
                consensus_height.as_u64(),
                anchor_height,
                &anchor_hash.to_string(),
                certificate,
                false,
            )
            .await
            .context("Failed to insert empty batch")?;

            // Empty to EXECUTE is not empty as DECIDED. A rollback can narrow a batch
            // until nothing is left to run while its certificate still certifies the
            // original txids, and `batch_txids` records what consensus decided (I4) —
            // a peer syncing this height re-derives the exclusions itself, so it needs
            // that list. `certified` is None for a genuinely empty decided batch, which
            // has nothing to record. `record_batch_txs` writes the DECIDED list to
            // both tables, so an emptied batch still records its certified txids AND
            // their raw bodies — the bodies of all-excluded txs exist nowhere else.
            if certified.is_some() {
                self.record_batch_txs(&conn, consensus_height, batch_txs, certified)
                    .await
                    .context("Failed to record the decided txids of an emptied batch")?;
            }

            gauge!(CONSENSUS_HEIGHT).set(consensus_height.as_u64() as f64);

            let checkpoint = self.consensus.get_checkpoint(&conn).await;
            self.consensus.emit_state_event(StateEvent::BatchApplied {
                consensus_height,
                anchor_height,
                txid_count: 0,
                checkpoint,
            });

            info!(
                anchor = anchor_height,
                consensus_height = %consensus_height,
                duration_ms = started_at.elapsed().as_millis() as u64,
                "Empty batch recorded"
            );
            return Ok(BatchOutcome::RecordedOnly);
        }

        // A decided batch may only EXECUTE against the exact chain state it was
        // anchored to: the local tip must sit at `anchor_height` with
        // `anchor_hash`. Anything else — a deferred drain whose anchor fell
        // behind, or a replay whose anchor block was reorged away — is recorded
        // for sync/bookkeeping but NOT executed: executing against a different
        // tip writes state (and a checkpoint) at a height the chain disagrees
        // about, i.e. silent divergence. A skipped batch's txids then simply
        // never confirm here and the finality window resolves it.
        // `None` ⇔ all-zeros is the pre-genesis convention `make_value` and
        // proposal validation anchor with.
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
            insert_batch(
                &conn,
                consensus_height.as_u64(),
                anchor_height,
                &anchor_hash.to_string(),
                certificate,
                false,
            )
            .await
            .context("Failed to record anchor-mismatched batch for sync")?;
            // Persist the certified content too (idempotent): a skipped batch
            // must still be servable to syncing peers with its real txs, and
            // the batch_txids/unconfirmed rows are what the sync path reads.
            self.record_batch_txs(&conn, consensus_height, batch_txs, certified)
                .await?;
            return Ok(BatchOutcome::RecordedOnly);
        }

        // Execute in decided order. `validate_batch` enforces dependency
        // order at propose/accept time, so a decided batch — carrying 2/3+
        // signatures — is already ordered; no re-sort or re-check here.
        let parsed_txs: Vec<indexer_types::Transaction> = batch_txs
            .iter()
            .map(|btx| {
                self.executor.parse_transaction(btx).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Failed to parse decided batch transaction {}",
                        btx.compute_txid()
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Track for finality — must happen once per batch execution
        let txids: Vec<Txid> = batch_txs.iter().map(|tx| tx.compute_txid()).collect();
        self.consensus.unfinalized_batches.push(UnfinalizedBatch {
            consensus_height,
            anchor_height,
            anchor_hash,
            txids,
            deadline: deadline_for(anchor_height),
        });

        self.runtime
            .storage
            .savepoint()
            .await
            .context("Failed to begin batch transaction")?;

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
                .execute_transaction(&mut self.runtime, anchor_height, tx_id, t)
                .await
                .context("execute_transaction failed")?;
        }

        self.runtime
            .storage
            .commit()
            .await
            .context("Failed to commit batch transaction")?;
        gauge!(CONSENSUS_HEIGHT).set(consensus_height.as_u64() as f64);
        // Counter increments only after commit so we count ops persisted,
        // not ops attempted (mirrors the block path; simulation can't reach
        // here so it never inflates the metric).
        let executed_ops: u64 = parsed_txs
            .iter()
            .flat_map(|t| t.inputs.iter())
            .map(|input| input.insts.ops.len() as u64)
            .sum();
        if executed_ops > 0 {
            counter!(ITEMS_INDEXED).increment(executed_ops);
        }

        let checkpoint = self.consensus.get_checkpoint(&conn).await;
        self.consensus.emit_state_event(StateEvent::BatchApplied {
            consensus_height,
            anchor_height,
            txid_count: parsed_txs.len(),
            checkpoint,
        });

        info!(
            anchor = anchor_height,
            consensus_height = %consensus_height,
            duration_ms = started_at.elapsed().as_millis() as u64,
            "Batch processing complete"
        );

        Ok(BatchOutcome::Executed)
    }

    /// The next pending Bitcoin block as a proposal value, if any. Blocks
    /// outrank batches and need no I/O, so this fast path runs UNCONDITIONALLY
    /// — a batch validation in flight must never starve block proposals, or a
    /// slow bitcoind would stall the chain through the proposer.
    ///
    /// Range-bounded, not `first_key_value`: an entry at or below the tip is
    /// already applied, and proposing it stops the chain — peers vote it valid
    /// (they still hold the block), it is decided, the finalize gate rejects it
    /// as out of order, and it stays the minimum forever so no newer block is
    /// ever proposed. The insert side refuses to buffer those now; this makes
    /// the proposer independently unable to emit one.
    fn pending_block_value(&self) -> Option<Value> {
        self.consensus
            .pending_blocks
            .range(self.last_height + 1..)
            .next()
            .map(|(&height, block)| Value::new_block(height, block.hash))
    }

    /// The state-only half of building a BATCH proposal: candidates judged
    /// entirely on the loop (pool, DB, fee index) with no bitcoind
    /// round-trips. They then go through the I/O phase as an [`IoJob`].
    async fn make_value_snapshot(&mut self) -> Result<ProposalSnapshot> {
        let conn = self.db_conn();

        // Pre-filter already-processed txids to avoid unnecessary validation
        let pending_txids: Vec<Txid> = self
            .consensus
            .pending_transactions
            .keys()
            .copied()
            .collect();
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
                self.consensus.pending_transactions.remove(&txid);
            }
        }

        // Candidate filter: state predicates only. Everything that needs
        // bitcoind happens in the I/O phase, off this loop.
        let mut txs = Vec::new();
        let mut invalid_txids = Vec::new();
        for (raw_tx, parsed) in self.consensus.pending_transactions.values() {
            let txid = raw_tx.compute_txid();
            if !unbatched_set.contains(&txid) {
                continue;
            }
            if is_batchable(&parsed.inputs) {
                txs.push(raw_tx.clone());
            } else {
                invalid_txids.push(txid);
            }
        }
        for txid in &invalid_txids {
            self.consensus.pending_transactions.remove(txid);
        }
        if txs.is_empty() {
            return Ok(ProposalSnapshot::Nothing);
        }
        // Compute the fee threshold once for this candidate set (the index is
        // a snapshot during this pass) and carry it into the I/O phase.
        let threshold = compute_fee_threshold(&self.consensus.mempool_fee_index);
        Ok(ProposalSnapshot::Batch { txs, threshold })
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
        height: Height,
        round: Round,
        reply: tokio::sync::oneshot::Sender<Option<ProposedValue<Ctx>>>,
    ) -> Result<()> {
        let conn = self.db_conn();
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        let value = match data {
            ProposalData::Block { height: bh, hash } => {
                if let Some(block) = self.consensus.pending_blocks.get(bh) {
                    // Deliberately NOT gated on `bh == last_height + 1`.
                    //
                    // Tempting, since a node behind on execution votes here for a
                    // block it cannot yet apply. But a `Value::Block` asserts only
                    // "this is the canonical Bitcoin block at this height", which
                    // this node can confirm from its own buffer; when to run it is
                    // a local ordering matter, settled by `handle_finalized` and
                    // the deferred queue. Withholding the vote would trade a stuck
                    // node for a stalled chain: at 3-of-4 quorum with one
                    // validator already down, one nil vote is the difference
                    // between the network advancing and halting — which is the
                    // failure this whole change exists to prevent, reintroduced
                    // from the other side.
                    if block.hash != *hash {
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
                Value::new_block(*bh, *hash)
            }
            ProposalData::Batch {
                anchor_height,
                anchor_hash,
                transactions,
            } => {
                // SNAPSHOT phase: every state predicate, judged now for the
                // fast reject. Re-judged at apply time — see `IoJob`.
                if let Some(reason) = self
                    .consensus
                    .validate_batch(
                        &conn,
                        *anchor_height,
                        *anchor_hash,
                        transactions,
                        last_height,
                        last_hash,
                    )
                    .await?
                {
                    warn!("Rejecting batch proposal: {reason}");
                    let _ = reply.send(None);
                    return Ok(());
                }
                let mut parsed_txs = Vec::with_capacity(transactions.len());
                for tx in transactions {
                    let txid = tx.compute_txid();
                    let parsed =
                        if let Some((_, cached)) = self.consensus.pending_transactions.get(&txid) {
                            cached.clone()
                        } else if let Some(p) = self.executor.parse_transaction(tx) {
                            p
                        } else {
                            warn!(%txid, "Rejecting proposal: transaction failed to parse");
                            let _ = reply.send(None);
                            return Ok(());
                        };
                    if !is_batchable(&parsed.inputs) {
                        warn!(%txid, "Rejecting proposal: transaction not batchable");
                        let _ = reply.send(None);
                        return Ok(());
                    }
                    parsed_txs.push(parsed);
                }
                let threshold = compute_fee_threshold(&self.consensus.mempool_fee_index);
                let verdicts = self.executor.validate_txs(transactions.clone(), threshold);
                self.io_jobs.push_back(IoJob {
                    verdicts,
                    apply: IoApply::ValidateProposal {
                        height,
                        round,
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
            proposer: self.consensus.address,
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
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        let past_deadline = match &self.consensus.pending_proposal {
            Some(p) => Instant::now() >= p.hard_deadline(),
            None => return Ok(false),
        };

        // Blocks first, always — even with a batch validation in flight. They
        // need no I/O, and a chain whose block proposals queue behind a slow
        // bitcoind is the head-of-line blocking this design removes.
        if let Some(value) = self.pending_block_value() {
            self.fulfill_pending_with(value).await?;
            return Ok(true);
        }

        // A candidate set already validated for THIS anchor — banked when the
        // deadline consumed the proposal it was meant for. Judged at use:
        // anchor must still match, membership is re-checked against the pool,
        // and `validate_batch` re-runs; anything stale falls through to a
        // fresh snapshot.
        if let Some(banked) = self.validated_candidates.take() {
            if banked.anchor_height == last_height && banked.anchor_hash == last_hash {
                let mut kept = banked.txs;
                kept.retain(|tx| {
                    self.consensus
                        .pending_transactions
                        .contains_key(&tx.compute_txid())
                });
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
                        self.fulfill_pending_with(Value::new_batch_raw(
                            last_height,
                            last_hash,
                            txs,
                        ))
                        .await?;
                        return Ok(true);
                    }
                }
            }
        }

        // One build job at a time — a second snapshot while one is in flight
        // would validate the same pool twice and race it on apply.
        let build_in_flight = self
            .io_jobs
            .iter()
            .any(|j| matches!(j.apply, IoApply::BuildProposal { .. }));
        if !build_in_flight {
            match self.make_value_snapshot().await? {
                ProposalSnapshot::Batch { txs, threshold } => {
                    info!(
                        candidates = txs.len(),
                        "Validating candidate batch off-loop; reply deferred"
                    );
                    let verdicts = self.executor.validate_txs(txs, threshold);
                    self.io_jobs.push_back(IoJob {
                        verdicts,
                        apply: IoApply::BuildProposal {
                            anchor_height: last_height,
                            anchor_hash: last_hash,
                        },
                    });
                }
                ProposalSnapshot::Nothing => {}
            }
        }
        if past_deadline {
            // The deadline outranks a validation still in flight. The old code
            // could not honor it — it was inside the RPCs when the deadline
            // passed — so "empty at the deadline" only fired when there was
            // nothing to validate. Now it always fires on time; a candidate
            // set still validating answers a LATER round, and its apply keeps
            // only the pool hygiene.
            info!("Proposing empty batch at hard deadline");
            self.fulfill_pending_with(Value::new_batch_raw(last_height, last_hash, vec![]))
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Answer the held GetValue with `value`: file it under `undecided`,
    /// stream the parts, release the engine's reply. No-op if nothing is held
    /// (the deadline or a competing path already answered).
    async fn fulfill_pending_with(&mut self, value: Value) -> Result<()> {
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
                anchor_height,
                anchor_hash,
            } => {
                // Pool hygiene counts even when the proposal below is stale.
                let mut kept = Vec::with_capacity(verdicts.len());
                for (tx, verdict) in verdicts {
                    match verdict {
                        TxPolicy::Accepted => kept.push(tx),
                        TxPolicy::Rejected(reason) => {
                            let txid = tx.compute_txid();
                            warn!(%txid, %reason, "Dropping candidate transaction");
                            self.consensus.pending_transactions.remove(&txid);
                        }
                    }
                }
                // The pool may have moved on while the I/O ran: an RBF
                // replacement or eviction arrived through the mempool arm —
                // which now runs freely during validation — and a superseded tx
                // draws nil votes (txn-mempool-conflict) or, decided, a batch
                // that can never confirm. Membership at APPLY time is the truth.
                kept.retain(|tx| {
                    self.consensus
                        .pending_transactions
                        .contains_key(&tx.compute_txid())
                });
                if self.consensus.pending_proposal.is_none() {
                    // The deadline already answered with an empty batch, or the
                    // engine moved on. BANK the verdicts for the next GetValue
                    // rather than burning them — see `ValidatedCandidates`.
                    if !kept.is_empty()
                        && anchor_height == self.last_height
                        && anchor_hash == self.last_hash.unwrap_or(BlockHash::all_zeros())
                    {
                        debug!(
                            count = kept.len(),
                            "Banking validated candidates for the next proposal"
                        );
                        self.validated_candidates = Some(ValidatedCandidates {
                            anchor_height,
                            anchor_hash,
                            txs: kept,
                        });
                    }
                    return Ok(());
                }
                if anchor_height != self.last_height
                    || anchor_hash != self.last_hash.unwrap_or(BlockHash::all_zeros())
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
                        self.last_height,
                        self.last_hash.unwrap_or(BlockHash::all_zeros()),
                    )
                    .await?
                {
                    info!("Not proposing batch: {reason}");
                    return Ok(());
                }
                self.fulfill_pending_with(Value::new_batch_raw(anchor_height, anchor_hash, txs))
                    .await
            }
            IoApply::ValidateProposal {
                height,
                round,
                anchor_height,
                anchor_hash,
                parsed,
                reply,
            } => {
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
                        self.last_height,
                        self.last_hash.unwrap_or(BlockHash::all_zeros()),
                    )
                    .await?
                {
                    warn!("Rejecting batch proposal: {reason}");
                    let _ = reply.send(None);
                    return Ok(());
                }
                for (tx, parsed) in transactions.iter().zip(parsed) {
                    self.consensus
                        .pending_transactions
                        .entry(tx.compute_txid())
                        .or_insert_with(|| (tx.clone(), parsed));
                }
                let proposed = ProposedValue {
                    height,
                    round,
                    valid_round: Round::Nil,
                    proposer: self.consensus.address,
                    value: Value::new_batch_raw(anchor_height, anchor_hash, transactions),
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

    /// Load the decided values to replay for a rollback from `from_anchor`.
    /// MUST run BEFORE the DB truncation: the query joins the `transactions`
    /// rows for each batch's txids, and those are cascade-deleted with their
    /// blocks by the rollback.
    pub(super) async fn load_replay_decisions(
        &mut self,
        from_anchor: u64,
    ) -> Result<Vec<consensus_state::DeferredDecision>> {
        let conn = self.db_conn();
        self.consensus
            .get_decided_from_anchor(&conn, from_anchor)
            .await
            .context("Failed to load replay batches for rollback")
    }

    /// Pair each decision with the transactions it carries.
    ///
    /// Both sides of the replay merge must resolve the SAME way: the exclusion
    /// closure needs tx INPUTS from the queued survivors too, and resolving only the
    /// replay set let a descendant of an excluded tx through to execute against state
    /// the rollback had wiped (#427 in a second form).
    async fn resolve_decisions(
        &mut self,
        decisions: impl IntoIterator<Item = consensus_state::DeferredDecision>,
    ) -> Result<Vec<(consensus_state::DeferredDecision, Vec<bitcoin::Transaction>)>> {
        let decisions = decisions.into_iter();
        let mut out = Vec::with_capacity(decisions.size_hint().0);
        for decision in decisions {
            let txs = match &decision.value {
                Value::Batch { txs, .. } => self.resolve_batch_txs(txs).await?,
                Value::Block { .. } => Vec::new(),
            };
            out.push((decision, txs));
        }
        Ok(out)
    }

    /// Install the replay decisions loaded by `load_replay_decisions` and kick
    /// off block redelivery. Runs AFTER the DB truncation: the raw-tx
    /// resolution can touch bitcoind, and a transient failure here is
    /// fatal-but-recoverable (the rollback already happened; on restart the
    /// startup cleanup forgets the unexecuted suffix and the node re-syncs).
    /// Before the truncation it would instead CANCEL a rollback that finality
    /// already demanded.
    pub(super) async fn prepare_replay(
        &mut self,
        from_anchor: u64,
        replay_batches: Vec<consensus_state::DeferredDecision>,
        // Per consensus height — see `select_applicable_exclusions`.
        applicable: HashMap<u64, HashSet<String>>,
    ) -> Result<()> {
        info!(
            from_anchor,
            replay_batches = replay_batches.len(),
            excluded = applicable.values().map(|s| s.len()).sum::<usize>(),
            "Initiating rollback replay"
        );

        // BOTH sides resolve, not just the replay set — see `resolve_decisions`.
        let replayed = self.resolve_decisions(replay_batches).await?;
        let queued = std::mem::take(&mut self.consensus.deferred_decisions);
        let survivors = self.resolve_decisions(queued).await?;

        let (queue, excluded) = build_replay_queue(replayed, survivors, &applicable);
        self.consensus.deferred_decisions = queue;

        // The excluded txids must also leave the proposal pool, or the next
        // make_value re-proposes the very txs whose missing confirmations caused
        // this rollback — repeating the same finality failure with no progress.
        for txid in &excluded {
            self.consensus.pending_transactions.remove(txid);
        }

        self.consensus
            .unfinalized_batches
            .retain(|b| b.anchor_height < from_anchor);

        // The reactor truncated to `from_anchor - 1`, deleting the anchor block
        // itself, so redelivery must START at `from_anchor` — i.e. strictly after
        // `from_anchor - 1`. Asking for `from_anchor` under the exclusive convention
        // resumes one block too late and the anchor never comes back.
        self.executor
            .replay_blocks_after(from_anchor.saturating_sub(1))
            .await
            .context("Failed to send replay request")?;
        Ok(())
    }

    /// Apply everything the current tip makes possible: drain decisions that were
    /// waiting on it, then settle any finality deadline it crossed, repeating while
    /// a rollback keeps changing the tip.
    ///
    /// The single funnel for a RISING `last_height`. Previously the finality check
    /// hung off one arm of the consensus-message handler, so a node whose tip
    /// advanced any other way — notably a lagging node receiving blocks via
    /// `BlockEvent::BlockInsert` — walked past deadlines without ever evaluating
    /// them, and diverged from peers that did. Routing both call sites through here
    /// makes "the tip never moves without a finality check" structural rather than
    /// something each call site has to remember.
    ///
    /// Terminates: a rollback moves `last_height` strictly BELOW every deadline it
    /// just settled, so the next pass has strictly fewer at-deadline batches.
    pub(super) async fn advance(&mut self) -> Result<()> {
        loop {
            self.drain_deferred_decisions()
                .await
                .context("drain_deferred_decisions failed")?;
            if !self.settle_finality().await? {
                return Ok(());
            }
        }
    }

    /// Whether any tracked batch has reached its deadline at the current tip.
    /// In-memory, bounded by the batches decided inside one finality window — no
    /// database work on the per-block path.
    fn finality_due(&self) -> bool {
        self.consensus
            .unfinalized_batches
            .iter()
            .any(|b| b.deadline <= self.last_height)
    }

    /// Run finality checks if any deadline has passed, performing the rollback and
    /// replay they demand. Returns whether a rollback happened (so `advance` knows
    /// the tip moved and it must drain again).
    async fn settle_finality(&mut self) -> Result<bool> {
        if !self.finality_due() {
            return Ok(false);
        }
        let conn = self.db_conn();
        let (events, rollback) = self
            .consensus
            .run_finality_checks(&conn, self.last_height)
            .await?;
        let Some((rollback_anchor, missing)) = rollback else {
            self.consensus.emit_finality_events(&events);
            return Ok(false);
        };

        // Depth-check BEFORE announcing anything. Rehydration can re-arm a deadline
        // whose anchor sits far below the tip — that is exactly the #515 residue this
        // PR picks up — and truncating below the prune watermark would destroy state
        // rather than restore it. Halting for a re-sync is the intended outcome, and
        // an observer must not be told a rollback happened when it did not.
        self.check_rollback_depth(rollback_anchor.saturating_sub(1))
            .context("finality rollback too deep")?;

        // Record this pass's exclusions BEFORE the truncation. The base set (which
        // txids went missing, and from which decision) is already known here — only
        // the descendant closure needs the resolved raw txs, and that part is
        // re-derivable. Writing after the rollback, as an earlier attempt did, leaves
        // a window where the truncation is durable and the reason for it is not: the
        // replay then reloads the full certified list and the oscillation returns.
        //
        // FATAL on failure, unlike the best-effort records elsewhere. Without this row
        // the pass is simply the original bug, and doing the rollback anyway would
        // commit to a truncation we can no longer justify on the next pass.
        let base_rows: Vec<(u64, String, u64)> = missing
            .iter()
            .flat_map(|m| {
                let (height, deadline) =
                    (m.consensus_height.as_u64(), deadline_for(m.anchor_height));
                m.txids
                    .iter()
                    .map(move |t| (height, t.to_string(), deadline))
            })
            .collect();
        insert_excluded_batch_txids(&conn, &base_rows)
            .await
            .context("Failed to record this pass's finality exclusions")?;

        // Read replay decisions BEFORE the truncation — the query joins rows that
        // are cascade-deleted with their blocks.
        let replay = self
            .load_replay_decisions(rollback_anchor)
            .await
            .context("load_replay_decisions failed")?;

        // Everything still applicable, this pass's rows included. Per DECISION: a row
        // for height H filters H and nothing else, so a txid re-decided in a later
        // batch against a fresh deadline still executes there. Applying exclusions
        // globally would skip a transaction the network ran — a divergence, and worse
        // than the stall this prevents.
        let applicable = select_applicable_exclusions(&conn)
            .await
            .context("Failed to load applicable finality exclusions")?;

        // Announce ONLY now, after every step that can still abort the pass: each
        // read/write above is fallible and `?`-propagates, and an observer told
        // about a rollback that then never happens is wrong about reality (I6) —
        // on restart a reorg can even re-render the verdict clean, making the
        // announcement permanently false. The truncation below is the commit point.
        self.consensus.emit_finality_events(&events);

        // Roll back to before the invalid anchor so all state at the anchor height
        // (including the invalid txs' effects) is wiped cleanly.
        self.rollback(rollback_anchor.saturating_sub(1))
            .await
            .context("rollback failed during finality rollback")?;

        // Fallible raw-tx resolution/filtering only after the truncation is durable:
        // a failure here must not cancel a rollback finality already demanded.
        self.prepare_replay(rollback_anchor, replay, applicable)
            .await
            .context("prepare_replay failed")?;

        let checkpoint = self.consensus.get_checkpoint(&conn).await;
        self.consensus
            .emit_state_event(StateEvent::RollbackExecuted {
                to_anchor: rollback_anchor,
                entries_removed: 0,
                checkpoint,
            });
        Ok(true)
    }

    /// Record a decided block this node will NOT execute.
    ///
    /// `batches` is the decided sequence and the only copy of it — Malachite asks
    /// US for decided values (`GetDecidedValues`), it does not keep them. So a
    /// consensus height left without a row is a hole in the record, and one that
    /// cannot be repaired: the startup cleanup trims an unexecuted SUFFIX, never a
    /// gap in the middle.
    ///
    /// Batches have always done this — the anchor gate records a batch it cannot
    /// apply and returns `RecordedOnly`. Block decisions did not, and the asymmetry
    /// was an oversight rather than a decision: the row costs nothing to write
    /// (`batches` has no foreign keys, so naming a block we do not hold is legal,
    /// and nothing references a block decision's row), while the batch case that
    /// DID get built also has to write `batch_txids` and `unconfirmed_batch_txs`.
    ///
    /// Declining to execute stays correct — the block was reorged away and running
    /// it would bind the wrong block to this consensus height. We just write down
    /// that we declined.
    async fn record_declined_block(
        &mut self,
        decision: &consensus_state::DeferredDecision,
    ) -> Result<()> {
        // Height and hash come from the decision itself — passing them alongside
        // invited a caller to record one block's decision under another's identity.
        let block_height = decision.value.block_height();
        let decided_hash = decision.value.block_hash();
        // FATAL on failure, deliberately. A declined decision that leaves no row is
        // the unrefillable middle gap this function exists to prevent: once
        // `current_height` moves past it, nothing re-decides the height and the
        // startup cleanup trims only a suffix. Failing is recoverable — restart
        // resumes consensus at this height, value sync re-delivers the decision,
        // and it is re-declined and recorded. Swallowing the error is not.
        insert_batch(
            &self.db_conn(),
            decision.consensus_height.as_u64(),
            block_height,
            &decided_hash.to_string(),
            &decision.certificate,
            true,
        )
        .await
        .with_context(|| {
            format!(
                "Failed to record declined block decision at consensus height {} \
                 (block {block_height})",
                decision.consensus_height
            )
        })
    }

    pub(super) async fn drain_deferred_decisions(&mut self) -> Result<()> {
        // Batches whose anchor block has not arrived yet. Held ASIDE rather than
        // stopping the drain: a waiting batch can only ever be unblocked by a
        // block, and the block decisions that would deliver it sit behind it in
        // this same queue — so parking on one could stall the very thing it waits
        // for. Restored to the front, in order, whenever a block executes and at
        // exit, so a batch is re-evaluated the moment its anchor lands.
        //
        // Every batch is judged ONLY on its own anchor — never held because an
        // earlier one is waiting. Holding a ready batch for queue order strands it:
        // the tip keeps climbing past its anchor while it sits here, and the
        // execution gate demands an exact `anchor == tip` match, so it would come
        // back as record-only and its transactions would never run even though
        // peers ran them.
        //
        // That costs no ordering guarantee, because a batch can only ever execute
        // at exactly its own anchor. Anchor order therefore fixes execution order
        // on every node, whatever position a decision happens to occupy here.
        let mut waiting: VecDeque<consensus_state::DeferredDecision> = VecDeque::new();

        loop {
            let cs = &mut self.consensus;
            let Some(decision) = cs.deferred_decisions.pop_front() else {
                break;
            };

            match &decision.value {
                Value::Block {
                    height: bh,
                    hash: decided_hash,
                } => {
                    let bh = *bh;
                    let decided_hash = *decided_hash;

                    // Gate on the tip BEFORE touching `pending_blocks`. A block
                    // can only execute at exactly `last_height + 1`; handing
                    // `handle_block` anything else trips its height guard, which
                    // is fatal to the reactor. Holding the block buffered is not
                    // permission to run it — a node whose execution has fallen
                    // behind caches the whole window from its tip to the
                    // network's, so the buffer hit says nothing about ordering.
                    if bh <= self.last_height {
                        // Terminal, never parked: the height is already executed
                        // (a re-decide after a rollback, or a sync replaying
                        // both) or was reorged away. Parking a decision that
                        // nothing can ever satisfy wedges the drain forever.
                        // Reachable with the block still buffered, too — the
                        // finality path deliberately keeps `pending_blocks`
                        // across a rollback and re-execution.
                        match select_block_at_height(&self.db_conn(), bh).await {
                            Ok(row) => {
                                warn!(
                                    block_height = bh,
                                    decided = %decided_hash,
                                    executed = ?row.map(|r| r.hash),
                                    last_height = self.last_height,
                                    consensus_height = %decision.consensus_height,
                                    "Dropping deferred block decision — at or below tip"
                                );
                                // Dropped is not unrecorded. `batches` is the only
                                // copy of the decided sequence — Malachite asks us
                                // for decided values rather than keeping them — and
                                // the startup cleanup trims an unexecuted SUFFIX,
                                // never a hole in the middle. A height that leaves
                                // no row can never be served to a syncing peer.
                                self.record_declined_block(&decision).await?;
                                continue;
                            }
                            Err(e) => {
                                warn!(error = %e, block_height = bh, "Block lookup failed during drain; parking decision");
                                self.consensus.deferred_decisions.push_front(decision);
                                break;
                            }
                        }
                    }
                    if bh > self.last_height + 1 {
                        // A decision ahead of the tip is one of two things, told
                        // apart by the buffered block at its height. After a
                        // reorg DEEPER than one block, the stale decisions for
                        // the orphaned heights land here (only `tip + 1` can be
                        // declined by the hash check below), while the re-decided
                        // chain-B blocks queue up BEHIND them — parking would
                        // wedge the drain forever, on every node that ever syncs
                        // across the reorg. The poller's canonical block at this
                        // height carrying a different hash is exactly the
                        // evidence the `tip + 1` decline acts on: decline and
                        // record, and let the re-decisions behind it through.
                        if let Some(block) = self.consensus.pending_blocks.get(&bh)
                            && block.hash != decided_hash
                        {
                            warn!(
                                block_height = bh,
                                decided = %decided_hash,
                                local = %block.hash,
                                consensus_height = %decision.consensus_height,
                                "Dropping stale deferred block decision ahead of the tip — \
                                 the canonical chain has replaced it"
                            );
                            self.record_declined_block(&decision).await?;
                            continue;
                        }
                        // No buffered block, or the hashes match: the
                        // predecessors were decided by the network but never
                        // reached this node's executor, and nothing here can
                        // close that gap — the missed heights will not be
                        // re-decided — so park and stay loud: this node needs a
                        // re-sync, and executing out of order is fatal.
                        error!(
                            block_height = bh,
                            last_height = self.last_height,
                            gap = bh - self.last_height,
                            consensus_height = %decision.consensus_height,
                            "Deferred block decision is ahead of the tip — this node cannot \
                             catch up on its own and needs a re-sync"
                        );
                        self.consensus.deferred_decisions.push_front(decision);
                        break;
                    }

                    let block = {
                        let cs = &mut self.consensus;
                        cs.pending_blocks.remove(&bh)
                    };
                    if let Some(block) = block {
                        // A rollback can leave a decision whose block was
                        // reorged away; the block now pending at this height
                        // belongs to the NEW chain. Executing it under the old
                        // decision would bind the wrong block to that consensus
                        // record — drop the stale decision instead and leave
                        // the block pending for a fresh proposal.
                        if block.hash != decided_hash {
                            warn!(
                                block_height = bh,
                                decided = %decided_hash,
                                local = %block.hash,
                                consensus_height = %decision.consensus_height,
                                "Dropping stale deferred block decision — hash mismatch after rollback"
                            );
                            self.record_declined_block(&decision).await?;
                            self.consensus.pending_blocks.insert(bh, block);
                            continue;
                        }
                        info!(
                            block_height = bh,
                            consensus_height = %decision.consensus_height,
                            "Draining deferred block decision"
                        );
                        self.handle_block(block, &decision)
                            .await
                            .context("handle_block failed in deferred drain")?;
                        // The tip moved — anything held may now be ready.
                        restore_waiting(&mut self.consensus.deferred_decisions, &mut waiting);
                    } else {
                        // `bh == last_height + 1` and the poller has not
                        // delivered it yet. The already-executed and reorged
                        // cases were both settled by the tip gate above, so this
                        // is the one genuinely transient case: park and wait for
                        // `BlockInsert` to drive the drain again.
                        info!(
                            block_height = bh,
                            consensus_height = %decision.consensus_height,
                            "Deferred block still waiting for data"
                        );
                        let cs = &mut self.consensus;
                        cs.deferred_decisions.push_front(decision);
                        break;
                    }
                }
                Value::Batch {
                    anchor_height,
                    anchor_hash,
                    txs,
                    ..
                } => {
                    if *anchor_height > self.last_height {
                        // debug!, not info!: every held batch is re-tested after every
                        // block execution, so a lagging node catching up would emit
                        // this once per (held batch x block) from inside the loop.
                        debug!(
                            anchor_height = *anchor_height,
                            last_height = self.last_height,
                            consensus_height = %decision.consensus_height,
                            "Deferred batch still waiting for anchor — holding aside"
                        );
                        waiting.push_back(decision);
                        continue;
                    }
                    info!(
                        anchor_height = *anchor_height,
                        consensus_height = %decision.consensus_height,
                        num_txs = txs.len(),
                        "Draining deferred batch decision"
                    );
                    let anchor_height = *anchor_height;
                    let anchor_hash = *anchor_hash;
                    let resolved_txs = self.resolve_batch_txs(txs).await?;
                    let outcome = self
                        .process_decided_batch(
                            anchor_height,
                            anchor_hash,
                            decision.consensus_height,
                            &decision.certificate,
                            &resolved_txs,
                            decision.certified_txs.as_deref(),
                        )
                        .await
                        .context("process_decided_batch failed in deferred drain")?;
                    if let Some(txids) = outcome.announced_txids(&resolved_txs)
                        && let Some(tx) = &self.event_tx
                        && tx.send(Event::BatchProcessed { txids }).await.is_err()
                    {
                        warn!("Event receiver dropped, cannot send BatchProcessed event");
                    }
                }
            }
        }
        restore_waiting(&mut self.consensus.deferred_decisions, &mut waiting);
        Ok(())
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
            // Hold the reply; `try_fulfill_pending_proposal` owns every way of
            // answering it — the block fast path, banked or freshly-validated
            // candidates, and the deadline machinery. `past_deadline` is false
            // by construction for a proposal created this instant, so this
            // cannot propose a premature empty batch. (This used to duplicate
            // that function's body, and the copies had already drifted.)
            self.consensus.pending_proposal = Some(consensus_state::PendingProposal {
                height,
                round,
                reply,
                timeout,
                created_at: Instant::now(),
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
        let conn = self.db_conn();
        let last_height = self.last_height;
        let mut result = consensus_state::ConsensusResult::None;

        // Take every proposal we held for this height (all rounds) and pick the
        // one matching the decided value. We match on value_id, not round: a node
        // can decide a round it locally advanced past, so the value is often filed
        // under a different round than the one in the certificate.
        let decided = self
            .consensus
            .undecided
            .remove(&certificate.height)
            .and_then(|rounds| {
                rounds
                    .into_values()
                    .find(|p| p.value.id() == certificate.value_id)
            });

        if let Some(proposal) = decided {
            if let Some(obs) = &self.consensus.observation {
                let _ = obs.decided_tx.try_send(DecidedBatch {
                    validator_index: self.consensus.validator_index,
                    consensus_height: certificate.height,
                    value: proposal.value.clone(),
                });
            }
            match &proposal.value {
                Value::Batch {
                    anchor_height,
                    anchor_hash,
                    txs,
                } => {
                    let full_txs = self.resolve_batch_txs(txs).await?;

                    for tx in &full_txs {
                        self.consensus
                            .pending_transactions
                            .remove(&tx.compute_txid());
                    }

                    let cert_bytes = encode_commit_certificate(&certificate)
                        .context("Failed to encode commit certificate")?
                        .encode_to_vec();

                    if *anchor_height > last_height {
                        info!(
                            anchor = anchor_height,
                            last_height,
                            consensus_height = %certificate.height,
                            "Deferring batch — anchor block not yet processed"
                        );
                        self.consensus.deferred_decisions.push_back(
                            consensus_state::DeferredDecision {
                                consensus_height: certificate.height,
                                value: proposal.value.clone(),
                                certificate: cert_bytes,
                                certified_txs: None,
                            },
                        );
                    } else {
                        // anchor_height <= last_height: process_decided_batch's
                        // anchor gate executes at an exact tip match and
                        // records-only (with certified content) for anything
                        // stale — one gate for both callers.
                        let outcome = self
                            .process_decided_batch(
                                *anchor_height,
                                *anchor_hash,
                                certificate.height,
                                &cert_bytes,
                                &full_txs,
                                // Freshly decided — never narrowed by a replay.
                                None,
                            )
                            .await
                            .context("process_decided_batch failed in Finalized handler")?;
                        if let Some(txids) = outcome.announced_txids(&full_txs) {
                            result = consensus_state::ConsensusResult::BatchProcessed { txids };
                        }
                    }
                }
                Value::Block { height, hash } => {
                    let cert_bytes = encode_commit_certificate(&certificate)
                        .context("Failed to encode commit certificate")?
                        .encode_to_vec();

                    // Take the block only when it can execute immediately: the
                    // exact next height, with no earlier block decision still
                    // queued ahead of it. Everything else goes through the
                    // deferred queue, the single ordered execution path.
                    //
                    // Without this, a buffered-but-not-next block was handed
                    // straight to the executor, whose height guard is a `bail!`
                    // — and the `batches` row had already been written. That is
                    // how a signet validator spent 20 h restarting: each boot it
                    // took one decision for a height 128 ahead of its tip, wrote
                    // the record, died on the guard, and came back one consensus
                    // height further from the state it actually held.
                    //
                    // The queue check is `is_block`, not `is_empty`: a deferred
                    // BATCH must not hold a block back. Batches are only ever
                    // gated on their own anchor (see `drain_deferred_decisions`),
                    // and a batch waiting on this very block would deadlock
                    // against it.
                    let in_order = *height == self.last_height + 1
                        && !self
                            .consensus
                            .deferred_decisions
                            .iter()
                            .any(|d| d.value.is_block());
                    let ready = if in_order {
                        self.consensus.pending_blocks.remove(height)
                    } else {
                        None
                    };

                    // Built ONCE. Every arm needs the same four fields, and
                    // `certificate` is the full validator-set commit certificate —
                    // cloning it per arm is pure waste.
                    let decision = consensus_state::DeferredDecision {
                        consensus_height: certificate.height,
                        value: proposal.value.clone(),
                        certificate: cert_bytes,
                        certified_txs: None,
                    };

                    // Being buffered at the right height is not the same as being the
                    // DECIDED block. A rollback can leave a decision whose block was
                    // reorged away, and the block now pending at that height belongs
                    // to the new chain — executing it under the old decision binds the
                    // wrong block to that consensus record. The deferred drain has
                    // always checked this; this path did not, so the guard held only
                    // when the decision happened to arrive late.
                    match ready {
                        // Buffered, and it IS the decided block.
                        Some(block) if block.hash == *hash => {
                            info!(
                                block_height = height,
                                block_hash = %hash,
                                consensus_height = %certificate.height,
                                "Block decided and ready to process"
                            );
                            result = consensus_state::ConsensusResult::Block(block, decision);
                        }
                        // Buffered, but a DIFFERENT block — the decision is stale.
                        // Settled here rather than falling through: the arm below asks
                        // the DB whether an EXECUTED block differs, and at
                        // `last_height + 1` nothing is executed yet, so it would read
                        // "not stale" and defer a decision we just declined.
                        Some(block) => {
                            warn!(
                                block_height = height,
                                decided = %hash,
                                local = %block.hash,
                                consensus_height = %certificate.height,
                                "Dropping stale block decision — hash mismatch after rollback"
                            );
                            self.record_declined_block(&decision).await?;
                            // Back in the buffer: it is the canonical block for this
                            // height on the new chain and still needs a fresh decision.
                            self.consensus.pending_blocks.insert(*height, block);
                        }
                        // Not buffered: either the poller has not delivered it yet, or
                        // the height was executed with a different block (reorged).
                        None => {
                            let is_stale = matches!(
                                select_block_at_height(&conn, *height).await,
                                Ok(Some(row)) if row.hash != *hash
                            );
                            if is_stale {
                                warn!(
                                    block_height = height,
                                    block_hash = %hash,
                                    consensus_height = %certificate.height,
                                    "Ignoring stale block decision (post-rollback)"
                                );
                                self.record_declined_block(&decision).await?;
                            } else {
                                info!(
                                    block_height = height,
                                    block_hash = %hash,
                                    last_height = self.last_height,
                                    consensus_height = %certificate.height,
                                    "Block decided but not ready to execute — deferring"
                                );
                                self.consensus.deferred_decisions.push_back(decision);
                                // Run the drain NOW rather than waiting for the next
                                // block event. The decision just queued may already be
                                // settleable — after a ≥2-deep reorg, the stale
                                // pre-reorg decision lands here with its replacement
                                // block already buffered, and a node syncing that
                                // range receives no further block events to trigger
                                // the drain: without this it parks forever with the
                                // re-decided chain queued behind it.
                                self.advance()
                                    .await
                                    .context("advance failed after deferring a block decision")?;
                            }
                        }
                    }
                }
            }
        } else {
            // We decided a value we never assembled locally. For blocks this can't
            // happen (every node rebuilds the same block reference when proposing);
            // it would mean a batch decided at a round whose proposal we never saw
            // and whose txs aren't in our pool. Surface it rather than dropping it
            // silently, which would leave a hole in the decided sequence.
            warn!(
                height = %certificate.height,
                value = %certificate.value_id,
                "Finalized a value not held among our undecided proposals for this height"
            );
        }

        // An OOM backstop, not a policy knob. A node that genuinely cannot catch
        // up accumulates one deferred decision per decided value, each carrying a
        // certificate and possibly raw txs, forever. Failing here turns an
        // eventual OOM-kill into an explicit, diagnosable exit that names the
        // gap. Deliberately far above any real backlog: a tight bound would
        // recreate the crash loop this whole change exists to remove, and on a
        // bare-quorum network a crash loop takes the chain down with it.
        if self.consensus.deferred_decisions.len() > MAX_DEFERRED_DECISIONS {
            bail!(
                "deferred decision queue exceeded {MAX_DEFERRED_DECISIONS} entries at block \
                 height {} (consensus height {}) — this node is not executing what consensus \
                 decides and cannot recover on its own; re-sync required",
                self.last_height,
                certificate.height
            );
        }

        self.consensus.current_height = certificate.height.increment();
        self.consensus.current_round = Round::Nil;
        self.consensus.pending_proposal = None;

        let next = Next::Start(
            self.consensus.current_height,
            self.consensus.height_params(),
        );

        reply
            .send(next)
            .map_err(|_| anyhow::anyhow!("Failed to send Finalized reply"))?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::{batch_is_ordered, build_replay_queue, dependency_sort, restore_waiting};
    use crate::consensus::{Height, Value};
    use crate::reactor::consensus_state::DeferredDecision;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::collections::VecDeque;

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
            certified_txs: None,
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
        decision.certified_txs = Some(decided_all.clone());

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
        assert!(queue[0].certified_txs.is_none());
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
