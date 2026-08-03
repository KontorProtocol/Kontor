use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use anyhow::{Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use indexer_types::Event;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_core_types::{Round, Validity};
use malachitebft_engine::host::Next;
use metrics::{counter, gauge};
use prost::Message;
use tracing::{debug, info, warn};

use crate::consensus::codec::encode_commit_certificate;
use crate::consensus::finality_types::{DecidedBatch, StateEvent, UnfinalizedBatch, deadline_for};
use crate::consensus::{CommitCertificate, Ctx, Height, ProposalData, Value};
use crate::database::queries::{
    insert_batch, insert_batch_txids, insert_transaction, insert_unconfirmed_batch_tx,
    select_block_at_height, select_existing_txids,
};
use crate::metrics::{CONSENSUS_HEIGHT, ITEMS_INDEXED};

use super::Reactor;
use super::consensus_state;
use super::executor::Executor;
use super::mempool_fee_index::MempoolFeeIndex;

/// Multiplier applied to `MempoolFeeIndex::fastest_fee()` to derive the
/// per-batch acceptance threshold, as an integer ratio: 9/10 means we accept
/// txs at or above 90% of the median fee rate in projected block 0. Integer
/// math because this feeds proposal validation — a consensus-adjacent path
/// where float rounding is a determinism hazard (#429).
const FEE_THRESHOLD_NUM: u64 = 9;
const FEE_THRESHOLD_DEN: u64 = 10;

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

/// Expand a set of excluded txids to every batch tx that (transitively) spends
/// an excluded tx's output. Rollback replay filters excluded txids out of
/// replayed batches; dropping a parent while keeping its child would execute
/// the child against missing UTXOs and commit its deterministic failure —
/// silent state divergence (#427). Operates over the ordered replay sequence,
/// since a child may sit in a later batch than its parent. Iterates the
/// forward pass to a true fixed point rather than assuming parents always
/// precede children across batches — decided order makes that overwhelmingly
/// likely, but no consensus rule ENFORCES the cross-batch direction, and the
/// loop costs one extra no-growth pass in the normal case.
fn transitive_exclusion(
    batches: &[Vec<bitcoin::Transaction>],
    excluded: &HashSet<Txid>,
) -> HashSet<Txid> {
    let mut excluded = excluded.clone();
    loop {
        let before = excluded.len();
        for txs in batches {
            for tx in txs {
                let txid = tx.compute_txid();
                if excluded.contains(&txid) {
                    continue;
                }
                if tx
                    .input
                    .iter()
                    .any(|i| excluded.contains(&i.previous_output.txid))
                {
                    excluded.insert(txid);
                }
            }
        }
        if excluded.len() == before {
            return excluded;
        }
    }
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
/// them — from the batches in the result. Returns the queue and the full transitive
/// exclusion set, which the caller also purges from the proposal pool.
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
    excluded_txids: &HashSet<Txid>,
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

    if excluded_txids.is_empty() {
        return (merged.into_iter().map(|(d, _)| d).collect(), HashSet::new());
    }

    let batches: Vec<Vec<bitcoin::Transaction>> =
        merged.iter().map(|(_, txs)| txs.clone()).collect();
    let excluded = transitive_exclusion(&batches, excluded_txids);

    let queue = merged
        .into_iter()
        .map(|(mut decision, txs)| {
            if let Value::Batch {
                anchor_height,
                anchor_hash,
                ..
            } = &decision.value
            {
                let (anchor_height, anchor_hash) = (*anchor_height, *anchor_hash);
                let kept: Vec<bitcoin::Transaction> = txs
                    .into_iter()
                    .filter(|tx| !excluded.contains(&tx.compute_txid()))
                    .collect();
                decision.value = Value::new_batch_raw(anchor_height, anchor_hash, kept);
            }
            decision
        })
        .collect();

    (queue, excluded)
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
    async fn record_batch_txs(
        &self,
        conn: &libsql::Connection,
        consensus_height: Height,
        batch_txs: &[bitcoin::Transaction],
    ) -> Result<()> {
        let txids: Vec<String> = batch_txs
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect();
        insert_batch_txids(conn, consensus_height.as_u64(), &txids)
            .await
            .context("Failed to insert batch txids")?;
        for raw_tx in batch_txs {
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
            self.record_batch_txs(&conn, consensus_height, batch_txs)
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
        self.record_batch_txs(&conn, consensus_height, batch_txs)
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

    pub(super) async fn make_value(&mut self) -> Result<Option<Value>> {
        let conn = self.db_conn();
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        // If blocks are pending, always propose the next one first
        if let Some((&height, block)) = self.consensus.pending_blocks.first_key_value() {
            return Ok(Some(Value::new_block(height, block.hash)));
        }

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

        // Per-tx validation — remove invalid txs from the pool. Compute
        // the fee threshold once for this batch (it's the same for every
        // tx, since the index is a snapshot during this loop).
        let threshold = compute_fee_threshold(&self.consensus.mempool_fee_index);
        let mut txs = Vec::new();
        let mut invalid_txids = Vec::new();
        for (raw_tx, parsed) in self.consensus.pending_transactions.values() {
            let txid = raw_tx.compute_txid();
            if !unbatched_set.contains(&txid) {
                continue;
            }
            if self
                .executor
                .validate_transaction(raw_tx, parsed, threshold)
                .await?
            {
                txs.push(raw_tx.clone());
            } else {
                invalid_txids.push(txid);
            }
        }
        for txid in &invalid_txids {
            self.consensus.pending_transactions.remove(txid);
        }
        if txs.is_empty() {
            return Ok(None);
        }

        // Propose in dependency order — `pending_transactions` enumerates
        // in arbitrary order, but `validate_batch` rejects a batch with a
        // child ahead of its parent, so sort before validating.
        let order = dependency_sort(&txs);
        let txs: Vec<bitcoin::Transaction> = order.into_iter().map(|i| txs[i].clone()).collect();

        // Batch-level validation (already-processed check will pass since we pre-filtered)
        if let Some(reason) = self
            .consensus
            .validate_batch(&conn, last_height, last_hash, &txs, last_height, last_hash)
            .await?
        {
            info!("Not proposing batch: {reason}");
            return Ok(None);
        }

        let value = Value::new_batch_raw(last_height, last_hash, txs);
        Ok(Some(value))
    }

    pub(super) async fn validate_and_accept_proposal(
        &mut self,
        data: &ProposalData,
        height: Height,
        round: Round,
    ) -> Result<Option<ProposedValue<Ctx>>> {
        let conn = self.db_conn();
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        let value = match data {
            ProposalData::Block { height: bh, hash } => {
                if let Some(block) = self.consensus.pending_blocks.get(bh) {
                    if block.hash != *hash {
                        warn!(
                            block_height = bh,
                            proposed = %hash,
                            local = %block.hash,
                            "Rejecting block proposal: hash mismatch"
                        );
                        return Ok(None);
                    }
                } else {
                    warn!(
                        block_height = bh,
                        "Rejecting block proposal: block not yet received"
                    );
                    return Ok(None);
                }
                Value::new_block(*bh, *hash)
            }
            ProposalData::Batch {
                anchor_height,
                anchor_hash,
                transactions,
            } => {
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
                    return Ok(None);
                }
                let threshold = compute_fee_threshold(&self.consensus.mempool_fee_index);
                for tx in transactions {
                    let txid = tx.compute_txid();
                    let parsed =
                        if let Some((_, cached)) = self.consensus.pending_transactions.get(&txid) {
                            cached.clone()
                        } else if let Some(p) = self.executor.parse_transaction(tx) {
                            p
                        } else {
                            warn!(%txid, "Rejecting proposal: transaction failed to parse");
                            return Ok(None);
                        };
                    if !self
                        .executor
                        .validate_transaction(tx, &parsed, threshold)
                        .await?
                    {
                        warn!(%txid, "Rejecting proposal: transaction failed validation");
                        return Ok(None);
                    }
                    self.consensus
                        .pending_transactions
                        .entry(txid)
                        .or_insert_with(|| (tx.clone(), parsed));
                }
                Value::new_batch_raw(*anchor_height, *anchor_hash, transactions.clone())
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
        Ok(Some(proposed))
    }

    pub(super) async fn try_fulfill_pending_proposal(&mut self) -> Result<bool> {
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        let (past_deadline, pending_height, pending_round) = match &self.consensus.pending_proposal
        {
            Some(p) => (Instant::now() >= p.hard_deadline(), p.height, p.round),
            None => return Ok(false),
        };

        let value = if let Some(value) = self.make_value().await? {
            value
        } else if past_deadline {
            info!(
                height = %pending_height,
                round = %pending_round,
                "Proposing empty batch at hard deadline"
            );
            Value::new_batch_raw(last_height, last_hash, vec![])
        } else {
            return Ok(false);
        };

        let pending = self.consensus.pending_proposal.take().unwrap();
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

        Ok(true)
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

    /// Install the replay decisions loaded by `load_replay_decisions` and kick
    /// off block redelivery. Runs AFTER the DB truncation: the raw-tx
    /// resolution below can touch bitcoind, and a transient failure here is
    /// fatal-but-recoverable (the rollback already happened; on restart the
    /// startup cleanup forgets the unexecuted suffix and the node re-syncs).
    /// Before the truncation it would instead CANCEL a rollback that finality
    /// already demanded.
    pub(super) async fn prepare_replay(
        &mut self,
        from_anchor: u64,
        replay_batches: Vec<consensus_state::DeferredDecision>,
        excluded_txids: HashSet<Txid>,
    ) -> Result<()> {
        info!(
            from_anchor,
            replay_batches = replay_batches.len(),
            excluded = excluded_txids.len(),
            "Initiating rollback replay"
        );

        // Resolve BOTH the replay set and whatever was already queued before
        // excluding anything: the exclusion closure must see tx INPUTS to drop
        // descendants of an excluded tx, and a descendant can perfectly well sit in
        // a queued decision — it is queued because its anchor is HIGHER, which is
        // exactly where a child of an earlier tx lives. Resolving only the replay
        // set let such a child through to execute against state the rollback wiped
        // (#427 in a second form). Resolution pulls from the same sources the drain
        // would use later.
        let mut replayed = Vec::with_capacity(replay_batches.len());
        for decision in replay_batches {
            let txs = match &decision.value {
                Value::Batch { txs, .. } => self.resolve_batch_txs(txs).await?,
                Value::Block { .. } => Vec::new(),
            };
            replayed.push((decision, txs));
        }
        let queued = std::mem::take(&mut self.consensus.deferred_decisions);
        let mut survivors = Vec::with_capacity(queued.len());
        for decision in queued {
            let txs = match &decision.value {
                Value::Batch { txs, .. } => self.resolve_batch_txs(txs).await?,
                Value::Block { .. } => Vec::new(),
            };
            survivors.push((decision, txs));
        }

        let (queue, excluded) = build_replay_queue(replayed, survivors, &excluded_txids);
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
        let Some((rollback_anchor, excluded)) = self
            .consensus
            .run_finality_checks(&conn, self.last_height)
            .await
        else {
            return Ok(false);
        };

        // Read replay decisions BEFORE the truncation — the query joins rows that
        // are cascade-deleted with their blocks.
        let replay = self
            .load_replay_decisions(rollback_anchor)
            .await
            .context("load_replay_decisions failed")?;

        // Roll back to before the invalid anchor so all state at the anchor height
        // (including the invalid txs' effects) is wiped cleanly.
        //
        // Depth-checked like the reorg path. Rehydration can re-arm a deadline whose
        // anchor sits far below the tip — that is exactly the #515 residue this PR
        // exists to pick up — and truncating below the prune watermark would destroy
        // state rather than restore it. Halting for a re-sync is the intended outcome.
        self.check_rollback_depth(rollback_anchor.saturating_sub(1))
            .context("finality rollback too deep")?;
        self.rollback(rollback_anchor.saturating_sub(1))
            .await
            .context("rollback failed during finality rollback")?;

        // Fallible raw-tx resolution/filtering only after the truncation is durable:
        // a failure here must not cancel a rollback finality already demanded.
        self.prepare_replay(rollback_anchor, replay, excluded)
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
                            self.consensus.pending_blocks.insert(bh, block);
                            continue;
                        }
                        info!(
                            block_height = bh,
                            consensus_height = %decision.consensus_height,
                            "Draining deferred block decision"
                        );
                        self.handle_block_with_decision(block, &decision)
                            .await
                            .context("handle_block_with_decision failed in deferred drain")?;
                        // The tip moved — anything held may now be ready.
                        restore_waiting(&mut self.consensus.deferred_decisions, &mut waiting);
                    } else {
                        // No pending block at this height. Before parking the
                        // queue on it, check whether the height was already
                        // executed: a block row with the SAME hash means this
                        // decision is a duplicate record (a re-decide after a
                        // rollback, or a sync replaying both) — already
                        // satisfied; a DIFFERENT hash means the decided block
                        // was reorged away. Either way the decision is
                        // terminal — parking it would wedge the drain forever
                        // on a delivery that can never come.
                        match select_block_at_height(&self.db_conn(), bh).await {
                            Ok(Some(row)) => {
                                warn!(
                                    block_height = bh,
                                    decided = %decided_hash,
                                    executed = %row.hash,
                                    consensus_height = %decision.consensus_height,
                                    "Dropping deferred block decision — height already executed"
                                );
                                continue;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                warn!(error = %e, block_height = bh, "Block lookup failed during drain; parking decision");
                            }
                        }
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
        } else if let Some(value) = self.make_value().await? {
            let proposed = ProposedValue {
                height,
                round,
                valid_round: Round::Nil,
                proposer: self.consensus.address,
                value: value.clone(),
                validity: Validity::Valid,
            };
            self.consensus
                .undecided
                .entry(height)
                .or_default()
                .insert(round, proposed);
            let proposal = LocallyProposedValue::new(height, round, value);
            self.send_proposal_parts(&proposal, Round::Nil).await?;
            reply
                .send(proposal)
                .map_err(|_| anyhow::anyhow!("Failed to send GetValue reply"))?;
        } else {
            info!(%height, %round, "Nothing to propose, holding reply for pending transactions");
            self.consensus.pending_proposal = Some(consensus_state::PendingProposal {
                height,
                round,
                reply,
                timeout,
                created_at: Instant::now(),
            });
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

                    if let Some(block) = self.consensus.pending_blocks.remove(height) {
                        info!(
                            block_height = height,
                            block_hash = %hash,
                            consensus_height = %certificate.height,
                            "Block decided and ready to process"
                        );
                        result = consensus_state::ConsensusResult::Block(
                            block,
                            consensus_state::DeferredDecision {
                                consensus_height: certificate.height,
                                value: proposal.value.clone(),
                                certificate: cert_bytes.clone(),
                            },
                        );
                    } else {
                        let is_stale = match select_block_at_height(&conn, *height).await {
                            Ok(Some(row)) => row.hash != *hash,
                            _ => false,
                        };
                        if !is_stale {
                            info!(
                                block_height = height,
                                block_hash = %hash,
                                consensus_height = %certificate.height,
                                "Block decided but not yet received — deferring"
                            );
                            self.consensus.deferred_decisions.push_back(
                                consensus_state::DeferredDecision {
                                    consensus_height: certificate.height,
                                    value: proposal.value.clone(),
                                    certificate: cert_bytes.clone(),
                                },
                            );
                        } else {
                            warn!(
                                block_height = height,
                                block_hash = %hash,
                                "Ignoring stale block decision (post-rollback)"
                            );
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
    use super::{
        batch_is_ordered, build_replay_queue, dependency_sort, restore_waiting,
        transitive_exclusion,
    };
    use crate::consensus::{Height, Value};
    use crate::reactor::consensus_state::DeferredDecision;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
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

    #[test]
    fn transitive_exclusion_drops_descendants_within_a_batch() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);
        let grandchild = tx(&[spend(&child)], 3);
        let independent = tx(&[OutPoint::null()], 4);

        let excluded: HashSet<Txid> = [parent.compute_txid()].into();
        let batch = vec![
            parent.clone(),
            child.clone(),
            grandchild.clone(),
            independent.clone(),
        ];
        let result = transitive_exclusion(&[batch], &excluded);

        assert!(result.contains(&parent.compute_txid()));
        assert!(result.contains(&child.compute_txid()));
        assert!(result.contains(&grandchild.compute_txid()));
        assert!(!result.contains(&independent.compute_txid()));
    }

    #[test]
    fn transitive_exclusion_crosses_batch_boundaries() {
        let parent = tx(&[OutPoint::null()], 1);
        let child = tx(&[spend(&parent)], 2);
        let excluded: HashSet<Txid> = [parent.compute_txid()].into();

        // Parent in batch 0, child in batch 1 — the closure must follow the
        // dependency across the replay sequence.
        let result = transitive_exclusion(&[vec![parent.clone()], vec![child.clone()]], &excluded);
        assert!(result.contains(&child.compute_txid()));
    }

    /// Decisions are identified by consensus height, not by position.
    fn decision(consensus_height: u64) -> DeferredDecision {
        DeferredDecision {
            consensus_height: Height::new(consensus_height),
            value: Value::new_batch_raw(0, bitcoin::BlockHash::all_zeros(), vec![]),
            certificate: Vec::new(),
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

    fn queue_of(
        replayed: Vec<(DeferredDecision, Vec<Transaction>)>,
        survivors: Vec<(DeferredDecision, Vec<Transaction>)>,
    ) -> VecDeque<DeferredDecision> {
        build_replay_queue(replayed, survivors, &HashSet::new()).0
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

        let excluded: HashSet<Txid> = [parent.compute_txid()].into();
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

    #[test]
    fn transitive_exclusion_leaves_unrelated_batches_untouched() {
        let a = tx(&[OutPoint::null()], 1);
        let b = tx(&[OutPoint::null()], 2);
        let excluded: HashSet<Txid> = [tx(&[OutPoint::null()], 9).compute_txid()].into();

        let result = transitive_exclusion(&[vec![a.clone()], vec![b.clone()]], &excluded);
        assert!(!result.contains(&a.compute_txid()));
        assert!(!result.contains(&b.compute_txid()));
        assert_eq!(result.len(), 1);
    }
}
