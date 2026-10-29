use std::collections::{HashMap, HashSet, VecDeque};

use bitcoin::{Transaction, Txid};

use crate::consensus::{Height, Value};
use crate::protocol::coordinator::decision::DeferredDecision;

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
pub(crate) fn build_replay_queue(
    replayed: Vec<(DeferredDecision, Vec<Transaction>)>,
    survivors: Vec<(DeferredDecision, Vec<Transaction>)>,
    // Exclusions PER consensus height, already re-verified against the chain.
    applicable: &HashMap<u64, HashSet<String>>,
) -> (VecDeque<DeferredDecision>, HashSet<Txid>) {
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

    let dropped_at = |decision: &DeferredDecision, txid: &Txid| -> bool {
        applicable
            .get(&decision.consensus_height.as_u64())
            .is_some_and(|s| s.contains(&txid.to_string()))
    };

    // Which txids each decision must drop, computed in EXECUTION order and then
    // applied in queue order. Two orders, because they answer different questions:
    //
    //   * availability — whether a tx's parent output exists when the tx runs — is
    //     a function of the order transactions EXECUTE, which is anchor order: the
    //     drain holds every batch aside until the tip reaches its anchor, so a batch
    //     at a lower anchor runs first regardless of consensus height. That order is
    //     a shared input `(anchor_height, consensus_height)` — the same one
    //     `check_finality` renders its verdict in — so every node computes the same
    //     drops. Walking in QUEUE order instead (replay-set-first, survivors behind)
    //     was node-local: a lagging node orders a survivor differently from a node
    //     that already executed the height, so the two kept different tx sets from
    //     one rollback with identical exclusion rows — silent state divergence.
    //
    //   * the QUEUE order is replay-set-first for drain LIVENESS (a survivor block
    //     decision ordered ahead of the replay set would stall the very decisions
    //     that raise the tip back up), and is unrelated to availability.
    //
    // The walk tracks outputs the original execution produced that this replay will
    // not: every excluded tx, from the anchor position it was dropped at, until (if
    // ever) a later position re-decides and keeps it. A keep re-creates its parent's
    // outputs only from its own position onward, so a child ordered between an
    // excluded parent and its re-decide drops (#427 through the re-decide door),
    // while a child ordered before the parent keeps — it never saw those effects in
    // the original execution either. Exclusions recorded at heights not in this
    // queue happened below `from_anchor`, before every position here, so they are
    // unavailable from the start (#427's original shape).
    let queued_heights: HashSet<u64> = merged
        .iter()
        .map(|(d, _)| d.consensus_height.as_u64())
        .collect();
    let mut unavailable: HashSet<Txid> = applicable
        .iter()
        .filter(|(height, _)| !queued_heights.contains(height))
        .flat_map(|(_, txids)| txids.iter().filter_map(|t| t.parse::<Txid>().ok()))
        .collect();

    let mut execution_order: Vec<usize> = (0..merged.len()).collect();
    execution_order.sort_by_key(|&i| {
        let (d, _) = &merged[i];
        match &d.value {
            Value::Batch { anchor_height, .. } => (*anchor_height, d.consensus_height.as_u64()),
            // Blocks carry no batch txs; the walk ignores them, so their key only
            // needs to be stable. Their own height orders them among batches.
            Value::Block { height, .. } => (*height, d.consensus_height.as_u64()),
        }
    });

    // Dropped positions per merged index, so the emit below filters by index and
    // never re-hashes a tx the walk already hashed here.
    let mut all_excluded: HashSet<Txid> = HashSet::new();
    let mut dropped_positions: HashMap<usize, HashSet<usize>> = HashMap::new();
    for &i in &execution_order {
        let (decision, txs) = &merged[i];
        if !matches!(decision.value, Value::Batch { .. }) {
            continue;
        }
        let mut dropped = HashSet::new();
        for (pos, tx) in txs.iter().enumerate() {
            let txid = tx.compute_txid();
            if dropped_at(decision, &txid) {
                all_excluded.insert(txid);
                unavailable.insert(txid);
                dropped.insert(pos);
            } else if tx
                .input
                .iter()
                .any(|i| unavailable.contains(&i.previous_output.txid))
            {
                // A descendant of a tx missing AT THIS EXECUTION POSITION. Dropped in
                // memory, deliberately NOT recorded in `excluded_batch_txids`: a
                // descendant's drop is only justified while its parent stays excluded,
                // and a durable row outlives that justification — the read predicate
                // re-checks the CHILD's confirmation, never the parent's recovery, so a
                // recorded child would stay dropped after a reorg heals the parent while
                // every fresh syncer executes it. Re-deriving from the durable base rows
                // each pass costs at most one extra rollback (a leaked child re-arms its
                // own deadline and becomes a base row); a wrong durable drop is a
                // divergence.
                all_excluded.insert(txid);
                unavailable.insert(txid);
                dropped.insert(pos);
            } else {
                // A re-decided copy of a previously excluded tx: from here on its
                // outputs exist again, so later children survive.
                unavailable.remove(&txid);
            }
        }
        if !dropped.is_empty() {
            dropped_positions.insert(i, dropped);
        }
    }

    // Emit the queue in its original (replay-first) order — deliberately NOT the
    // execution order above. Replay-first is the drain's LIVENESS order (a survivor
    // BLOCK decision ahead of the replay set would stall the tip); the drain
    // executes each batch only when the tip reaches its anchor, and among batches
    // sharing an anchor it cannot reverse a cross-batch dependency: the dependent
    // batch can only be a survivor while its dependency is one (both wait for the
    // same tip in decided order), never replayed-ahead of a survivor dependency,
    // because the tip passing an anchor drains every deferred batch at it. So the
    // deterministic per-position drop set is safe under the node-local queue order.
    let mut queue = VecDeque::with_capacity(merged.len());
    for (idx, (mut decision, txs)) in merged.into_iter().enumerate() {
        if let Value::Batch {
            anchor_height,
            anchor_hash,
            ..
        } = &decision.value
        {
            let (anchor_height, anchor_hash) = (*anchor_height, *anchor_hash);
            let dropped = dropped_positions.get(&idx);
            let kept: Vec<Transaction> = txs
                .iter()
                .enumerate()
                .filter(|(pos, _)| !dropped.is_some_and(|d| d.contains(pos)))
                .map(|(_, tx)| tx.clone())
                .collect();
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
