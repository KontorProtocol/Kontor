use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use bitcoin::{Transaction, Txid};

mod finality;
mod replay;

pub(crate) use finality::build_finality_events;
pub(crate) use replay::build_replay_queue;

pub const FINALITY_WINDOW: u64 = 6;

// Invalidating an anchor at its deadline restores the anchor's predecessor.
pub const FINALITY_ROLLBACK_DEPTH: u64 = FINALITY_WINDOW + 1;

/// Bitcoin height by which a batch anchored at `anchor_height` must have its
/// transactions confirmed, or the batch is void and its anchor rolls back.
pub const fn deadline_for(anchor_height: u64) -> u64 {
    anchor_height + FINALITY_WINDOW
}

/// Lowest anchor height whose batches can still be awaiting a deadline at `tip`.
/// Startup rehydration reloads exactly this band, so it introduces no new window —
/// it reconstructs the set the running node already tracks.
///
/// Inclusive of the at-deadline anchor (`anchor >= floor`, not `>`): a batch whose
/// deadline is exactly `tip` still needs its verdict, and dropping it on restart
/// would silently skip the rollback a peer performs. The first `check_finality`
/// after startup settles it.
pub const fn tracking_floor(tip: u64) -> u64 {
    tip.saturating_sub(FINALITY_WINDOW)
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
pub(crate) fn dependency_sort(txs: &[Transaction]) -> Vec<usize> {
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
pub(crate) fn batch_is_ordered(txs: &[Transaction]) -> bool {
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
