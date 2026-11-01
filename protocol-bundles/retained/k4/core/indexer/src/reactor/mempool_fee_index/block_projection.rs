//! Greedy block-template projection over the local mempool view.
//!
//! We don't call Bitcoin Core's `getblocktemplate` because (a) it
//! returns only block 0, and we need projections for blocks 0..3 to
//! drive the three fee tiers; (b) it builds a full mineable template
//! (coinbase, witness commitment, merkle tree) which is far heavier
//! than just running tx-selection; (c) we can't customize what it
//! returns. So we re-implement the tx-selection portion locally.
//!
//! Approximates Bitcoin Core's `BlockAssembler` with a CPFP-aware
//! greedy sweep: at each step we include the highest-effective-rate
//! package (transaction + its in-mempool ancestors), then re-score
//! every descendant of the freshly-included transactions because they
//! no longer need to "pay for" included ancestors.
//!
//! Same shape as mempool.space's `gbt` crate, but re-implemented from
//! first principles for our `Txid`-keyed `MempoolEntry`s. Sigops are
//! intentionally omitted: Bitcoin Core's `getmempoolentry.vsize` is
//! already sigop-adjusted (it returns
//! `GetVirtualTransactionSize(weight, sigOpCost, bytesPerSigOp)`), so
//! a second pass would double-count.
//!
//! Output is a `Vec<ProjectedBlock>` where each block's `entries` lists
//! `(cluster_rate_sat_per_vb, vsize)` in inclusion order. The cluster
//! rate is the effective package rate at which a miner would include the
//! transaction; reporting it (rather than each tx's individual rate)
//! keeps `ProjectedBlock::median_fee_rate()` honest in the presence of
//! CPFP packages.
//!
//! The score used for sorting is `min(self_rate, package_rate)`. The
//! `min` is essential: if a tx's package rate is lower than its
//! self-rate (a high-fee child carried down by a low-fee parent) it
//! cannot be included faster than the package allows. Conversely, if the
//! package rate is higher (a low-fee tx artificially inflated by a
//! high-fee ancestor it has no causal claim to) we still cap at
//! self-rate.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

use bitcoin::Txid;
use priority_queue::PriorityQueue;

use crate::bitcoin_client::types::MempoolEntry;

use super::{BLOCK_VSIZE, ProjectedBlock};

/// Stop trying to fit additional packages once this many consecutive
/// candidates have failed to fit AND the current block is close to full.
/// Mirrors mempool.space's threshold so behaviour is comparable.
const FAILURES_BEFORE_BLOCK_FINALIZE: u32 = 1_000;

/// Per-tx working state during a single projection pass. Mutates as
/// packages are included so descendants can be re-scored.
struct WorkingTx {
    self_fee: u64,
    self_vsize: u64,
    /// In-mempool parents from `MempoolEntry.depends`. Indexed for fast
    /// graph traversal; each value points back into the working set.
    parents: Vec<Txid>,
    /// Transitive ancestors (excluding self). Mutated by `forget_ancestor`.
    ancestors: HashSet<Txid>,
    /// In-mempool children. Built by inverting `parents` during graph
    /// construction; never mutated after that.
    children: HashSet<Txid>,
    /// Sum of self_fee + every still-unincluded ancestor's self_fee.
    /// Decreases as ancestors are included and removed from `ancestors`.
    pkg_fee: u64,
    /// Same idea for vsize.
    pkg_vsize: u64,
    /// Marked once this tx lands in some projected block. Used txs are
    /// removed from the priority queue on inclusion, but the flag lets
    /// descendant traversals skip them without re-looking at the queue.
    used: bool,
}

impl WorkingTx {
    fn from_entry(entry: &MempoolEntry) -> Self {
        let fee = entry.fees.base.to_sat();
        Self {
            self_fee: fee,
            self_vsize: entry.vsize,
            parents: entry.depends.clone(),
            ancestors: HashSet::new(),
            children: HashSet::new(),
            pkg_fee: fee,
            pkg_vsize: entry.vsize,
            used: false,
        }
    }

    fn self_rate(&self) -> f64 {
        if self.self_vsize == 0 {
            0.0
        } else {
            self.self_fee as f64 / self.self_vsize as f64
        }
    }

    fn package_rate(&self) -> f64 {
        if self.pkg_vsize == 0 {
            0.0
        } else {
            self.pkg_fee as f64 / self.pkg_vsize as f64
        }
    }

    /// Effective inclusion priority. The miner won't include this tx at
    /// a higher rate than its package supports, nor at a higher rate
    /// than its own self-fee justifies — `min` of the two.
    fn score(&self) -> f64 {
        self.self_rate().min(self.package_rate())
    }

    /// Apply the side-effects of an ancestor being included. Returns the
    /// score before the change so the caller can decide whether the
    /// priority queue needs an update.
    fn forget_ancestor(
        &mut self,
        ancestor_txid: Txid,
        ancestor_fee: u64,
        ancestor_vsize: u64,
    ) -> f64 {
        let prior = self.score();
        if self.ancestors.remove(&ancestor_txid) {
            self.pkg_fee = self.pkg_fee.saturating_sub(ancestor_fee);
            self.pkg_vsize = self.pkg_vsize.saturating_sub(ancestor_vsize);
        }
        prior
    }
}

/// Score wrapper that implements `Ord` so it can sit in a `PriorityQueue`.
/// The two extra fields are tie-breakers: `order` is the original sort
/// position (lower = was higher in the initial stack) and `txid_lex`
/// gives a deterministic last-resort comparator.
#[derive(Clone, Copy, Debug)]
struct Priority {
    score: f64,
    order: u32,
    txid_lex: Txid,
}

impl PartialEq for Priority {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Priority {}

impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Priority {
    fn cmp(&self, other: &Self) -> Ordering {
        // The priority queue is a max-heap, so we want "higher score"
        // to mean "Ord::Greater". Tie-break by `order` (lower = earlier
        // in the initial sort = preferred), then by txid for full
        // determinism.
        match self
            .score
            .partial_cmp(&other.score)
            .unwrap_or(Ordering::Equal)
        {
            Ordering::Equal => {}
            ord => return ord,
        }
        match other.order.cmp(&self.order) {
            Ordering::Equal => {}
            ord => return ord,
        }
        other.txid_lex.cmp(&self.txid_lex)
    }
}

/// Project the next `n_blocks` worth of mined blocks from `entries`.
///
/// High-level driver: pop the highest-priority candidate, try to fit its
/// ancestor chain, either include it (which rescores descendants in one
/// pass) or defer to the next block. All DAG/priority-queue bookkeeping
/// is encapsulated in `WorkingPool`; this function just sequences block
/// boundaries and the "when does the current block finalize" policy.
pub fn project_blocks(
    entries: &HashMap<Txid, MempoolEntry>,
    n_blocks: usize,
) -> Vec<ProjectedBlock> {
    if n_blocks == 0 || entries.is_empty() {
        return vec![];
    }

    let mut pool = WorkingPool::from_entries(entries);
    let mut blocks: Vec<ProjectedBlock> = vec![ProjectedBlock::default()];
    let mut failures: u32 = 0;

    while let Some(chosen) = pool.pop_best() {
        let chain = pool.chain_for(chosen);
        let chain_vsize = pool.chain_vsize(&chain);

        let final_block = blocks.len() == n_blocks;
        let cur_vsize = blocks.last().map(|b| b.vsize).unwrap_or(0);
        let fits = cur_vsize + chain_vsize <= BLOCK_VSIZE;

        if !fits {
            if final_block {
                // No more blocks to spill into; we're done.
                break;
            }
            // Doesn't fit in this block — hold for the next one.
            pool.defer(chosen);
            failures += 1;
        } else {
            // Cluster rate: the chosen tx's score is the rate at which
            // a miner accepts the whole package (bottlenecked by the
            // worst sub-rate in the chain).
            let cluster_rate = pool.score_of(chosen).max(0.0).floor() as u64;
            let block = blocks.last_mut().expect("at least one block");
            pool.include(&chain, cluster_rate, block);
            failures = 0;
        }

        // Finalize when we've stalled near full, or when the queue has
        // drained but we still have deferred candidates waiting for a
        // fresh block.
        let finalize_now = {
            let cur = blocks.last().expect("at least one block");
            (failures > FAILURES_BEFORE_BLOCK_FINALIZE
                && cur.vsize > BLOCK_VSIZE.saturating_sub(8_000))
                || (!pool.has_candidates() && pool.has_overflow())
        };
        if finalize_now {
            let current_has_entries = !blocks
                .last()
                .expect("at least one block")
                .entries
                .is_empty();
            if blocks.len() < n_blocks && current_has_entries {
                blocks.push(ProjectedBlock::default());
                failures = 0;
                pool.drain_overflow();
            } else {
                break;
            }
        }
    }

    // Strip a trailing empty block if the last finalize-and-push left
    // one behind (we pre-allocate the next block before knowing whether
    // we still have candidates).
    if blocks.last().map(|b| b.entries.is_empty()).unwrap_or(false) {
        blocks.pop();
    }

    blocks
}

/// A txid that `WorkingPool::pop_best` validated as both present in the
/// pool and not yet used. Methods that logically require "an actual live
/// candidate" — `chain_for`, `score_of`, `defer` — take `Chosen` rather
/// than `Txid` so the compiler enforces they can only be called with a
/// freshly-popped candidate. Module-private constructor keeps the
/// guarantee from being bypassed outside this file.
#[derive(Clone, Copy, Debug)]
struct Chosen(Txid);

impl Chosen {
    fn txid(self) -> Txid {
        self.0
    }

    #[cfg(test)]
    fn for_testing(txid: Txid) -> Self {
        Self(txid)
    }
}

/// Owns the DAG and the candidate priority queue, with methods that
/// preserve the "`ancestors` contains only unused txs" and "candidate
/// scores are current" invariants. `project_blocks` never mutates these
/// directly — it goes through the methods.
struct WorkingPool {
    txs: HashMap<Txid, WorkingTx>,
    /// Position in a precomputed topological order. Used to sort
    /// ancestor chains parents-before-children without re-walking edges.
    topo_rank: HashMap<Txid, u32>,
    /// Original (pre-rescore) score rank, used as the priority queue
    /// tie-breaker — lower `order` means "appeared higher in the
    /// initial sort," which the `Priority` `Ord` impl prefers.
    order_of: HashMap<Txid, u32>,
    /// All unused candidates. Priority tracks current (possibly rescored)
    /// score; `change_priority` on rescoring keeps it current in-place.
    pq: PriorityQueue<Txid, Priority>,
    /// Candidates whose chain didn't fit in the current block, held for
    /// the next block. Drained back into `pq` on block finalization.
    overflow: Vec<Txid>,
}

impl WorkingPool {
    /// Build the pool from raw `MempoolEntry` data: construct the DAG,
    /// topologically order it, populate ancestor/package aggregates,
    /// and seed the priority queue with the initial score order.
    fn from_entries(entries: &HashMap<Txid, MempoolEntry>) -> Self {
        let mut pool = Self {
            txs: entries
                .iter()
                .map(|(txid, e)| (*txid, WorkingTx::from_entry(e)))
                .collect(),
            topo_rank: HashMap::new(),
            order_of: HashMap::new(),
            pq: PriorityQueue::with_capacity(entries.len()),
            overflow: Vec::new(),
        };

        // Bidirectional DAG + topological order so subsequent passes
        // can rely on them.
        pool.populate_children();
        let topo = pool.topological_order();
        pool.topo_rank = topo
            .iter()
            .enumerate()
            .map(|(i, t)| (*t, i as u32))
            .collect();
        pool.build_relatives(&topo);
        pool.seed_priority_queue();
        pool
    }

    /// Invert `parents` into `children` — every tx registers itself in
    /// each of its parents' children set. The resulting DAG has edges
    /// in both directions, which lets later passes walk either way
    /// without recomputing.
    fn populate_children(&mut self) {
        let edges: Vec<(Txid, Txid)> = self
            .txs
            .iter()
            .flat_map(|(txid, w)| w.parents.iter().map(move |p| (*p, *txid)))
            .collect();
        for (parent, child) in edges {
            if let Some(p) = self.txs.get_mut(&parent) {
                p.children.insert(child);
            }
        }
    }

    /// Kahn's algorithm: emit parents before children. Missing/pruned
    /// parents (referenced in `depends` but absent from the pool) don't
    /// contribute to in-degree, so they don't block progress.
    fn topological_order(&self) -> Vec<Txid> {
        let mut in_degree: HashMap<Txid, usize> = self
            .txs
            .iter()
            .map(|(txid, w)| {
                let deg = w
                    .parents
                    .iter()
                    .filter(|p| self.txs.contains_key(*p))
                    .count();
                (*txid, deg)
            })
            .collect();
        let mut queue: VecDeque<Txid> = in_degree
            .iter()
            .filter_map(|(txid, deg)| (*deg == 0).then_some(*txid))
            .collect();
        let mut order: Vec<Txid> = Vec::with_capacity(self.txs.len());
        while let Some(txid) = queue.pop_front() {
            order.push(txid);
            if let Some(w) = self.txs.get(&txid) {
                for child in &w.children {
                    if let Some(deg) = in_degree.get_mut(child) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(*child);
                        }
                    }
                }
            }
        }
        order
    }

    /// Populate `ancestors`, `pkg_fee`, `pkg_vsize` for every tx.
    ///
    /// Single forward pass over `topo`: by the time we process a tx,
    /// all of its parents have already been processed, so their
    /// `ancestors` sets and package-aggregate fields are stable. That
    /// lets us just union parent ancestor sets (plus the parent itself)
    /// without worrying about recursion or initialization order —
    /// diamond-shaped dependencies are handled by the `HashSet` dedup.
    fn build_relatives(&mut self, topo: &[Txid]) {
        for txid in topo {
            let parents = self
                .txs
                .get(txid)
                .map(|w| w.parents.clone())
                .unwrap_or_default();
            let mut accumulated: HashSet<Txid> = HashSet::new();
            let mut anc_fee: u64 = 0;
            let mut anc_vsize: u64 = 0;
            for parent in &parents {
                if let Some(p) = self.txs.get(parent) {
                    if accumulated.insert(*parent) {
                        anc_fee = anc_fee.saturating_add(p.self_fee);
                        anc_vsize = anc_vsize.saturating_add(p.self_vsize);
                    }
                    // Parent's ancestors are already populated (topo order).
                    for grand in &p.ancestors {
                        if accumulated.insert(*grand)
                            && let Some(g) = self.txs.get(grand)
                        {
                            anc_fee = anc_fee.saturating_add(g.self_fee);
                            anc_vsize = anc_vsize.saturating_add(g.self_vsize);
                        }
                    }
                }
            }
            if let Some(w) = self.txs.get_mut(txid) {
                w.ancestors = accumulated;
                w.pkg_fee = w.self_fee.saturating_add(anc_fee);
                w.pkg_vsize = w.self_vsize.saturating_add(anc_vsize);
            }
        }
    }

    /// Compute `order_of` (stable tie-break position for each tx) from
    /// the score-descending ranking, then seed the pq with every tx.
    fn seed_priority_queue(&mut self) {
        let mut initial: Vec<(Txid, f64)> = self
            .txs
            .iter()
            .map(|(txid, w)| (*txid, w.score()))
            .collect();
        initial.sort_by(
            |a, b| match b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal) {
                Ordering::Equal => a.0.cmp(&b.0),
                ord => ord,
            },
        );
        self.order_of = initial
            .iter()
            .enumerate()
            .map(|(i, (t, _))| (*t, i as u32))
            .collect();
        for (txid, _) in initial {
            self.enqueue(txid);
        }
    }

    /// Insert or update `txid` in the priority queue with its current
    /// score. Central point for all pq additions — keeps the three
    /// priority-construction sites from duplicating the `Priority`
    /// field layout and the `order_of` fallback.
    fn enqueue(&mut self, txid: Txid) {
        let score = self.txs.get(&txid).map(WorkingTx::score).unwrap_or(0.0);
        let prio = Priority {
            score,
            order: self.order_of.get(&txid).copied().unwrap_or(u32::MAX),
            txid_lex: txid,
        };
        self.pq.push(txid, prio);
    }

    /// Pop the highest-priority unused candidate. Used txs are removed
    /// on inclusion, so the front of the queue is always live; the
    /// returned `Chosen` captures that invariant at compile time.
    fn pop_best(&mut self) -> Option<Chosen> {
        self.pq.pop().map(|(t, _)| Chosen(t))
    }

    /// `chosen` plus its unused transitive ancestors, ordered parents-
    /// before-children by `topo_rank`. `chosen.ancestors` is maintained
    /// to contain only unused ancestors (see module-level invariants),
    /// and `Chosen` asserts that `chosen` itself is unused.
    fn chain_for(&self, chosen: Chosen) -> Vec<Txid> {
        let root = chosen.txid();
        let Some(w) = self.txs.get(&root) else {
            return Vec::new();
        };
        let mut chain: Vec<Txid> = std::iter::once(root)
            .chain(w.ancestors.iter().copied())
            .collect();
        chain.sort_by_key(|t| self.topo_rank.get(t).copied().unwrap_or(u32::MAX));
        chain
    }

    /// Sum of `self_vsize` across `chain`.
    fn chain_vsize(&self, chain: &[Txid]) -> u64 {
        chain
            .iter()
            .map(|t| self.txs.get(t).map(|w| w.self_vsize).unwrap_or(0))
            .sum()
    }

    /// Score of `chosen`, or 0 if missing.
    fn score_of(&self, chosen: Chosen) -> f64 {
        self.txs
            .get(&chosen.txid())
            .map(WorkingTx::score)
            .unwrap_or(0.0)
    }

    /// Include `chain` in `block` at `cluster_rate`, mark members used,
    /// and rescore every unique descendant of the chain in a single
    /// combined BFS pass. A shared descendant (reachable from multiple
    /// chain members) is visited once and has `forget_ancestor` applied
    /// for every chain member it depended on.
    fn include(&mut self, chain: &[Txid], cluster_rate: u64, block: &mut ProjectedBlock) {
        // Phase 1: mark used, push into the block, pull out of the pq,
        // and record each member's (fee, vsize) for the rescore pass.
        let mut chain_fees: Vec<(Txid, u64, u64)> = Vec::with_capacity(chain.len());
        for &m in chain {
            if let Some(w) = self.txs.get_mut(&m) {
                w.used = true;
                block.entries.push((cluster_rate, w.self_vsize));
                block.vsize += w.self_vsize;
                chain_fees.push((m, w.self_fee, w.self_vsize));
            }
            self.pq.remove(&m);
        }
        let chain_set: HashSet<Txid> = chain_fees.iter().map(|(m, _, _)| *m).collect();

        // Phase 2: collect the chain's immediate (non-chain) children
        // as the initial BFS frontier. Then walk descendants, applying
        // every chain member's forget_ancestor per descendant. Each
        // descendant is visited exactly once.
        let mut visited: HashSet<Txid> = HashSet::new();
        let mut frontier: Vec<Txid> = Vec::new();
        for (m, _, _) in &chain_fees {
            if let Some(w) = self.txs.get(m) {
                for c in &w.children {
                    if !chain_set.contains(c) {
                        frontier.push(*c);
                    }
                }
            }
        }

        while let Some(d) = frontier.pop() {
            if !visited.insert(d) {
                continue;
            }
            if chain_set.contains(&d) {
                continue;
            }
            let Some(d_tx) = self.txs.get_mut(&d) else {
                continue;
            };
            if d_tx.used {
                continue;
            }
            let prior_score = d_tx.score();
            for (m, m_fee, m_vsize) in &chain_fees {
                d_tx.forget_ancestor(*m, *m_fee, *m_vsize);
            }
            let new_score = d_tx.score();
            let children: Vec<Txid> = d_tx.children.iter().copied().collect();

            if (new_score - prior_score).abs() > f64::EPSILON {
                // `enqueue` uses `pq.push`, which updates the priority
                // if the key is already present — handles both the
                // "still in pq because never popped" and "already
                // popped, not in pq" cases.
                self.enqueue(d);
            }

            for c in children {
                if !visited.contains(&c) && !chain_set.contains(&c) {
                    frontier.push(c);
                }
            }
        }
    }

    /// Set aside `chosen` until the current block finalizes.
    fn defer(&mut self, chosen: Chosen) {
        self.overflow.push(chosen.txid());
    }

    /// Move deferred candidates back into the priority queue with their
    /// (possibly rescored) current priority. Called on block finalize.
    fn drain_overflow(&mut self) {
        while let Some(txid) = self.overflow.pop() {
            if self.txs.get(&txid).is_some_and(|w| !w.used) {
                self.enqueue(txid);
            }
        }
    }

    fn has_candidates(&self) -> bool {
        !self.pq.is_empty()
    }

    fn has_overflow(&self) -> bool {
        !self.overflow.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn txid(n: u8) -> Txid {
        let mut b = [0u8; 32];
        b[31] = n;
        Txid::from_byte_array(b)
    }

    fn leaf(parents: Vec<Txid>) -> WorkingTx {
        WorkingTx {
            self_fee: 1,
            self_vsize: 1,
            parents,
            ancestors: HashSet::new(),
            children: HashSet::new(),
            pkg_fee: 1,
            pkg_vsize: 1,
            used: false,
        }
    }

    /// Build a `WorkingPool` directly from a pre-constructed
    /// `HashMap<Txid, WorkingTx>`. Runs the same setup pipeline as
    /// `from_entries` (children → topo order → build_relatives) but
    /// skips the `MempoolEntry` conversion and the initial pq seeding
    /// (tests call `chain_for`/`include` directly, not `pop_best`).
    fn pool_from_txs(txs: HashMap<Txid, WorkingTx>) -> WorkingPool {
        let mut pool = WorkingPool {
            txs,
            topo_rank: HashMap::new(),
            order_of: HashMap::new(),
            pq: PriorityQueue::new(),
            overflow: Vec::new(),
        };
        pool.populate_children();
        let topo = pool.topological_order();
        pool.topo_rank = topo
            .iter()
            .enumerate()
            .map(|(i, t)| (*t, i as u32))
            .collect();
        pool.build_relatives(&topo);
        pool
    }

    /// `pos_of(c, &chain)` returns the index of `c` in `chain`, or panics.
    /// Used to express "A appears before B" succinctly in assertions.
    fn pos_of(t: Txid, chain: &[Txid]) -> usize {
        chain
            .iter()
            .position(|x| *x == t)
            .unwrap_or_else(|| panic!("missing {t} in chain"))
    }

    #[test]
    fn chain_for_linear() {
        // root ← A ← B ← C
        let root = txid(1);
        let a = txid(2);
        let b = txid(3);
        let c = txid(4);
        let mut txs = HashMap::new();
        txs.insert(root, leaf(vec![]));
        txs.insert(a, leaf(vec![root]));
        txs.insert(b, leaf(vec![a]));
        txs.insert(c, leaf(vec![b]));
        let pool = pool_from_txs(txs);

        assert_eq!(pool.chain_for(Chosen::for_testing(c)), vec![root, a, b, c]);
    }

    #[test]
    fn chain_for_diamond() {
        // root ← {A, B} ← C: both A and B depend on root; C depends on both.
        // Regression guard for the pre-order-plus-reverse bug that emitted
        // [A, root, B, C] — violating the parents-before-children invariant.
        let root = txid(1);
        let a = txid(2);
        let b = txid(3);
        let c = txid(4);
        let mut txs = HashMap::new();
        txs.insert(root, leaf(vec![]));
        txs.insert(a, leaf(vec![root]));
        txs.insert(b, leaf(vec![root]));
        txs.insert(c, leaf(vec![a, b]));
        let pool = pool_from_txs(txs);

        let chain = pool.chain_for(Chosen::for_testing(c));
        assert_eq!(chain.len(), 4);
        // Every edge: parent must precede child in the chain.
        assert!(pos_of(root, &chain) < pos_of(a, &chain));
        assert!(pos_of(root, &chain) < pos_of(b, &chain));
        assert!(pos_of(a, &chain) < pos_of(c, &chain));
        assert!(pos_of(b, &chain) < pos_of(c, &chain));
    }

    #[test]
    fn chain_for_excludes_used_ancestors() {
        // root ← A ← C. After `include([root])` runs, `root` should no
        // longer appear in C's chain (it's used and has been stripped
        // from C's `ancestors` by the combined rescore pass).
        let root = txid(1);
        let a = txid(2);
        let c = txid(3);
        let mut txs = HashMap::new();
        txs.insert(root, leaf(vec![]));
        txs.insert(a, leaf(vec![root]));
        txs.insert(c, leaf(vec![a]));
        let mut pool = pool_from_txs(txs);

        let mut block = ProjectedBlock::default();
        pool.include(&[root], 1, &mut block);

        assert_eq!(pool.chain_for(Chosen::for_testing(c)), vec![a, c]);
    }

    // --- Load-bearing invariant tests: these pin down the properties
    //     the rest of the algorithm relies on (`forget_ancestor`
    //     propagation, pq hygiene, topo-sort correctness). If someone
    //     modifies `include` or `forget_ancestor` without preserving
    //     these, these tests should fail before the rest of the suite
    //     goes sideways. ---

    #[test]
    fn invariant_include_strips_chain_members_from_all_descendant_ancestors() {
        // root ← A ← {B, C}. Including [root, A] must leave neither B
        // nor C with `root` or `a` in their ancestors sets.
        let root = txid(1);
        let a = txid(2);
        let b = txid(3);
        let c = txid(4);
        let mut txs = HashMap::new();
        txs.insert(root, leaf(vec![]));
        txs.insert(a, leaf(vec![root]));
        txs.insert(b, leaf(vec![a]));
        txs.insert(c, leaf(vec![a]));
        let mut pool = pool_from_txs(txs);

        let mut block = ProjectedBlock::default();
        pool.include(&[root, a], 1, &mut block);

        for child in [b, c] {
            let ancs = &pool.txs.get(&child).unwrap().ancestors;
            assert!(!ancs.contains(&root), "{child}.ancestors still has root");
            assert!(!ancs.contains(&a), "{child}.ancestors still has a");
        }
    }

    #[test]
    fn invariant_include_removes_chain_members_from_pq() {
        // Seed the pq directly, run include, confirm chain members are
        // gone from the pq. Relied on by `pop_best`'s "front of the
        // queue is always live" contract.
        let root = txid(1);
        let a = txid(2);
        let other = txid(3);
        let mut txs = HashMap::new();
        txs.insert(root, leaf(vec![]));
        txs.insert(a, leaf(vec![root]));
        txs.insert(other, leaf(vec![]));
        let mut pool = pool_from_txs(txs);

        let prio = |t: Txid| Priority {
            score: 1.0,
            order: 0,
            txid_lex: t,
        };
        pool.pq.push(root, prio(root));
        pool.pq.push(a, prio(a));
        pool.pq.push(other, prio(other));

        let mut block = ProjectedBlock::default();
        pool.include(&[root, a], 1, &mut block);

        assert!(pool.pq.get_priority(&root).is_none());
        assert!(pool.pq.get_priority(&a).is_none());
        assert!(
            pool.pq.get_priority(&other).is_some(),
            "non-chain tx should not be affected"
        );
    }

    #[test]
    fn invariant_forget_ancestor_propagates_through_multi_level_chain() {
        // root ← A ← B ← C. After including just `root`, A/B/C must
        // all have root removed from their ancestors. The combined
        // rescore pass must walk all the way down, not just one level.
        let root = txid(1);
        let a = txid(2);
        let b = txid(3);
        let c = txid(4);
        let mut txs = HashMap::new();
        txs.insert(root, leaf(vec![]));
        txs.insert(a, leaf(vec![root]));
        txs.insert(b, leaf(vec![a]));
        txs.insert(c, leaf(vec![b]));
        let mut pool = pool_from_txs(txs);

        let mut block = ProjectedBlock::default();
        pool.include(&[root], 1, &mut block);

        for descendant in [a, b, c] {
            assert!(
                !pool.txs.get(&descendant).unwrap().ancestors.contains(&root),
                "root still in {descendant}.ancestors"
            );
        }
    }

    #[test]
    fn invariant_chain_for_is_valid_topological_order() {
        // Generalization of `chain_for_diamond`: for an arbitrary
        // (diamond + linear mix) DAG, every returned txid's parents
        // that also appear in the chain must appear before it.
        let root = txid(1);
        let a = txid(2);
        let b = txid(3);
        let c = txid(4);
        let d = txid(5);
        let e = txid(6);
        let mut txs = HashMap::new();
        txs.insert(root, leaf(vec![]));
        txs.insert(a, leaf(vec![root]));
        txs.insert(b, leaf(vec![root]));
        txs.insert(c, leaf(vec![a, b]));
        txs.insert(d, leaf(vec![c]));
        txs.insert(e, leaf(vec![c, d]));
        let pool = pool_from_txs(txs);

        let chain = pool.chain_for(Chosen::for_testing(e));
        let positions: HashMap<Txid, usize> =
            chain.iter().enumerate().map(|(i, t)| (*t, i)).collect();
        for tx in &chain {
            for parent in &pool.txs.get(tx).unwrap().parents {
                if let Some(&parent_pos) = positions.get(parent) {
                    let tx_pos = positions[tx];
                    assert!(
                        parent_pos < tx_pos,
                        "{parent} (pos {parent_pos}) should precede {tx} (pos {tx_pos})"
                    );
                }
            }
        }
    }
}
