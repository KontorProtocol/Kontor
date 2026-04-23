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
use std::collections::{HashMap, HashSet};

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
    /// Marked once this tx lands in some projected block.
    used: bool,
    /// Marked once this tx's score has been modified after the initial
    /// sort — tells the main loop to look at the modified-queue value
    /// rather than the (now stale) stack value.
    requeued: bool,
    relatives_built: bool,
}

impl WorkingTx {
    fn from_entry(_txid: Txid, entry: &MempoolEntry) -> Self {
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
            requeued: false,
            relatives_built: false,
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
pub fn project_blocks(
    entries: &HashMap<Txid, MempoolEntry>,
    n_blocks: usize,
) -> Vec<ProjectedBlock> {
    if n_blocks == 0 || entries.is_empty() {
        return vec![];
    }

    // 1. Build working state for every entry.
    let mut pool: HashMap<Txid, WorkingTx> = entries
        .iter()
        .map(|(txid, e)| (*txid, WorkingTx::from_entry(*txid, e)))
        .collect();

    // 2. Walk the depends graph to populate `ancestors` (transitive),
    //    `children` (inverse of depends), and the package-aggregate
    //    fields. Done in two passes: first build the ancestor sets,
    //    then push self into each ancestor's children set.
    let txids: Vec<Txid> = pool.keys().copied().collect();
    for txid in &txids {
        build_relatives(*txid, &mut pool);
    }
    populate_children(&mut pool);

    // 3. Initial deterministic ordering: by score DESC, then a stable
    //    tie-break (we use lexicographic txid). Assign each tx an
    //    `order` for use in the priority queue tie-breaker.
    let mut initial: Vec<(Txid, f64)> = pool.iter().map(|(txid, w)| (*txid, w.score())).collect();
    initial.sort_by(
        |a, b| match b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal) {
            Ordering::Equal => a.0.cmp(&b.0),
            ord => ord,
        },
    );
    let order_of: HashMap<Txid, u32> = initial
        .iter()
        .enumerate()
        .map(|(i, (t, _))| (*t, i as u32))
        .collect();
    // Stack: candidates we'll consume in order. Reverse so cheap pop
    // gives the highest-scoring tx.
    let mut stack: Vec<Txid> = initial.into_iter().map(|(t, _)| t).rev().collect();

    // 4. Run the greedy block-packing loop.
    let mut requeued: PriorityQueue<Txid, Priority> = PriorityQueue::new();
    let mut blocks: Vec<ProjectedBlock> = vec![ProjectedBlock::default()];
    let mut overflow: Vec<Txid> = Vec::new();
    let mut failures: u32 = 0;

    loop {
        let from_stack = peek_unused_stack(&mut stack, &pool);
        let from_queue = peek_unused_queue(&mut requeued, &pool);

        if from_stack.is_none() && from_queue.is_none() {
            break;
        }
        // Pick the higher-priority of the two heads.
        let (chosen, took_from_stack) = match (from_stack, from_queue) {
            (Some(s), Some(q)) => {
                let s_prio = priority_for(s, &pool, &order_of);
                let q_prio = priority_for(q, &pool, &order_of);
                if s_prio >= q_prio {
                    (s, true)
                } else {
                    (q, false)
                }
            }
            (Some(s), None) => (s, true),
            (None, Some(q)) => (q, false),
            (None, None) => unreachable!(),
        };
        if took_from_stack {
            stack.pop();
        } else {
            requeued.pop();
        }

        // Walk the chosen tx's ancestor chain to compute total package
        // vsize. Topologically order so parents come before children
        // when we write to the block.
        let chain = topological_ancestor_chain(chosen, &pool);
        let chain_vsize: u64 = chain
            .iter()
            .map(|t| pool.get(t).map(|w| w.self_vsize).unwrap_or(0))
            .sum();

        let final_block = blocks.len() == n_blocks;
        let cur_vsize = blocks.last().map(|b| b.vsize).unwrap_or(0);
        let fits = cur_vsize + chain_vsize <= BLOCK_VSIZE;

        if !fits && !final_block {
            // Doesn't fit in this block — set aside and try smaller.
            overflow.push(chosen);
            failures += 1;
        } else if !fits && final_block {
            // No more blocks to spill into; we're done.
            break;
        } else {
            // Include the package. The cluster_rate is the originating
            // tx's score — the rate at which the miner would accept the
            // bundle (bottlenecked by the worst sub-rate in the chain).
            let cluster_rate_f = pool.get(&chosen).map(WorkingTx::score).unwrap_or(0.0);
            let cluster_rate = cluster_rate_f.max(0.0).floor() as u64;

            for member in &chain {
                let (member_fee, member_vsize) = match pool.get_mut(member) {
                    Some(w) => {
                        w.used = true;
                        let block = blocks.last_mut().expect("at least one block");
                        block.entries.push((cluster_rate, w.self_vsize));
                        block.vsize += w.self_vsize;
                        (w.self_fee, w.self_vsize)
                    }
                    None => continue,
                };
                rescore_descendants(
                    *member,
                    member_fee,
                    member_vsize,
                    &mut pool,
                    &mut requeued,
                    &order_of,
                );
            }
            failures = 0;
        }

        // Decide whether the current block is "done" — either we've hit
        // the failure threshold near full capacity, or no more candidates
        // exist. When a block finalizes, drain overflow back into the
        // candidate pool for the next block.
        let finalize_now = {
            let cur = blocks.last().expect("at least one block");
            (failures > FAILURES_BEFORE_BLOCK_FINALIZE
                && cur.vsize > BLOCK_VSIZE.saturating_sub(8_000))
                || (stack.is_empty() && requeued.is_empty())
        };
        if finalize_now {
            if blocks.len() < n_blocks
                && !blocks
                    .last()
                    .expect("at least one block")
                    .entries
                    .is_empty()
            {
                blocks.push(ProjectedBlock::default());
                failures = 0;
                drain_overflow_back(&mut overflow, &mut stack, &mut requeued, &pool, &order_of);
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

/// Recursively populate `ancestors`, `pkg_fee`, `pkg_vsize`. Idempotent
/// via the `relatives_built` flag.
fn build_relatives(txid: Txid, pool: &mut HashMap<Txid, WorkingTx>) {
    let parents = match pool.get(&txid) {
        Some(w) if !w.relatives_built => w.parents.clone(),
        _ => return,
    };
    for parent in &parents {
        build_relatives(*parent, pool);
    }
    let mut accumulated: HashSet<Txid> = HashSet::new();
    let mut anc_fee: u64 = 0;
    let mut anc_vsize: u64 = 0;
    for parent in &parents {
        if let Some(p) = pool.get(parent) {
            if accumulated.insert(*parent) {
                anc_fee = anc_fee.saturating_add(p.self_fee);
                anc_vsize = anc_vsize.saturating_add(p.self_vsize);
            }
            for grand in &p.ancestors {
                if !accumulated.contains(grand)
                    && let Some(g) = pool.get(grand)
                {
                    accumulated.insert(*grand);
                    anc_fee = anc_fee.saturating_add(g.self_fee);
                    anc_vsize = anc_vsize.saturating_add(g.self_vsize);
                }
            }
        }
    }
    if let Some(w) = pool.get_mut(&txid) {
        w.ancestors = accumulated;
        w.pkg_fee = w.self_fee.saturating_add(anc_fee);
        w.pkg_vsize = w.self_vsize.saturating_add(anc_vsize);
        w.relatives_built = true;
    }
}

/// Inverse of `parents`: for every tx, register self as a child of each
/// of its parents. Done after `build_relatives` so the ancestor sets are
/// stable.
fn populate_children(pool: &mut HashMap<Txid, WorkingTx>) {
    let edges: Vec<(Txid, Txid)> = pool
        .iter()
        .flat_map(|(txid, w)| w.parents.iter().map(move |p| (*p, *txid)))
        .collect();
    for (parent, child) in edges {
        if let Some(p) = pool.get_mut(&parent) {
            p.children.insert(child);
        }
    }
}

/// Topological ancestor chain ending in `root`: every entry is unincluded
/// and appears after all of its ancestors that also appear. Built
/// breadth-first up the parent edges, then post-order-flattened so the
/// deepest roots come first.
fn topological_ancestor_chain(root: Txid, pool: &HashMap<Txid, WorkingTx>) -> Vec<Txid> {
    let mut chain: Vec<Txid> = Vec::new();
    let mut seen: HashSet<Txid> = HashSet::new();
    let mut stack: Vec<Txid> = vec![root];
    while let Some(top) = stack.pop() {
        if seen.contains(&top) {
            continue;
        }
        if let Some(w) = pool.get(&top) {
            if w.used {
                continue;
            }
            for parent in &w.parents {
                if !seen.contains(parent) && pool.get(parent).is_some_and(|p| !p.used) {
                    stack.push(*parent);
                }
            }
        }
        seen.insert(top);
        chain.push(top);
    }
    chain.reverse();
    chain
}

/// Walk children of `root_txid`, removing root from each child's
/// ancestor accounting, recomputing scores, and updating the requeued
/// priority queue.
fn rescore_descendants(
    root_txid: Txid,
    root_fee: u64,
    root_vsize: u64,
    pool: &mut HashMap<Txid, WorkingTx>,
    requeued: &mut PriorityQueue<Txid, Priority>,
    order_of: &HashMap<Txid, u32>,
) {
    let mut visited: HashSet<Txid> = HashSet::new();
    let direct: Vec<Txid> = pool
        .get(&root_txid)
        .map(|w| w.children.iter().copied().collect())
        .unwrap_or_default();
    let mut frontier: Vec<Txid> = direct;
    while let Some(child_id) = frontier.pop() {
        if !visited.insert(child_id) {
            continue;
        }
        let (changed, new_score, more_children) = {
            let Some(child) = pool.get_mut(&child_id) else {
                continue;
            };
            if child.used {
                continue;
            }
            let prior = child.forget_ancestor(root_txid, root_fee, root_vsize);
            let new = child.score();
            let extra: Vec<Txid> = child.children.iter().copied().collect();
            (prior != new, new, extra)
        };
        if changed {
            if let Some(child) = pool.get_mut(&child_id) {
                child.requeued = true;
            }
            let prio = Priority {
                score: new_score,
                order: order_of.get(&child_id).copied().unwrap_or(u32::MAX),
                txid_lex: child_id,
            };
            // PriorityQueue::push handles both increase and decrease;
            // the priority for `child_id` is replaced if it already
            // exists in the queue.
            requeued.push(child_id, prio);
        }
        for c in more_children {
            if !visited.contains(&c) {
                frontier.push(c);
            }
        }
    }
}

fn peek_unused_stack(stack: &mut Vec<Txid>, pool: &HashMap<Txid, WorkingTx>) -> Option<Txid> {
    while let Some(top) = stack.last().copied() {
        match pool.get(&top) {
            Some(w) if !w.used && !w.requeued => return Some(top),
            _ => {
                stack.pop();
            }
        }
    }
    None
}

fn peek_unused_queue(
    queue: &mut PriorityQueue<Txid, Priority>,
    pool: &HashMap<Txid, WorkingTx>,
) -> Option<Txid> {
    while let Some((txid, _)) = queue.peek() {
        let txid = *txid;
        match pool.get(&txid) {
            Some(w) if !w.used => return Some(txid),
            _ => {
                queue.pop();
            }
        }
    }
    None
}

fn priority_for(
    txid: Txid,
    pool: &HashMap<Txid, WorkingTx>,
    order_of: &HashMap<Txid, u32>,
) -> Priority {
    let score = pool.get(&txid).map(WorkingTx::score).unwrap_or(0.0);
    Priority {
        score,
        order: order_of.get(&txid).copied().unwrap_or(u32::MAX),
        txid_lex: txid,
    }
}

fn drain_overflow_back(
    overflow: &mut Vec<Txid>,
    stack: &mut Vec<Txid>,
    requeued: &mut PriorityQueue<Txid, Priority>,
    pool: &HashMap<Txid, WorkingTx>,
    order_of: &HashMap<Txid, u32>,
) {
    overflow.reverse();
    for txid in overflow.drain(..) {
        if let Some(w) = pool.get(&txid) {
            if w.requeued {
                requeued.push(txid, priority_for(txid, pool, order_of));
            } else {
                stack.push(txid);
            }
        }
    }
}
