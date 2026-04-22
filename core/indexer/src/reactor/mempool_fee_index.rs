//! Local mempool fee index, used by `validate_transaction` to reject
//! Kontor transactions whose fee rate is too low to likely confirm within
//! our 6-block window.
//!
//! Per-validator state. BFT tolerates small variance across validators.
//!
//! The threshold is `fastest_fee()`: the median package fee rate of
//! projected block 0, with `optimize_median_fee` tweaks ported from
//! mempool.space (`fee-api.ts:91-101`). Uses Bitcoin Core's pre-computed
//! `ancestor_fees / ancestor_size` per tx rather than re-running
//! BlockAssembler from scratch.

use std::collections::{HashMap, HashSet};

use bitcoin::Txid;

use crate::bitcoin_client::types::MempoolEntry;

/// Package fee rate in sat/vB for a mempool entry. Miners order
/// transactions by this value. `ancestor` fees/size includes this tx and
/// all its in-mempool ancestors.
fn package_fee_rate(entry: &MempoolEntry) -> u64 {
    entry
        .fees
        .ancestor
        .to_sat()
        .checked_div(entry.ancestorsize)
        .unwrap_or(0)
}

/// One Bitcoin block's worth of vsize (weight 4 000 000 / 4).
const BLOCK_VSIZE: u64 = 1_000_000;

/// Thresholds used by `optimize_median_fee` to decide when a projected
/// block is "full enough" to trust its median as a recommendation.
const FULL_BLOCK_VSIZE: u64 = 950_000;
const HALF_BLOCK_VSIZE: u64 = 500_000;

pub struct MempoolFeeIndex {
    entries: HashMap<Txid, MempoolEntry>,
    /// Bitcoin's dynamic mempool purge floor, in sat/vB. Any estimate
    /// below this would be rejected by `sendrawtransaction` anyway, so
    /// we floor at this value for coherence with Bitcoin Core.
    mempool_min_fee_sat_per_vb: u64,
}

impl MempoolFeeIndex {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            mempool_min_fee_sat_per_vb: 1,
        }
    }

    pub fn insert(&mut self, txid: Txid, entry: MempoolEntry) {
        self.entries.insert(txid, entry);
    }

    pub fn remove(&mut self, txid: &Txid) {
        self.entries.remove(txid);
    }

    pub fn replace_all(&mut self, entries: HashMap<Txid, MempoolEntry>) {
        self.entries = entries;
    }

    pub fn set_min_fee(&mut self, sat_per_vb: u64) {
        self.mempool_min_fee_sat_per_vb = sat_per_vb.max(1);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn min_fee(&self) -> u64 {
        self.mempool_min_fee_sat_per_vb
    }

    /// "fastestFee" — fee rate to land in the next block (~10 min) with
    /// high confidence. Median package fee rate of projected block 0,
    /// optimized per `fee-api.ts:optimizeMedianFee`. Used by
    /// `validate_transaction`.
    pub fn fastest_fee(&self) -> u64 {
        let blocks = self.project_blocks(4);
        let block0 = blocks.first();
        let block1 = blocks.get(1);
        optimize_median_fee(block0, block1, None, self.mempool_min_fee_sat_per_vb)
    }

    /// "halfHourFee" — fee rate to land in roughly the next 3 blocks.
    /// Median of projected block 1, smoothed against `fastest_fee()`.
    /// Not currently consumed by Kontor consensus, but kept available for
    /// future use (e.g. tiered acceptance, API exposure).
    pub fn half_hour_fee(&self) -> u64 {
        let blocks = self.project_blocks(4);
        let block1 = blocks.get(1);
        let block2 = blocks.get(2);
        let prev = Some(self.fastest_fee());
        optimize_median_fee(block1, block2, prev, self.mempool_min_fee_sat_per_vb)
    }

    /// "hourFee" — fee rate to land in roughly the next 6 blocks.
    /// Median of projected block 2, smoothed against `half_hour_fee()`.
    /// Not currently consumed; provided for parity with mempool.space's
    /// recommendation tiers.
    pub fn hour_fee(&self) -> u64 {
        let blocks = self.project_blocks(4);
        let block2 = blocks.get(2);
        let block3 = blocks.get(3);
        let prev = Some(self.half_hour_fee());
        optimize_median_fee(block2, block3, prev, self.mempool_min_fee_sat_per_vb)
    }

    /// Project the next `n_blocks` via a CPFP-aware greedy sweep over
    /// mempool entries ordered by package fee rate. Each block is a
    /// list of `(fee_rate_sat_per_vb, vsize)` in the order they'd be
    /// included by a miner.
    fn project_blocks(&self, n_blocks: usize) -> Vec<ProjectedBlock> {
        if n_blocks == 0 || self.entries.is_empty() {
            return vec![];
        }

        // Sort all entries by package fee rate DESC. Tie-break by txid for
        // determinism (so two validators with the same mempool produce the
        // same ordering).
        let mut sorted: Vec<(&Txid, &MempoolEntry)> = self.entries.iter().collect();
        sorted.sort_by(|(a_id, a), (b_id, b)| {
            package_fee_rate(b)
                .cmp(&package_fee_rate(a))
                .then_with(|| a_id.cmp(b_id))
        });

        let mut blocks: Vec<ProjectedBlock> = vec![ProjectedBlock::default()];
        let mut included: HashSet<Txid> = HashSet::new();

        for (txid, info) in &sorted {
            let txid = **txid;
            if included.contains(&txid) {
                continue;
            }
            // Rate at which this whole package gets included by a miner.
            // All ancestors pulled in by this tx are reported at this rate
            // — a low-fee parent included via CPFP "costs" the package
            // rate, not its own individual rate, from the median's POV.
            let originating_rate = package_fee_rate(info);
            // Walk ancestors transitively (depth-first). Collect those
            // not yet included so we can add them before the tx itself.
            let mut ancestor_chain: Vec<Txid> = Vec::new();
            let mut stack: Vec<Txid> = vec![txid];
            while let Some(top) = stack.pop() {
                if included.contains(&top) || ancestor_chain.contains(&top) {
                    continue;
                }
                if let Some(top_info) = self.entries.get(&top) {
                    for parent in &top_info.depends {
                        if !included.contains(parent) && !ancestor_chain.contains(parent) {
                            stack.push(*parent);
                        }
                    }
                }
                ancestor_chain.push(top);
            }
            // Reverse so we include the root ancestors first.
            ancestor_chain.reverse();

            // Treat the ancestor chain as an atomic unit — a low-fee
            // parent must never land in a block without its bumping
            // child, otherwise a real miner wouldn't include it.
            let chain_vsize: u64 = ancestor_chain
                .iter()
                .filter_map(|a| self.entries.get(a).map(|e| e.vsize))
                .sum();

            // Spill the entire package to the next block if it doesn't fit.
            while blocks
                .last()
                .is_some_and(|b| b.vsize + chain_vsize > BLOCK_VSIZE)
                && blocks.len() < n_blocks
            {
                blocks.push(ProjectedBlock::default());
            }
            if blocks
                .last()
                .is_some_and(|b| b.vsize + chain_vsize > BLOCK_VSIZE)
            {
                // No more blocks to spill into. Stop.
                return blocks;
            }

            for anc in ancestor_chain {
                let Some(anc_entry) = self.entries.get(&anc) else {
                    continue;
                };
                let vsize = anc_entry.vsize;
                let block = blocks.last_mut().unwrap();
                block.entries.push((originating_rate, vsize));
                block.vsize += vsize;
                included.insert(anc);
            }
        }

        blocks
    }
}

impl Default for MempoolFeeIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default, Debug)]
pub struct ProjectedBlock {
    /// (fee_rate_sat_per_vb, vsize) in inclusion order.
    pub entries: Vec<(u64, u64)>,
    pub vsize: u64,
}

impl ProjectedBlock {
    /// Median of per-byte fee rates, weighted by vsize so the result is
    /// "the fee rate of the byte at the block's vsize midpoint." Matches
    /// mempool.space's `medianFee` computation.
    pub fn median_fee_rate(&self) -> u64 {
        if self.vsize == 0 {
            return 0;
        }
        let half = self.vsize / 2;
        let mut cum: u64 = 0;
        for &(rate, vsz) in &self.entries {
            cum += vsz;
            if cum >= half {
                return rate;
            }
        }
        // Shouldn't happen unless entries is empty.
        self.entries.last().map(|(r, _)| *r).unwrap_or(0)
    }
}

/// Ported from mempool.space's `fee-api.ts:optimizeMedianFee`. Decides the
/// recommended "fastestFee" given a projected block 0 and (optionally) the
/// next block. Handles edge cases where the mempool isn't full enough for
/// the median to be a meaningful signal.
fn optimize_median_fee(
    block: Option<&ProjectedBlock>,
    next_block: Option<&ProjectedBlock>,
    previous_fee: Option<u64>,
    min_fee: u64,
) -> u64 {
    let Some(block) = block else {
        return min_fee;
    };
    let median = block.median_fee_rate();

    // When the block is nearly empty, the median is uninformative — fall
    // back to the mempool-min-fee floor.
    if block.vsize <= HALF_BLOCK_VSIZE || median < min_fee {
        return min_fee;
    }

    let use_fee = if let Some(prev) = previous_fee {
        (median + prev) / 2
    } else {
        median
    };

    // 500k–950k with no next block: scale the median down by fullness —
    // the "block" will actually be partial so miners include lower fees.
    if block.vsize <= FULL_BLOCK_VSIZE && next_block.is_none() {
        // (vsize - 500_000) / 500_000 is 0..1; multiply the fee by that.
        let scaled =
            use_fee.saturating_mul(block.vsize.saturating_sub(HALF_BLOCK_VSIZE)) / HALF_BLOCK_VSIZE;
        return scaled.max(min_fee);
    }

    use_fee.max(min_fee)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin_client::types::MempoolEntryFees;
    use bitcoin::Amount;
    use bitcoin::hashes::Hash;

    fn txid(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    fn entry(fee_sat: u64, vsize: u64, depends: Vec<Txid>) -> MempoolEntry {
        // No ancestors: ancestor_* mirrors individual values.
        MempoolEntry {
            vsize,
            ancestorsize: vsize,
            fees: MempoolEntryFees {
                base: Amount::from_sat(fee_sat),
                ancestor: Amount::from_sat(fee_sat),
            },
            depends,
        }
    }

    /// Build a MempoolEntry where ancestors are provided explicitly (for
    /// CPFP test scenarios). `ancestor_fees_sat` is the sum of fees
    /// including this tx and all ancestors; `ancestor_size` is the sum
    /// of vsizes.
    fn entry_with_package(
        fee_sat: u64,
        vsize: u64,
        ancestor_fees_sat: u64,
        ancestor_size: u64,
        depends: Vec<Txid>,
    ) -> MempoolEntry {
        MempoolEntry {
            vsize,
            ancestorsize: ancestor_size,
            fees: MempoolEntryFees {
                base: Amount::from_sat(fee_sat),
                ancestor: Amount::from_sat(ancestor_fees_sat),
            },
            depends,
        }
    }

    #[test]
    fn empty_mempool_returns_min_fee() {
        let mut idx = MempoolFeeIndex::new();
        idx.set_min_fee(5);
        assert_eq!(idx.fastest_fee(), 5);
    }

    #[test]
    fn half_empty_block_returns_min_fee() {
        let mut idx = MempoolFeeIndex::new();
        idx.set_min_fee(3);
        // 100 txs of ~1000 vB each = 100k vB total (far below HALF_BLOCK).
        for n in 0..100u8 {
            idx.insert(txid(n), entry(10_000 /* 10 sat/vB × 1000 */, 1_000, vec![]));
        }
        assert_eq!(idx.fastest_fee(), 3);
    }

    #[test]
    fn full_block_returns_median() {
        let mut idx = MempoolFeeIndex::new();
        idx.set_min_fee(1);
        // 2000 txs × 1000 vB = 2M vB → fills block 0 exactly with 1000 of them.
        // Use increasing fee rates so median is well-defined.
        for n in 0..200u8 {
            // fee = n+1 sat/vB, vsize 5000 → total 1M vB across 200 txs.
            let rate = (n as u64) + 1;
            idx.insert(txid(n), entry(rate * 5000, 5000, vec![]));
        }
        let fastest = idx.fastest_fee();
        // Median of 1..=200 at vsize midpoint — ~100 sat/vB.
        assert!(
            (90..=110).contains(&fastest),
            "unexpected median: {fastest}"
        );
    }

    #[test]
    fn cpfp_parent_and_child_included_together() {
        // Parent: 1 sat/vB, vsize 500, no deps
        // Child: 200 sat/vB individual, package rate 75.6 (60500 / 800)
        let mut idx = MempoolFeeIndex::new();
        let parent_id = txid(1);
        let child_id = txid(2);

        idx.insert(parent_id, entry(500 /* 500 sats */, 500, vec![]));
        idx.insert(
            child_id,
            entry_with_package(
                60_000,
                300,
                60_500, // 500 parent + 60000 child
                800,    // 500 parent + 300 child
                vec![parent_id],
            ),
        );

        let blocks = idx.project_blocks(1);
        assert_eq!(blocks.len(), 1);
        // Both parent and child should be in block 0.
        assert_eq!(blocks[0].entries.len(), 2);
        assert_eq!(blocks[0].vsize, 800);
    }

    #[test]
    fn grandparent_parent_child_chain() {
        // GP: 1 sat/vB, 400 vB, no deps
        // P: 1 sat/vB, 400 vB, depends on GP
        // C: package rate high (spans all three), 200 vB, depends on P
        let mut idx = MempoolFeeIndex::new();
        let gp = txid(1);
        let p = txid(2);
        let c = txid(3);

        idx.insert(gp, entry_with_package(400, 400, 400, 400, vec![]));
        idx.insert(p, entry_with_package(400, 400, 800, 800, vec![gp]));
        idx.insert(
            c,
            entry_with_package(
                100_000,
                200,     // large child fee
                100_800, // 400 + 400 + 100_000
                1_000,   // 400 + 400 + 200
                vec![p],
            ),
        );

        let blocks = idx.project_blocks(1);
        assert_eq!(blocks.len(), 1);
        // All three should be included — in order gp, p, c.
        assert_eq!(blocks[0].entries.len(), 3);
        assert_eq!(blocks[0].vsize, 1_000);
    }

    #[test]
    fn median_weighted_by_vsize() {
        // Small high-fee tx + large low-fee tx: median by vsize should
        // favor the large tx.
        let block = ProjectedBlock {
            entries: vec![(100, 1_000), (10, 999_000)],
            vsize: 1_000_000,
        };
        // Midpoint is 500_000 vB into the block. First tx is at vsize 1000,
        // second tx takes us to 1_000_000 — so the midpoint falls inside
        // the second tx.
        assert_eq!(block.median_fee_rate(), 10);
    }

    #[test]
    fn insert_and_remove_roundtrip() {
        let mut idx = MempoolFeeIndex::new();
        let id = txid(42);
        idx.insert(id, entry(1000, 100, vec![]));
        assert_eq!(idx.len(), 1);
        idx.remove(&id);
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn replace_all_wipes_previous_state() {
        let mut idx = MempoolFeeIndex::new();
        idx.insert(txid(1), entry(100, 100, vec![]));
        idx.insert(txid(2), entry(200, 100, vec![]));
        assert_eq!(idx.len(), 2);

        let mut replacement = HashMap::new();
        replacement.insert(txid(3), entry(300, 100, vec![]));
        idx.replace_all(replacement);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn cpfp_parent_attributed_at_package_rate() {
        // Regression: bugbot caught us reporting CPFP parents at their
        // own (low) individual rate, dragging the median down. A 600k vB
        // parent at 1 sat/vB pulled in by a tiny high-fee child should
        // contribute the *package* rate to the median, otherwise the
        // parent dominates the block's vsize and median_fee_rate()
        // returns 1 sat/vB — wrong.
        let mut idx = MempoolFeeIndex::new();
        let parent_id = txid(1);
        let child_id = txid(2);

        // Parent: 600k vB, 600k sats fee → 1 sat/vB individual.
        idx.insert(
            parent_id,
            entry_with_package(600_000, 600_000, 600_000, 600_000, vec![]),
        );
        // Child: 100k vB, 3.4M sats → package = (600k + 3.4M) / (600k + 100k)
        // = 4M / 700k ≈ 5.7 sat/vB.
        idx.insert(
            child_id,
            entry_with_package(3_400_000, 100_000, 4_000_000, 700_000, vec![parent_id]),
        );

        let blocks = idx.project_blocks(1);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].vsize, 700_000);

        let median = blocks[0].median_fee_rate();
        assert!(
            (5..=6).contains(&median),
            "expected median ~5 sat/vB (package rate), got {median}"
        );
    }

    #[test]
    fn cpfp_packages_compete_for_block_zero() {
        // Two CPFP packages too big to both fit in block 0 (1M vB). The
        // higher-package-rate one should land in block 0; the other spills
        // to block 1.
        //
        // Package A: parent (1 sat/vB, 100k vB) + child (300 sat/vB, 200k vB)
        //   ancestor_fees = 100_000 + 60_000_000 = 60_100_000
        //   ancestor_size = 100_000 + 200_000 = 300_000
        //   package rate = ~200 sat/vB
        // Package B: parent (1 sat/vB, 400k vB) + child (200 sat/vB, 400k vB)
        //   ancestor_fees = 400_000 + 80_000_000 = 80_400_000
        //   ancestor_size = 400_000 + 400_000 = 800_000
        //   package rate = ~100 sat/vB
        //
        // A (300k vB) + B (800k vB) = 1.1M vB > 1M block capacity. A should
        // be in block 0 alone (300k vB), B should spill to block 1.
        let mut idx = MempoolFeeIndex::new();
        let a_p = txid(1);
        let a_c = txid(2);
        let b_p = txid(3);
        let b_c = txid(4);

        idx.insert(
            a_p,
            entry_with_package(100_000, 100_000, 100_000, 100_000, vec![]),
        );
        idx.insert(
            a_c,
            entry_with_package(60_000_000, 200_000, 60_100_000, 300_000, vec![a_p]),
        );
        idx.insert(
            b_p,
            entry_with_package(400_000, 400_000, 400_000, 400_000, vec![]),
        );
        idx.insert(
            b_c,
            entry_with_package(80_000_000, 400_000, 80_400_000, 800_000, vec![b_p]),
        );

        let blocks = idx.project_blocks(2);
        assert_eq!(blocks.len(), 2, "expected two blocks");
        assert_eq!(blocks[0].vsize, 300_000, "block 0 should hold package A");
        assert_eq!(blocks[1].vsize, 800_000, "block 1 should hold package B");
    }

    #[test]
    fn partial_block_scales_recommendation_down() {
        // Block 0 fills to ~700k vB (between 500k and 950k) with median
        // around 50 sat/vB. With no next block, the scaling branch should
        // multiply by (700k - 500k) / 500k = 0.4, giving ~20 sat/vB.
        let mut idx = MempoolFeeIndex::new();
        idx.set_min_fee(1);
        // 70 entries × 10k vB at 50 sat/vB.
        for n in 0..70u8 {
            idx.insert(txid(n), entry(50 * 10_000, 10_000, vec![]));
        }
        let fastest = idx.fastest_fee();
        // Scaled: 50 × (700_000 - 500_000) / 500_000 = 50 × 0.4 = 20.
        // Allow a few sat/vB of slack for integer arithmetic.
        assert!(
            (15..=25).contains(&fastest),
            "expected scaling to ~20 sat/vB, got {fastest}"
        );
    }

    #[test]
    fn half_hour_fee_smooths_against_fastest() {
        // Build a mempool that fills 3 full blocks (2 we examine + 1
        // following so the scaling branch doesn't fire on block 1).
        // Block 0 ~200 sat/vB, block 1 ~60 sat/vB, block 2 ~30 sat/vB.
        // halfHourFee = (block1.median + fastest_fee) / 2 ≈ (60 + 200) / 2.
        let mut idx = MempoolFeeIndex::new();
        idx.set_min_fee(1);

        // Helper to make a unique txid from two bytes, avoiding the
        // 1-byte txid() collisions used elsewhere.
        let make_id = |a: u8, b: u8| {
            let mut bytes = [0u8; 32];
            bytes[0] = a;
            bytes[1] = b;
            bitcoin::Txid::from_byte_array(bytes)
        };

        // Block 0: 220 entries × 5000 vB = 1.1M vB at fee rates 100..=320.
        for n in 0..220u8 {
            idx.insert(
                make_id(0, n),
                entry((100 + n as u64) * 5_000, 5_000, vec![]),
            );
        }
        // Block 1: 220 entries × 5000 vB at fee rates 50..=70.
        for n in 0..220u8 {
            let rate = 50 + (n as u64) / 11;
            idx.insert(make_id(1, n), entry(rate * 5_000, 5_000, vec![]));
        }
        // Block 2: 220 entries × 5000 vB at fee rates ~30 (so block 1
        // has a non-empty next_block — disables the partial-block scaling).
        for n in 0..220u8 {
            idx.insert(make_id(2, n), entry(30 * 5_000, 5_000, vec![]));
        }

        let fastest = idx.fastest_fee();
        let half_hour = idx.half_hour_fee();
        assert!(
            fastest > half_hour,
            "expected fastest ({fastest}) > halfHour ({half_hour})"
        );
        // Smoothing should pull halfHour above the raw block-1 median (~60).
        assert!(
            half_hour > 60,
            "expected smoothing to lift halfHour above ~60, got {half_hour}"
        );
    }
}
