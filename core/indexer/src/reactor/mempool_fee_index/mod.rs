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

mod block_projection;

use std::collections::HashMap;

use bitcoin::Txid;
use indexer_types::Fees;
use tokio::sync::watch;

use crate::bitcoin_client::types::MempoolEntry;

/// One Bitcoin block's worth of vsize (weight 4 000 000 / 4).
pub(super) const BLOCK_VSIZE: u64 = 1_000_000;

/// Thresholds used by `optimize_median_fee` to decide when a projected
/// block is "full enough" to trust its median as a recommendation.
const FULL_BLOCK_VSIZE: u64 = 950_000;
const HALF_BLOCK_VSIZE: u64 = 500_000;

pub struct MempoolFeeIndex {
    entries: HashMap<Txid, MempoolEntry>,
    /// Bitcoin's dynamic mempool purge floor, in sat/vB. Any estimate
    /// below this would be rejected by `sendrawtransaction` anyway, so
    /// `optimize_median_fee` floors at this value for coherence with
    /// Bitcoin Core. Updated together with `entries` via `replace`.
    mempool_min_fee_sat_per_vb: u64,
    /// Set by every mutating call; cleared by `recompute()`. Gates the
    /// reactor's periodic publish so we skip work when nothing has
    /// changed.
    dirty: bool,
    /// Most recent fee tier snapshot — written by `recompute()`, read by
    /// consensus (`compute_fee_threshold`) and the API. Initial /
    /// post-`replace` value is `Fees::floor(min_fee)` so readers never
    /// see a value below the current floor.
    fees: Fees,
    /// Optional sink for the fee snapshot. When set, every `recompute()`
    /// publishes the new value here in addition to caching it locally.
    /// Owning the sender on the index means the API watch-channel
    /// always sees the same projection consensus does, with no need
    /// for the caller to remember to publish after each compute.
    fee_tx: Option<watch::Sender<Fees>>,
}

impl MempoolFeeIndex {
    pub fn new(fee_tx: Option<watch::Sender<Fees>>) -> Self {
        Self {
            entries: HashMap::new(),
            mempool_min_fee_sat_per_vb: 1,
            dirty: false,
            fees: Fees::floor(1),
            fee_tx,
        }
    }

    pub fn insert(&mut self, txid: Txid, entry: MempoolEntry) {
        self.entries.insert(txid, entry);
        self.dirty = true;
    }

    pub fn remove(&mut self, txid: &Txid) {
        if self.entries.remove(txid).is_some() {
            self.dirty = true;
        }
    }

    /// Atomic full-snapshot replacement, paired with the dynamic
    /// mempool minimum fee from the same `getmempoolinfo` snapshot.
    /// Always called together (from the listener's `MempoolEvent::Sync`
    /// handler) so collapsing them removes a class of "min_fee got out
    /// of sync with entries" bugs. Resets cached `fees` to the new
    /// floor; the next tick recomputes real values.
    pub fn replace(&mut self, entries: HashMap<Txid, MempoolEntry>, min_fee_sat_per_vb: u64) {
        let new_min = min_fee_sat_per_vb.max(1);
        self.entries = entries;
        self.mempool_min_fee_sat_per_vb = new_min;
        self.fees = Fees::floor(new_min);
        self.dirty = true;
    }

    /// Returns whether the index has been mutated since the last call,
    /// then clears the flag. Use from a periodic publisher to skip the
    /// recompute when nothing has changed.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
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

    /// Most recent fee tier snapshot. **Does not trigger a recompute** —
    /// the reactor's tick is the only producer.
    pub fn fees(&self) -> Fees {
        self.fees
    }

    pub fn fastest_fee(&self) -> u64 {
        self.fees.fastest
    }

    pub fn half_hour_fee(&self) -> u64 {
        self.fees.half_hour
    }

    pub fn hour_fee(&self) -> u64 {
        self.fees.hour
    }

    /// Recompute all three fee tiers from the current `entries`, cache
    /// them in `fees`, publish via `fee_tx` if set, and return the new
    /// snapshot. Always clears `dirty` — the next periodic tick will
    /// skip until a new mutation arrives.
    pub fn recompute(&mut self) -> Fees {
        let blocks = block_projection::project_blocks(&self.entries, 4);
        let min = self.mempool_min_fee_sat_per_vb;
        let fastest = optimize_median_fee(blocks.first(), blocks.get(1), None, min);
        let half_hour = optimize_median_fee(blocks.get(1), blocks.get(2), Some(fastest), min);
        let hour = optimize_median_fee(blocks.get(2), blocks.get(3), Some(half_hour), min);
        self.fees = Fees {
            fastest,
            half_hour,
            hour,
        };
        self.dirty = false;
        if let Some(tx) = &self.fee_tx {
            // Errors only when all receivers are dropped — fine, the
            // reactor keeps running.
            let _ = tx.send(self.fees);
        }
        self.fees
    }

    /// Run the block projection bypassing the cached `fees`. Exposed for
    /// tests that want to inspect the raw projection structure.
    #[cfg(test)]
    fn project_blocks(&self, n_blocks: usize) -> Vec<ProjectedBlock> {
        block_projection::project_blocks(&self.entries, n_blocks)
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
        let mut idx = MempoolFeeIndex::new(None);
        idx.replace(HashMap::new(), 5);
        assert_eq!(idx.fastest_fee(), 5);
    }

    #[test]
    fn half_empty_block_returns_min_fee() {
        let mut idx = MempoolFeeIndex::new(None);
        idx.replace(HashMap::new(), 3);
        // 100 txs of ~1000 vB each = 100k vB total (far below HALF_BLOCK).
        for n in 0..100u8 {
            idx.insert(txid(n), entry(10_000 /* 10 sat/vB × 1000 */, 1_000, vec![]));
        }
        assert_eq!(idx.fastest_fee(), 3);
    }

    #[test]
    fn full_block_returns_median() {
        let mut idx = MempoolFeeIndex::new(None);
        // 2000 txs × 1000 vB = 2M vB → fills block 0 exactly with 1000 of them.
        // Use increasing fee rates so median is well-defined.
        for n in 0..200u8 {
            // fee = n+1 sat/vB, vsize 5000 → total 1M vB across 200 txs.
            let rate = (n as u64) + 1;
            idx.insert(txid(n), entry(rate * 5000, 5000, vec![]));
        }
        let fastest = idx.recompute().fastest;
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
        let mut idx = MempoolFeeIndex::new(None);
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
        let mut idx = MempoolFeeIndex::new(None);
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
        let mut idx = MempoolFeeIndex::new(None);
        let id = txid(42);
        idx.insert(id, entry(1000, 100, vec![]));
        assert_eq!(idx.len(), 1);
        idx.remove(&id);
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn dirty_flag_tracks_mutations() {
        // The reactor's periodic publish gates on `take_dirty()` —
        // every mutation must mark the index dirty so the next tick
        // picks up the change.
        let mut idx = MempoolFeeIndex::new(None);
        assert!(!idx.take_dirty(), "fresh index is clean");
        assert!(!idx.take_dirty(), "take_dirty clears the flag");

        // insert always dirties.
        let id = txid(1);
        idx.insert(id, entry(100, 100, vec![]));
        assert!(idx.take_dirty(), "insert must dirty");

        // remove of a present entry dirties.
        idx.remove(&id);
        assert!(idx.take_dirty(), "remove of present entry must dirty");

        // remove of a missing entry is a no-op.
        idx.remove(&txid(99));
        assert!(
            !idx.take_dirty(),
            "remove of missing entry should not dirty"
        );

        // replace always dirties.
        idx.replace(HashMap::new(), 5);
        assert!(idx.take_dirty(), "replace must dirty");
    }

    #[test]
    fn replace_wipes_previous_state() {
        let mut idx = MempoolFeeIndex::new(None);
        idx.insert(txid(1), entry(100, 100, vec![]));
        idx.insert(txid(2), entry(200, 100, vec![]));
        assert_eq!(idx.len(), 2);

        let mut replacement = HashMap::new();
        replacement.insert(txid(3), entry(300, 100, vec![]));
        idx.replace(replacement, 5);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.min_fee(), 5);
        // `replace` resets the cached fee tiers to the new floor.
        assert_eq!(idx.fees().fastest, 5);
        assert_eq!(idx.fees().half_hour, 5);
        assert_eq!(idx.fees().hour, 5);
    }

    #[test]
    fn cpfp_parent_attributed_at_package_rate() {
        // Regression: bugbot caught us reporting CPFP parents at their
        // own (low) individual rate, dragging the median down. A 600k vB
        // parent at 1 sat/vB pulled in by a tiny high-fee child should
        // contribute the *package* rate to the median, otherwise the
        // parent dominates the block's vsize and median_fee_rate()
        // returns 1 sat/vB — wrong.
        let mut idx = MempoolFeeIndex::new(None);
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
        let mut idx = MempoolFeeIndex::new(None);
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
        // After the gbt port: when B's package overflows block 0, the
        // algorithm fills the remaining space with smaller candidates
        // (matches Bitcoin Core's BlockAssembler). B's parent (vsize
        // 400k, fee rate 1) fits in the 700k slot left after A's
        // package. Block 0 ends at A_p (100k) + A_c (200k) + B_p (400k)
        // = 700k. B_c lands alone in block 1 at its true rate (since
        // B_p is now "confirmed" in block 0 and removed from B_c's
        // ancestor accounting).
        assert_eq!(
            blocks[0].vsize, 700_000,
            "block 0 fills A's package + B's parent"
        );
        assert_eq!(
            blocks[1].vsize, 400_000,
            "block 1 holds just B's child (parent already in block 0)"
        );
    }

    #[test]
    fn partial_block_scales_recommendation_down() {
        // Block 0 fills to ~700k vB (between 500k and 950k) with median
        // around 50 sat/vB. With no next block, the scaling branch should
        // multiply by (700k - 500k) / 500k = 0.4, giving ~20 sat/vB.
        let mut idx = MempoolFeeIndex::new(None);
        // 70 entries × 10k vB at 50 sat/vB.
        for n in 0..70u8 {
            idx.insert(txid(n), entry(50 * 10_000, 10_000, vec![]));
        }
        let fastest = idx.recompute().fastest;
        // Scaled: 50 × (700_000 - 500_000) / 500_000 = 50 × 0.4 = 20.
        // Allow a few sat/vB of slack for integer arithmetic.
        assert!(
            (15..=25).contains(&fastest),
            "expected scaling to ~20 sat/vB, got {fastest}"
        );
    }

    #[test]
    fn descendant_rescored_after_sibling_package_includes_parent() {
        // Two children sharing a parent. One child carries a much
        // larger CPFP bump than the other.
        //
        //   P (1 sat/vB, 200k vB)
        //   ├── A (high CPFP, package rate ~75 sat/vB)
        //   └── B (smaller CPFP, package rate ~10 sat/vB)
        //
        // Greedy algo pops A first (highest score), includes {P, A} as
        // a package at A's score (~75 sat/vB). After that inclusion B
        // shouldn't still claim its old package rate of ~10 sat/vB —
        // P is now in the block, so B's effective rate is just B's own
        // self_rate (50 sat/vB), which is much higher than its old
        // package rate. The gbt algorithm re-scores B via the modified
        // queue and includes it at the higher rate.
        //
        // The previous algorithm (no descendant rescoring) would
        // include B at its stale package rate of 10 sat/vB.
        let mut idx = MempoolFeeIndex::new(None);
        let p = txid(1);
        let a = txid(2);
        let b = txid(3);

        // P: 200k sats fee, 200k vB → 1 sat/vB
        idx.insert(
            p,
            entry_with_package(200_000, 200_000, 200_000, 200_000, vec![]),
        );
        // A: large fee child of P. ancestor_fee = 200k + 7.3M = 7.5M,
        // ancestor_vsize = 200k + 100k = 300k → ~25 sat/vB package.
        idx.insert(
            a,
            entry_with_package(7_300_000, 100_000, 7_500_000, 300_000, vec![p]),
        );
        // B: 50 sat/vB self. fee 5M / vsize 100k = 50. With P as
        // ancestor: package_fee 5.2M / package_vsize 300k ≈ 17 sat/vB.
        idx.insert(
            b,
            entry_with_package(5_000_000, 100_000, 5_200_000, 300_000, vec![p]),
        );

        let blocks = idx.project_blocks(1);
        assert_eq!(blocks.len(), 1);
        // {P, A, B} all in block 0 (combined 400k vB, fits).
        assert_eq!(blocks[0].entries.len(), 3);
        // B was included LAST (after A's package took P). B's recorded
        // rate must be its rescored rate (close to its self_rate of 50),
        // not the stale ~17 sat/vB package rate it had when it still
        // counted P as an ancestor.
        let (b_rate, b_vsize) = *blocks[0].entries.last().expect("non-empty block");
        assert_eq!(b_vsize, 100_000, "B is the last-included entry");
        assert!(
            b_rate >= 40,
            "rescored B should report ≥40 sat/vB, got {b_rate}"
        );
    }

    #[test]
    fn half_hour_fee_smooths_against_fastest() {
        // Build a mempool that fills 3 full blocks (2 we examine + 1
        // following so the scaling branch doesn't fire on block 1).
        // Block 0 ~200 sat/vB, block 1 ~60 sat/vB, block 2 ~30 sat/vB.
        // halfHourFee = (block1.median + fastest_fee) / 2 ≈ (60 + 200) / 2.
        let mut idx = MempoolFeeIndex::new(None);

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

        let fastest = idx.recompute().fastest;
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
