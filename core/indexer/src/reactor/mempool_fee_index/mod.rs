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
    /// Bitcoin Core. Updated together with `entries` via `sync`.
    mempool_min_fee_sat_per_vb: u64,
    input_revision: u64,
    applied_revision: u64,
    /// A projection may lag ordinary deltas, but never a completed full Sync.
    fees: Fees,
    /// Optional sink for the fee snapshot. When set, every `recompute()`
    /// publishes the new value here in addition to caching it locally.
    /// Owning the sender on the index means the API watch-channel
    /// always sees the same projection consensus does, with no need
    /// for the caller to remember to publish after each compute.
    fee_tx: Option<watch::Sender<Fees>>,
}

pub struct FeeProjectionInput {
    revision: u64,
    entries: HashMap<Txid, MempoolEntry>,
    min_fee: u64,
}

pub struct FeeProjection {
    revision: u64,
    fees: Fees,
}

impl FeeProjectionInput {
    pub fn compute(self) -> FeeProjection {
        FeeProjection {
            revision: self.revision,
            fees: project_fees(&self.entries, self.min_fee),
        }
    }
}

impl MempoolFeeIndex {
    pub fn new(fee_tx: Option<watch::Sender<Fees>>) -> Self {
        Self {
            entries: HashMap::new(),
            mempool_min_fee_sat_per_vb: 1,
            input_revision: 0,
            applied_revision: 0,
            fees: Fees::floor(1),
            fee_tx,
        }
    }

    pub fn insert(&mut self, txid: Txid, entry: MempoolEntry) {
        self.entries.insert(txid, entry);
        self.advance_revision();
    }

    pub fn remove(&mut self, txid: &Txid) {
        if self.entries.remove(txid).is_some() {
            self.advance_revision();
        }
    }

    /// Atomic full-snapshot replacement, paired with the dynamic
    /// mempool minimum fee from the same `getmempoolinfo` snapshot.
    /// Publishing before returning invalidates older off-loop results and keeps
    /// the cached projection and watch channel aligned with the new floor.
    pub fn sync(&mut self, entries: HashMap<Txid, MempoolEntry>, min_fee_sat_per_vb: u64) {
        self.entries = entries;
        self.mempool_min_fee_sat_per_vb = min_fee_sat_per_vb.max(1);
        self.advance_revision();
        self.recompute();
    }

    fn advance_revision(&mut self) {
        self.input_revision = self
            .input_revision
            .checked_add(1)
            .expect("fee revision exhausted");
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

    /// Most recent fee tier snapshot. Does not trigger a recompute.
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

    fn recompute(&mut self) -> Fees {
        let fees = project_fees(&self.entries, self.mempool_min_fee_sat_per_vb);
        self.apply_projection(FeeProjection {
            revision: self.input_revision,
            fees,
        });
        fees
    }

    /// The inputs a `recompute` needs, cloned so the projection can run on a
    /// blocking thread off the reactor's event loop. The clone is an O(entries)
    /// memcpy; the projection it enables — a topological sort with a per-tx
    /// ancestor-set union — is the expensive part (tens to hundreds of ms at
    /// mainnet scale) and is what must not run inline on the consensus thread.
    /// Taking a snapshot does not acknowledge progress: a failed task remains
    /// eligible for retry without requiring another mempool mutation.
    pub fn snapshot_if_needed(&self) -> Option<FeeProjectionInput> {
        (self.input_revision > self.applied_revision).then(|| FeeProjectionInput {
            revision: self.input_revision,
            entries: self.entries.clone(),
            min_fee: self.mempool_min_fee_sat_per_vb,
        })
    }

    pub fn apply_projection(&mut self, projection: FeeProjection) {
        if projection.revision <= self.applied_revision {
            return;
        }
        // Accept intermediate delta snapshots so a busy mempool cannot starve
        // publication. A newer input revision still schedules the next compute.
        self.applied_revision = projection.revision;
        self.fees = projection.fees;
        if let Some(tx) = &self.fee_tx {
            // Errors only when all receivers are dropped — fine, the
            // reactor keeps running.
            let _ = tx.send(self.fees);
        }
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

/// Project the three fee tiers from a mempool snapshot. Pure — no `self`, no
/// I/O — so it can run on a blocking thread. This is the expensive body of
/// `recompute`, lifted out for [`MempoolFeeIndex::snapshot_if_needed`].
pub fn project_fees(entries: &HashMap<Txid, MempoolEntry>, min: u64) -> Fees {
    let blocks = block_projection::project_blocks(entries, 4);
    let fastest = optimize_median_fee(blocks.first(), blocks.get(1), None, min);
    let half_hour = optimize_median_fee(blocks.get(1), blocks.get(2), Some(fastest), min);
    let hour = optimize_median_fee(blocks.get(2), blocks.get(3), Some(half_hour), min);
    Fees {
        fastest,
        half_hour,
        hour,
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
            wtxid: None,
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
            wtxid: None,
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
        idx.sync(HashMap::new(), 5);
        let fastest = idx.recompute().fastest;
        assert_eq!(fastest, 5);
    }

    #[test]
    fn half_empty_block_returns_min_fee() {
        let mut idx = MempoolFeeIndex::new(None);
        idx.sync(HashMap::new(), 3);
        // 100 txs of ~1000 vB each = 100k vB total (far below HALF_BLOCK).
        for n in 0..100u8 {
            idx.insert(txid(n), entry(10_000 /* 10 sat/vB × 1000 */, 1_000, vec![]));
        }
        let fastest = idx.recompute().fastest;
        assert_eq!(fastest, 3);
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
    fn successful_projection_acknowledges_mutations() {
        let mut idx = MempoolFeeIndex::new(None);
        assert!(idx.snapshot_if_needed().is_none());
        let id = txid(1);
        idx.insert(id, entry(100, 100, vec![]));
        let input = idx.snapshot_if_needed().unwrap();
        idx.apply_projection(input.compute());
        assert!(idx.snapshot_if_needed().is_none());
        idx.remove(&id);
        let input = idx.snapshot_if_needed().unwrap();
        idx.apply_projection(input.compute());
        idx.remove(&txid(99));
        assert!(idx.snapshot_if_needed().is_none());
    }

    #[test]
    fn sync_supersedes_in_flight_projection_in_either_completion_order() {
        for complete_before_sync in [false, true] {
            let (tx, mut rx) = watch::channel(Fees::floor(1));
            let mut idx = MempoolFeeIndex::new(Some(tx));
            idx.insert(txid(1), entry(20_000_000, 1_000_000, vec![]));
            let projection = idx.snapshot_if_needed().unwrap().compute();
            assert!(projection.fees.fastest > 5);
            if complete_before_sync {
                idx.apply_projection(projection);
                idx.sync(HashMap::new(), 5);
            } else {
                idx.sync(HashMap::new(), 5);
                assert_eq!(*rx.borrow_and_update(), Fees::floor(5));
                idx.apply_projection(projection);
                assert!(!rx.has_changed().unwrap(), "stale result must not publish");
            }
            assert_eq!(idx.fees(), Fees::floor(5));
            assert_eq!(*rx.borrow(), idx.fees());
            assert_eq!(idx.min_fee(), 5);
            assert!(idx.snapshot_if_needed().is_none());
        }
    }

    #[test]
    fn continuous_deltas_publish_intermediate_results_without_losing_pending_work() {
        let (tx, mut rx) = watch::channel(Fees::floor(1));
        let mut idx = MempoolFeeIndex::new(Some(tx));
        idx.insert(txid(1), entry(10_000_000, 1_000_000, vec![]));
        for rate in 11..16 {
            let input = idx.snapshot_if_needed().unwrap();
            idx.insert(txid(1), entry(rate * 1_000_000, 1_000_000, vec![]));
            idx.apply_projection(input.compute());
            assert_eq!(idx.fastest_fee(), rate - 1);
            assert!(rx.has_changed().unwrap());
            assert_eq!(*rx.borrow_and_update(), idx.fees());
            assert!(idx.snapshot_if_needed().is_some());
        }
        let input = idx.snapshot_if_needed().unwrap();
        idx.apply_projection(input.compute());
        assert_eq!(idx.fastest_fee(), 15);
        assert!(idx.snapshot_if_needed().is_none());
    }

    #[test]
    fn failed_computation_can_retry_without_another_mutation() {
        let mut idx = MempoolFeeIndex::new(None);
        idx.insert(txid(1), entry(10_000_000, 1_000_000, vec![]));
        // A task that exits without a result must not acknowledge its input.
        drop(idx.snapshot_if_needed().unwrap());
        let retry = idx.snapshot_if_needed().unwrap();
        idx.apply_projection(retry.compute());
        assert_eq!(idx.fastest_fee(), 10);
        assert!(idx.snapshot_if_needed().is_none());
    }

    #[test]
    fn sync_wipes_previous_state_and_publishes_current_floor() {
        let mut idx = MempoolFeeIndex::new(None);
        idx.insert(txid(1), entry(100, 100, vec![]));
        idx.insert(txid(2), entry(200, 100, vec![]));
        assert_eq!(idx.len(), 2);

        let mut replacement = HashMap::new();
        replacement.insert(txid(3), entry(300, 100, vec![]));
        idx.sync(replacement, 5);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.min_fee(), 5);
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
