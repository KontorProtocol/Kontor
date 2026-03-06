use std::collections::HashSet;

use sha3::{Digest, Keccak256};

use indexer::consensus::Height;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    Batched,
    Confirmed,
}

impl TxStatus {
    fn as_byte(&self) -> u8 {
        match self {
            TxStatus::Batched => 0,
            TxStatus::Confirmed => 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StateEntry {
    pub anchor_height: u64,
    pub batch_height: Option<Height>, // None = unbatched (from bitcoin block directly)
    pub txid: [u8; 32],
    pub status: TxStatus,
}

pub struct StateLog {
    entries: Vec<StateEntry>,
    checkpoint: [u8; 32],
}

impl Default for StateLog {
    fn default() -> Self {
        Self::new()
    }
}

impl StateLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            checkpoint: [0u8; 32],
        }
    }

    pub fn checkpoint(&self) -> [u8; 32] {
        self.checkpoint
    }

    pub fn entries(&self) -> &[StateEntry] {
        &self.entries
    }

    pub fn status_of(&self, txid: &[u8; 32]) -> Option<&TxStatus> {
        self.entries
            .iter()
            .rev()
            .find(|e| &e.txid == txid)
            .map(|e| &e.status)
    }

    pub fn batched_txids(&self) -> HashSet<[u8; 32]> {
        self.entries
            .iter()
            .filter(|e| e.status == TxStatus::Batched)
            .map(|e| e.txid)
            .collect()
    }

    pub fn entries_at_anchor(&self, height: u64) -> Vec<&StateEntry> {
        self.entries
            .iter()
            .filter(|e| e.anchor_height == height)
            .collect()
    }

    /// Low-level append: add a single entry and update checkpoint.
    pub fn append_entry(&mut self, anchor_height: u64, txid: [u8; 32], status: TxStatus) {
        let entry = StateEntry {
            anchor_height,
            batch_height: None,
            txid,
            status,
        };
        self.update_checkpoint(&entry);
        self.entries.push(entry);
    }

    /// Append entries for a decided batch. All txids get `Batched` status.
    pub fn apply_batch(
        &mut self,
        anchor_height: u64,
        consensus_height: Height,
        txids: &[[u8; 32]],
    ) {
        for txid in txids {
            let entry = StateEntry {
                anchor_height,
                batch_height: Some(consensus_height),
                txid: *txid,
                status: TxStatus::Batched,
            };
            self.update_checkpoint(&entry);
            self.entries.push(entry);
        }
    }

    /// Append entries for a bitcoin block's transactions. Skips txids already in `Batched` status
    /// (deduplication — batched txs take priority).
    pub fn apply_block(&mut self, height: u64, txids: &[[u8; 32]]) {
        let batched = self.batched_txids();
        for txid in txids {
            if batched.contains(txid) {
                continue;
            }
            let entry = StateEntry {
                anchor_height: height,
                batch_height: None,
                txid: *txid,
                status: TxStatus::Confirmed,
            };
            self.update_checkpoint(&entry);
            self.entries.push(entry);
        }
    }

    /// Remove all entries at or above `anchor_height` and recompute checkpoint.
    pub fn rollback_to(&mut self, anchor_height: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.anchor_height < anchor_height);
        let removed = before - self.entries.len();
        self.recompute_checkpoint();
        removed
    }

    fn update_checkpoint(&mut self, entry: &StateEntry) {
        let mut hasher = Keccak256::new();
        hasher.update(self.checkpoint);
        hasher.update(entry.txid);
        hasher.update([entry.status.as_byte()]);
        self.checkpoint = hasher.finalize().into();
    }

    fn recompute_checkpoint(&mut self) {
        self.checkpoint = [0u8; 32];
        for i in 0..self.entries.len() {
            let txid = self.entries[i].txid;
            let status_byte = self.entries[i].status.as_byte();
            let mut hasher = Keccak256::new();
            hasher.update(self.checkpoint);
            hasher.update(txid);
            hasher.update([status_byte]);
            self.checkpoint = hasher.finalize().into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_txid(n: u8) -> [u8; 32] {
        let mut txid = [0u8; 32];
        txid[0] = n;
        txid
    }

    #[test]
    fn apply_batch_appends_entries() {
        let mut log = StateLog::new();
        let txids = vec![make_txid(1), make_txid(2)];
        log.apply_batch(100, Height::new(1), &txids);

        assert_eq!(log.entries().len(), 2);
        assert_eq!(log.status_of(&make_txid(1)), Some(&TxStatus::Batched));
        assert_eq!(log.status_of(&make_txid(2)), Some(&TxStatus::Batched));
        assert_eq!(log.entries()[0].anchor_height, 100);
        assert_eq!(log.entries()[0].batch_height, Some(Height::new(1)));
    }

    #[test]
    fn apply_block_appends_confirmed_entries() {
        let mut log = StateLog::new();
        let txids = vec![make_txid(1), make_txid(2)];
        log.apply_block(100, &txids);

        assert_eq!(log.entries().len(), 2);
        assert_eq!(log.status_of(&make_txid(1)), Some(&TxStatus::Confirmed));
        assert_eq!(log.entries()[0].batch_height, None);
    }

    #[test]
    fn apply_block_skips_batched_duplicates() {
        let mut log = StateLog::new();
        let tx1 = make_txid(1);
        let tx2 = make_txid(2);
        let tx3 = make_txid(3);

        // Batch contains tx1 and tx2
        log.apply_batch(100, Height::new(1), &[tx1, tx2]);
        // Block contains tx1, tx2, tx3 — only tx3 should be added
        log.apply_block(100, &[tx1, tx2, tx3]);

        assert_eq!(log.entries().len(), 3); // 2 batched + 1 confirmed
        assert_eq!(log.status_of(&tx1), Some(&TxStatus::Batched));
        assert_eq!(log.status_of(&tx2), Some(&TxStatus::Batched));
        assert_eq!(log.status_of(&tx3), Some(&TxStatus::Confirmed));
    }

    #[test]
    fn rollback_truncates_at_anchor() {
        let mut log = StateLog::new();
        log.apply_batch(100, Height::new(1), &[make_txid(1)]);
        log.apply_batch(101, Height::new(2), &[make_txid(2)]);
        log.apply_batch(102, Height::new(3), &[make_txid(3)]);

        let removed = log.rollback_to(101);
        assert_eq!(removed, 2); // entries at 101 and 102
        assert_eq!(log.entries().len(), 1);
        assert_eq!(log.status_of(&make_txid(1)), Some(&TxStatus::Batched));
        assert_eq!(log.status_of(&make_txid(2)), None);
        assert_eq!(log.status_of(&make_txid(3)), None);
    }

    #[test]
    fn checkpoint_changes_on_append() {
        let mut log = StateLog::new();
        let initial = log.checkpoint();
        assert_eq!(initial, [0u8; 32]);

        log.apply_batch(100, Height::new(1), &[make_txid(1)]);
        let after_one = log.checkpoint();
        assert_ne!(after_one, initial);

        log.apply_batch(100, Height::new(1), &[make_txid(2)]);
        let after_two = log.checkpoint();
        assert_ne!(after_two, after_one);
    }

    #[test]
    fn checkpoint_restored_after_rollback() {
        let mut log = StateLog::new();
        log.apply_batch(100, Height::new(1), &[make_txid(1)]);
        let checkpoint_at_100 = log.checkpoint();

        log.apply_batch(101, Height::new(2), &[make_txid(2)]);
        assert_ne!(log.checkpoint(), checkpoint_at_100);

        log.rollback_to(101);
        assert_eq!(log.checkpoint(), checkpoint_at_100);
    }

    #[test]
    fn same_operations_produce_same_checkpoint() {
        let mut log_a = StateLog::new();
        let mut log_b = StateLog::new();

        let txids = vec![make_txid(1), make_txid(2)];
        log_a.apply_batch(100, Height::new(1), &txids);
        log_b.apply_batch(100, Height::new(1), &txids);

        assert_eq!(log_a.checkpoint(), log_b.checkpoint());

        log_a.apply_block(100, &[make_txid(3)]);
        log_b.apply_block(100, &[make_txid(3)]);

        assert_eq!(log_a.checkpoint(), log_b.checkpoint());
    }

    #[test]
    fn batched_txids_returns_all_batched() {
        let mut log = StateLog::new();
        log.apply_batch(100, Height::new(1), &[make_txid(1), make_txid(2)]);
        log.apply_block(100, &[make_txid(3)]);

        let batched = log.batched_txids();
        assert_eq!(batched.len(), 2);
        assert!(batched.contains(&make_txid(1)));
        assert!(batched.contains(&make_txid(2)));
        assert!(!batched.contains(&make_txid(3)));
    }

    #[test]
    fn entries_at_anchor_filters_correctly() {
        let mut log = StateLog::new();
        log.apply_batch(100, Height::new(1), &[make_txid(1)]);
        log.apply_batch(101, Height::new(2), &[make_txid(2)]);
        log.apply_block(100, &[make_txid(3)]);

        let at_100 = log.entries_at_anchor(100);
        assert_eq!(at_100.len(), 2); // tx1 (batched) + tx3 (confirmed)

        let at_101 = log.entries_at_anchor(101);
        assert_eq!(at_101.len(), 1); // tx2 (batched)
    }
}
