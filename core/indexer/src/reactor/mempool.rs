use std::collections::{HashMap, HashSet};
#[cfg(test)]
use std::slice;

use bitcoin::{Transaction as BitcoinTransaction, Txid};
use indexer_types::Transaction;

use super::executor::RecognizedTransaction;

#[derive(Default)]
pub struct Mempool {
    raw: HashMap<Txid, BitcoinTransaction>,
    suppressed: HashSet<Txid>,
    pub candidates: HashMap<Txid, (BitcoinTransaction, Transaction)>,
}

impl Mempool {
    pub fn replace(&mut self, transactions: Vec<RecognizedTransaction>) {
        self.raw.clear();
        self.candidates.clear();
        self.suppressed.clear();
        for transaction in transactions {
            self.insert(transaction);
        }
    }

    pub fn stage_snapshot(&mut self, transactions: &[BitcoinTransaction]) {
        self.raw.clear();
        self.candidates.clear();
        self.suppressed.clear();
        for raw in transactions {
            self.stage(raw);
        }
    }

    pub fn stage(&mut self, raw: &BitcoinTransaction) {
        let txid = raw.compute_txid();
        self.raw.insert(txid, raw.clone());
        self.candidates.remove(&txid);
        self.suppressed.remove(&txid);
    }

    pub fn insert(&mut self, transaction: RecognizedTransaction) -> bool {
        self.stage(&transaction.raw);
        self.finish(transaction)
    }

    pub fn finish(&mut self, transaction: RecognizedTransaction) -> bool {
        let RecognizedTransaction { raw, parsed } = transaction;
        let txid = raw.compute_txid();
        // Blocks and finality can remove or suppress inputs while recognition
        // runs. A late result must not restore them or a replacement witness.
        if self.raw.get(&txid) != Some(&raw) || self.suppressed.contains(&txid) {
            return false;
        }
        let recognized = parsed.is_some();
        if let Some(parsed) = parsed {
            self.candidates.insert(txid, (raw, parsed));
        }
        recognized
    }

    pub fn contains_candidate(&self, raw: &BitcoinTransaction) -> bool {
        self.candidates
            .get(&raw.compute_txid())
            .is_some_and(|(current, _)| current == raw)
    }

    pub fn suppress(&mut self, txid: &Txid) {
        self.candidates.remove(txid);
        if self.raw.contains_key(txid) {
            self.suppressed.insert(*txid);
        }
    }

    pub fn reject(&mut self, raw: &BitcoinTransaction) {
        let txid = raw.compute_txid();
        if self.raw.get(&txid) == Some(raw) {
            self.suppress(&txid);
        }
    }

    pub fn cache_proposal(&mut self, raw: &BitcoinTransaction, parsed: Transaction) {
        let txid = raw.compute_txid();
        if self.suppressed.contains(&txid) {
            return;
        }
        let current = self.raw.entry(txid).or_insert_with(|| raw.clone());
        // Proposal validation judges its own bytes. Its optional mempool cache
        // must not overwrite a different witness received from the listener.
        if current == raw {
            self.candidates
                .entry(txid)
                .or_insert_with(|| (raw.clone(), parsed));
        }
    }

    pub fn remove(&mut self, txid: &Txid) {
        self.raw.remove(txid);
        self.candidates.remove(txid);
        self.suppressed.remove(txid);
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::{Network, Witness};

    use super::*;

    fn prepared(raw: BitcoinTransaction, recognized: bool) -> RecognizedTransaction {
        let parsed = recognized.then(|| Transaction {
            txid: raw.compute_txid(),
            index: 0,
            inputs: Vec::new(),
            op_return_raw: None,
        });
        RecognizedTransaction { raw, parsed }
    }

    #[test]
    fn unrecognized_input_survives_candidate_filtering_until_removal() {
        let raw = genesis_block(Network::Regtest).txdata.remove(0);
        let txid = raw.compute_txid();
        let mut pool = Mempool::default();
        assert!(!pool.insert(prepared(raw.clone(), false)));
        assert!(pool.candidates.is_empty());
        assert_eq!(pool.raw.get(&txid), Some(&raw));
        assert!(pool.insert(prepared(raw.clone(), true)));
        pool.candidates.remove(&txid);
        assert_eq!(pool.raw.get(&txid), Some(&raw));
        pool.remove(&txid);
        assert!(pool.raw.get(&txid).is_none());
        assert!(pool.candidates.is_empty());
    }

    #[test]
    fn changed_witness_replaces_raw_bytes_and_invalidates_old_recognition() {
        let raw = genesis_block(Network::Regtest).txdata.remove(0);
        let txid = raw.compute_txid();
        let mut replacement = raw.clone();
        replacement.input[0].witness = Witness::from_slice(&[b"new witness".as_slice()]);
        assert_eq!(replacement.compute_txid(), txid);
        let mut pool = Mempool::default();
        assert!(pool.insert(prepared(raw, true)));
        assert!(!pool.insert(prepared(replacement.clone(), false)));
        assert!(pool.candidates.is_empty());
        assert_eq!(pool.raw.get(&txid), Some(&replacement));
    }

    #[test]
    fn snapshot_replaces_raw_inputs_and_candidates_together() {
        let raw = genesis_block(Network::Regtest).txdata.remove(0);
        let txid = raw.compute_txid();
        let mut pool = Mempool::default();
        pool.insert(prepared(raw.clone(), true));
        pool.replace(vec![prepared(raw, false)]);
        assert!(pool.candidates.is_empty());
        assert!(pool.raw.get(&txid).is_some());
        pool.replace(Vec::new());
        assert!(pool.raw.get(&txid).is_none());
    }
    #[test]
    fn late_recognition_cannot_restore_removed_or_suppressed_inputs() {
        let raw = genesis_block(Network::Regtest).txdata.remove(0);
        let txid = raw.compute_txid();
        let mut pool = Mempool::default();
        pool.stage_snapshot(slice::from_ref(&raw));
        pool.remove(&txid);
        assert!(!pool.finish(prepared(raw.clone(), true)));
        assert!(!pool.contains_candidate(&raw));
        pool.stage_snapshot(slice::from_ref(&raw));
        pool.suppress(&txid);
        assert!(!pool.finish(prepared(raw.clone(), true)));
        assert!(!pool.contains_candidate(&raw));
        assert_eq!(pool.raw.get(&txid), Some(&raw));
        pool.stage(&raw);
        assert!(pool.finish(prepared(raw.clone(), true)));
        assert!(pool.contains_candidate(&raw));
    }

    #[test]
    fn stale_recognition_and_rejection_leave_replacement_witness_intact() {
        let raw = genesis_block(Network::Regtest).txdata.remove(0);
        let mut replacement = raw.clone();
        replacement.input[0].witness = Witness::from_slice(&[b"replacement".as_slice()]);
        let mut pool = Mempool::default();
        pool.stage(&raw);
        pool.stage(&replacement);
        assert!(!pool.finish(prepared(raw.clone(), true)));
        assert!(pool.finish(prepared(replacement.clone(), true)));
        pool.reject(&raw);
        assert!(!pool.contains_candidate(&raw));
        assert!(pool.contains_candidate(&replacement));
        pool.reject(&replacement);
        assert!(!pool.finish(prepared(replacement.clone(), true)));
        assert!(!pool.contains_candidate(&replacement));
    }

    #[test]
    fn proposal_cache_preserves_listener_witness_and_local_suppression() {
        let raw = genesis_block(Network::Regtest).txdata.remove(0);
        let mut other = raw.clone();
        other.input[0].witness = Witness::from_slice(&[b"proposal".as_slice()]);
        let mut pool = Mempool::default();
        pool.stage(&raw);
        pool.cache_proposal(&other, prepared(other.clone(), true).parsed.unwrap());
        assert!(!pool.contains_candidate(&other));
        assert!(pool.finish(prepared(raw.clone(), true)));
        pool.suppress(&raw.compute_txid());
        pool.cache_proposal(&raw, prepared(raw.clone(), true).parsed.unwrap());
        assert!(!pool.contains_candidate(&raw));
        pool.remove(&raw.compute_txid());
        pool.cache_proposal(&other, prepared(other.clone(), true).parsed.unwrap());
        assert!(pool.contains_candidate(&other));
        assert_eq!(pool.raw.get(&other.compute_txid()), Some(&other));
    }
}
