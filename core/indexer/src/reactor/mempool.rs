use std::collections::HashMap;

use bitcoin::{Transaction as BitcoinTransaction, Txid};
use indexer_types::Transaction;

use super::executor::RecognizedTransaction;

#[derive(Default)]
pub struct Mempool {
    raw: HashMap<Txid, BitcoinTransaction>,
    pub candidates: HashMap<Txid, (BitcoinTransaction, Transaction)>,
}

impl Mempool {
    pub fn replace(&mut self, transactions: Vec<RecognizedTransaction>) {
        self.raw.clear();
        self.candidates.clear();
        for transaction in transactions {
            self.insert(transaction);
        }
    }

    pub fn insert(&mut self, transaction: RecognizedTransaction) -> bool {
        let RecognizedTransaction { raw, parsed } = transaction;
        let txid = raw.compute_txid();
        let recognized = parsed.is_some();
        if let Some(parsed) = parsed {
            self.candidates.insert(txid, (raw.clone(), parsed));
        } else {
            // A replacement witness can cease to be recognized while keeping
            // its txid. Never reuse the previous witness's parsed instructions.
            self.candidates.remove(&txid);
        }
        self.raw.insert(txid, raw);
        recognized
    }

    pub fn remove(&mut self, txid: &Txid) {
        self.raw.remove(txid);
        self.candidates.remove(txid);
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
}
