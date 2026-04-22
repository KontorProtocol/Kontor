use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bitcoin::{
    BlockHash, CompactTarget, TxMerkleNode, Txid,
    block::{Header, Version},
    hashes::Hash,
};
use indexer_types::Block;

use super::error::Error;
use super::types::{
    GetBlockchainInfoResult, GetMempoolInfoResult, GetRawMempoolResult, MempoolEntry,
    MempoolEntryFees, TestMempoolAcceptResult,
};
use crate::bitcoin_client::client::BitcoinRpc;

/// Minimal default mempool entry used when the test doesn't explicitly seed
/// fee info for a tx. Fee values are negligible — tests that care about fee
/// estimation should use `set_mempool_entry` to provide real values.
fn stub_entry() -> MempoolEntry {
    MempoolEntry {
        vsize: 1,
        ancestorsize: 1,
        fees: MempoolEntryFees {
            base: bitcoin::Amount::from_sat(1),
            ancestor: bitcoin::Amount::from_sat(1),
        },
        depends: vec![],
    }
}

#[derive(Clone, Debug)]
pub struct MockBitcoinRpc {
    blocks: Arc<Mutex<Vec<Block>>>,
    mempool_txs: Arc<Mutex<Vec<bitcoin::Transaction>>>,
    mempool_sequence: Arc<Mutex<u64>>,
    mempool_entries: Arc<Mutex<HashMap<Txid, MempoolEntry>>>,
    mempool_min_fee_btc_per_kvb: Arc<Mutex<f64>>,
    /// Seeded responses keyed by txid for `test_mempool_accept`. Missing
    /// keys fall back to a default allowed-with-fees result.
    test_mempool_accept_overrides: Arc<Mutex<HashMap<Txid, TestMempoolAcceptResult>>>,
}

impl MockBitcoinRpc {
    pub fn new(blocks: Vec<Block>) -> Self {
        Self {
            blocks: Arc::new(Mutex::new(blocks)),
            mempool_txs: Arc::new(Mutex::new(vec![])),
            mempool_sequence: Arc::new(Mutex::new(0)),
            mempool_entries: Arc::new(Mutex::new(HashMap::new())),
            mempool_min_fee_btc_per_kvb: Arc::new(Mutex::new(0.00001)),
            test_mempool_accept_overrides: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn set_mempool(&self, txs: Vec<bitcoin::Transaction>) {
        *self.mempool_txs.lock().unwrap() = txs;
    }

    pub fn set_mempool_sequence(&self, seq: u64) {
        *self.mempool_sequence.lock().unwrap() = seq;
    }

    pub fn set_mempool_entry(&self, txid: Txid, entry: MempoolEntry) {
        self.mempool_entries.lock().unwrap().insert(txid, entry);
    }

    pub fn set_mempool_min_fee_btc_per_kvb(&self, fee: f64) {
        *self.mempool_min_fee_btc_per_kvb.lock().unwrap() = fee;
    }

    pub fn set_test_mempool_accept_result(&self, txid: Txid, result: TestMempoolAcceptResult) {
        self.test_mempool_accept_overrides
            .lock()
            .unwrap()
            .insert(txid, result);
    }

    pub fn append_blocks(&self, more: Vec<Block>) {
        self.blocks.lock().unwrap().extend(more);
    }

    pub fn replace_blocks(&self, blocks: Vec<Block>) {
        *self.blocks.lock().unwrap() = blocks;
    }

    pub fn blocks(&self) -> Vec<Block> {
        self.blocks.lock().unwrap().clone()
    }

    pub fn tip_height(&self) -> u64 {
        let blocks = self.blocks.lock().unwrap();
        blocks.last().map(|b| b.height).unwrap_or(0)
    }

    fn find_by_height(&self, height: u64) -> Option<Block> {
        let blocks = self.blocks.lock().unwrap();
        blocks.iter().find(|b| b.height == height).cloned()
    }

    fn find_by_hash(&self, hash: &BlockHash) -> Option<Block> {
        let blocks = self.blocks.lock().unwrap();
        blocks.iter().find(|b| b.hash == *hash).cloned()
    }
}

/// Build a minimal bitcoin::Block from an indexer_types::Block.
/// The header has the correct prev_blockhash and a merkle_root derived
/// from the block hash so that `block.block_hash()` won't collide
/// across different blocks (though it won't match `block.hash` since
/// we can't reverse a real PoW header). Tests should use the
/// indexer_types::Block fields rather than re-hashing the header.
fn to_bitcoin_block(block: &Block) -> bitcoin::Block {
    bitcoin::Block {
        header: Header {
            version: Version::ONE,
            prev_blockhash: block.prev_hash,
            merkle_root: TxMerkleNode::from_byte_array(block.hash.to_byte_array()),
            time: block.height as u32,
            bits: CompactTarget::from_consensus(0x2000_0000),
            nonce: 0,
        },
        txdata: vec![],
    }
}

impl BitcoinRpc for MockBitcoinRpc {
    async fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult, Error> {
        let blocks = self.blocks.lock().unwrap();
        let height = blocks.last().map(|b| b.height).unwrap_or(0);
        Ok(GetBlockchainInfoResult {
            chain: bitcoin::Network::Regtest,
            blocks: height,
            headers: height,
            difficulty: 1.0,
            median_time: 0,
            verification_progress: 1.0,
            initial_block_download: false,
            size_on_disk: 0,
            pruned: false,
            prune_height: None,
            automatic_pruning: None,
            prune_target_size: None,
        })
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        self.find_by_height(height)
            .map(|b| b.hash)
            .ok_or_else(|| Error::Unexpected(format!("no block at height {height}")))
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<bitcoin::Block, Error> {
        self.find_by_hash(hash)
            .map(|b| to_bitcoin_block(&b))
            .ok_or_else(|| Error::Unexpected(format!("no block with hash {hash}")))
    }

    async fn get_raw_mempool(&self) -> Result<Vec<Txid>, Error> {
        let txs = self.mempool_txs.lock().unwrap();
        Ok(txs.iter().map(|tx| tx.compute_txid()).collect())
    }

    async fn get_raw_mempool_sequence(&self) -> Result<GetRawMempoolResult, Error> {
        let txs = self.mempool_txs.lock().unwrap();
        let seq = *self.mempool_sequence.lock().unwrap();
        Ok(GetRawMempoolResult {
            txids: txs.iter().map(|tx| tx.compute_txid()).collect(),
            mempool_sequence: seq,
        })
    }

    async fn get_mempool_entry(&self, txid: &Txid) -> Result<Option<MempoolEntry>, Error> {
        // Explicit seeded entry wins; otherwise derive a stub from the raw
        // tx (if present) so tests that don't care about fees still work.
        if let Some(entry) = self.mempool_entries.lock().unwrap().get(txid).cloned() {
            return Ok(Some(entry));
        }
        let txs = self.mempool_txs.lock().unwrap();
        if txs.iter().any(|tx| tx.compute_txid() == *txid) {
            Ok(Some(stub_entry()))
        } else {
            Ok(None)
        }
    }

    async fn get_raw_mempool_verbose(&self) -> Result<HashMap<Txid, MempoolEntry>, Error> {
        // Merge seeded entries with stub entries for any mempool tx the
        // caller didn't explicitly set.
        let mut out = self.mempool_entries.lock().unwrap().clone();
        for tx in self.mempool_txs.lock().unwrap().iter() {
            out.entry(tx.compute_txid()).or_insert_with(stub_entry);
        }
        Ok(out)
    }

    async fn get_mempool_info(&self) -> Result<GetMempoolInfoResult, Error> {
        let fee = *self.mempool_min_fee_btc_per_kvb.lock().unwrap();
        Ok(GetMempoolInfoResult {
            mempool_min_fee_btc_per_kvb: fee,
            min_relay_tx_fee_btc_per_kvb: fee,
        })
    }

    async fn get_raw_transaction(&self, txid: &Txid) -> Result<bitcoin::Transaction, Error> {
        let txs = self.mempool_txs.lock().unwrap();
        txs.iter()
            .find(|tx| tx.compute_txid() == *txid)
            .cloned()
            .ok_or_else(|| {
                Error::Unexpected(format!("No such mempool or blockchain transaction: {txid}"))
            })
    }

    async fn get_raw_transactions(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Result<bitcoin::Transaction, Error>>, Error> {
        let txs = self.mempool_txs.lock().unwrap();
        Ok(txids
            .iter()
            .map(|txid| {
                txs.iter()
                    .find(|tx| tx.compute_txid() == *txid)
                    .cloned()
                    .ok_or_else(|| {
                        Error::Unexpected(format!(
                            "No such mempool or blockchain transaction: {txid}"
                        ))
                    })
            })
            .collect())
    }

    async fn test_mempool_accept(
        &self,
        raw_txs: &[String],
    ) -> Result<Vec<TestMempoolAcceptResult>, Error> {
        let overrides = self.test_mempool_accept_overrides.lock().unwrap();
        let mut out = Vec::with_capacity(raw_txs.len());
        for raw_hex in raw_txs {
            let raw: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(raw_hex)
                .map_err(|e| Error::Unexpected(format!("mock decode tx hex: {e}")))?;
            let txid = raw.compute_txid();
            let result = overrides
                .get(&txid)
                .cloned()
                .unwrap_or_else(|| TestMempoolAcceptResult {
                    txid,
                    wtxid: txid,
                    allowed: true,
                    reject_reason: None,
                    vsize: Some(raw.vsize() as u64),
                    fees: Some(super::types::TestMempoolAcceptResultFees {
                        base: bitcoin::Amount::from_sat(1_000),
                        effective_feerate_btc_per_kvb: Some(0.0001), // 10 sat/vB
                    }),
                });
            out.push(result);
        }
        Ok(out)
    }

    async fn send_raw_transaction(&self, raw_hex: &str) -> Result<String, Error> {
        let raw: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(raw_hex)
            .map_err(|e| Error::Unexpected(format!("mock decode tx hex: {e}")))?;
        Ok(raw.compute_txid().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin_client::client::check_mempool_acceptance;
    use crate::bitcoin_client::types::{Acceptance, MempoolEntryFees, TestMempoolAcceptResultFees};
    use bitcoin::consensus::encode;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Sequence, Transaction, TxIn, TxOut, Witness};

    /// Minimal bitcoin::Transaction suitable for hex-encoding. Uses a
    /// dummy OP_RETURN output so the tx is non-empty and serializes.
    fn sample_tx(n: u8) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([n; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    #[tokio::test]
    async fn accepted_with_fees() {
        let mock = MockBitcoinRpc::new(vec![]);
        let tx = sample_tx(1);
        let txid = tx.compute_txid();
        let raw_hex = encode::serialize_hex(&tx);

        // Seed a fresh accept with explicit fee rate: 0.0002 BTC/kvB → 20 sat/vB.
        mock.set_test_mempool_accept_result(
            txid,
            TestMempoolAcceptResult {
                txid,
                wtxid: txid,
                allowed: true,
                reject_reason: None,
                vsize: Some(200),
                fees: Some(TestMempoolAcceptResultFees {
                    base: Amount::from_sat(4_000),
                    effective_feerate_btc_per_kvb: Some(0.0002),
                }),
            },
        );

        let result = check_mempool_acceptance(&mock, &raw_hex, &txid)
            .await
            .unwrap();
        assert_eq!(
            result,
            Acceptance::Accepted {
                fee_rate_sat_per_vb: 20
            }
        );
    }

    #[tokio::test]
    async fn already_in_mempool_falls_back_to_entry() {
        let mock = MockBitcoinRpc::new(vec![]);
        let tx = sample_tx(2);
        let txid = tx.compute_txid();
        let raw_hex = encode::serialize_hex(&tx);

        // testmempoolaccept short-circuits — no fees, no vsize.
        mock.set_test_mempool_accept_result(
            txid,
            TestMempoolAcceptResult {
                txid,
                wtxid: txid,
                allowed: false,
                reject_reason: Some("txn-already-in-mempool".to_string()),
                vsize: None,
                fees: None,
            },
        );
        // Seed a mempool entry with ancestor fees 5000 sat / 250 vB = 20 sat/vB.
        mock.set_mempool_entry(
            txid,
            MempoolEntry {
                vsize: 250,
                ancestorsize: 250,
                fees: MempoolEntryFees {
                    base: Amount::from_sat(5_000),
                    ancestor: Amount::from_sat(5_000),
                },
                depends: vec![],
            },
        );

        let result = check_mempool_acceptance(&mock, &raw_hex, &txid)
            .await
            .unwrap();
        assert_eq!(
            result,
            Acceptance::Accepted {
                fee_rate_sat_per_vb: 20
            }
        );
    }

    #[tokio::test]
    async fn already_known_without_entry_returns_rejected() {
        let mock = MockBitcoinRpc::new(vec![]);
        let tx = sample_tx(3);
        let txid = tx.compute_txid();
        let raw_hex = encode::serialize_hex(&tx);

        // testmempoolaccept reports already-known but entry isn't present
        // (race: tx evicted between RPCs).
        mock.set_test_mempool_accept_result(
            txid,
            TestMempoolAcceptResult {
                txid,
                wtxid: txid,
                allowed: false,
                reject_reason: Some("txn-already-known".to_string()),
                vsize: None,
                fees: None,
            },
        );
        // Do NOT seed a mempool entry — and the tx isn't in mempool_txs
        // either, so get_mempool_entry returns None.

        let result = check_mempool_acceptance(&mock, &raw_hex, &txid)
            .await
            .unwrap();
        match result {
            Acceptance::Rejected { reason } => {
                assert!(
                    reason.contains("disappeared"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn truly_rejected_returns_reason() {
        let mock = MockBitcoinRpc::new(vec![]);
        let tx = sample_tx(4);
        let txid = tx.compute_txid();
        let raw_hex = encode::serialize_hex(&tx);

        mock.set_test_mempool_accept_result(
            txid,
            TestMempoolAcceptResult {
                txid,
                wtxid: txid,
                allowed: false,
                reject_reason: Some("min relay fee not met".to_string()),
                vsize: None,
                fees: None,
            },
        );

        let result = check_mempool_acceptance(&mock, &raw_hex, &txid)
            .await
            .unwrap();
        assert_eq!(
            result,
            Acceptance::Rejected {
                reason: "min relay fee not met".to_string(),
            }
        );
    }
}
