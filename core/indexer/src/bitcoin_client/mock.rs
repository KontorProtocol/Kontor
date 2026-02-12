use std::sync::{Arc, Mutex};

use bitcoin::{
    BlockHash, CompactTarget, TxMerkleNode, Txid,
    block::{Header, Version},
    hashes::Hash,
};
use indexer_types::Block;

use super::error::Error;
use super::types::GetBlockchainInfoResult;
use crate::bitcoin_client::client::BitcoinRpc;

#[derive(Clone, Debug)]
pub struct MockBitcoinRpc {
    blocks: Arc<Mutex<Vec<Block>>>,
}

impl MockBitcoinRpc {
    pub fn new(blocks: Vec<Block>) -> Self {
        Self {
            blocks: Arc::new(Mutex::new(blocks)),
        }
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
        Ok(vec![])
    }

    async fn get_raw_transaction(&self, _txid: &Txid) -> Result<bitcoin::Transaction, Error> {
        Err(Error::Unexpected("not implemented in mock".to_string()))
    }

    async fn get_raw_transactions(
        &self,
        _txids: &[Txid],
    ) -> Result<Vec<Result<bitcoin::Transaction, Error>>, Error> {
        Err(Error::Unexpected("not implemented in mock".to_string()))
    }
}
