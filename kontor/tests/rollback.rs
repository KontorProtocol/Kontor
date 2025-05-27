use anyhow::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use bitcoin::{self, BlockHash, Network, Txid, hashes::Hash};

use kontor::{
    bitcoin_client::{client, error, types},
    bitcoin_follower::{self, queries::select_block_at_height},
    database::{queries::insert_block, types::BlockRow},
    reactor,
    utils::{MockTransaction, new_test_db},
};

#[derive(Clone)]
struct MockClient {
    blocks: Vec<bitcoin::Block>,
    expect_get_raw_transaction_txid: Option<Txid>,
}

impl MockClient {
    fn new(blocks: Vec<bitcoin::Block>) -> Self {
        MockClient {
            blocks,
            expect_get_raw_transaction_txid: None,
        }
    }
}

// dummy transaction grabbed from bitcoin-rs test-code
const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

fn gen_block(prev_hash: &BlockHash, time: u32) -> bitcoin::Block {
    bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: *prev_hash,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0x77; 32]),
            time: time,
            bits: bitcoin::CompactTarget::from_consensus(3),
            nonce: 4,
        },
        txdata: vec![],
    }
}

fn gen_blocks(start: u64, end: u64, time: u32, prev_hash: BlockHash) -> Vec<bitcoin::Block> {
    let mut blocks = vec![];
    let mut hash = prev_hash;

    for _i in start..end {
        let block = gen_block(&hash, time);
        blocks.push(block.clone());

        hash = block.block_hash();
    }

    blocks
}

fn new_block_chain(n: u64, time: u32) -> Vec<bitcoin::Block> {
    gen_blocks(0, n, time, BlockHash::from_byte_array([0x00; 32]))
}

impl client::BitcoinRpc for MockClient {
    async fn get_blockchain_info(&self) -> Result<types::GetBlockchainInfoResult, error::Error> {
        Ok(types::GetBlockchainInfoResult {
            chain: Network::Bitcoin,
            blocks: self.blocks.len() as u64,
            headers: self.blocks.len() as u64,
            difficulty: 1.0,
            median_time: 1,
            verification_progress: 1.0,
            initial_block_download: false,
            size_on_disk: 0,
            pruned: false,
            prune_height: None,
            automatic_pruning: None,
            prune_target_size: None,
        })
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash, error::Error> {
        Ok(self.blocks[height as usize - 1].block_hash())
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<bitcoin::Block, error::Error> {
        Ok(self
            .blocks
            .iter()
            .find(|b| &b.block_hash() == hash)
            .unwrap()
            .clone())
    }

    async fn get_raw_mempool(&self) -> Result<Vec<Txid>, error::Error> {
        Ok(vec![])
    }

    async fn get_raw_transaction(&self, txid: &Txid) -> Result<bitcoin::Transaction, error::Error> {
        if let Some(id) = self.expect_get_raw_transaction_txid {
            assert_eq!(*txid, id);
        }

        // note: the returned transaction will not match the requested txid
        let raw_tx = hex::decode(SOME_TX).unwrap();
        let tx: bitcoin::Transaction =
            bitcoin::consensus::Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        Ok(tx)
    }

    async fn get_raw_transactions(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Result<bitcoin::Transaction, error::Error>>, error::Error> {
        if txids.len() == 0 {
            Ok(vec![])
        } else {
            assert_eq!(txids.len(), 1);
            let tx = self.get_raw_transaction(&txids[0]).await?;
            Ok(vec![Ok(tx)])
        }
    }
}

fn block_row(height: u64, b: &bitcoin::Block) -> BlockRow {
    BlockRow {
        height,
        hash: b.block_hash(),
    }
}

#[tokio::test]
async fn test_follower_reactor_fetching() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (tx, rx) = mpsc::channel(1);
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let blocks = new_block_chain(5, 123);
    let conn = &writer.connection();
    assert!(insert_block(conn, block_row(1, &blocks[0])).await.is_ok());
    assert!(insert_block(conn, block_row(2, &blocks[1])).await.is_ok());
    assert!(insert_block(conn, block_row(3, &blocks[2])).await.is_ok());

    let client = MockClient::new(blocks.clone());

    let mut handles = vec![];

    fn f(t: bitcoin::Transaction) -> Option<MockTransaction> {
        let raw_tx = hex::decode(SOME_TX).unwrap();
        let tx: bitcoin::Transaction =
            bitcoin::consensus::Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        assert_eq!(t, tx);

        Some(MockTransaction::new(123))
    }

    let start_height = 2; // will be overriden by stored blocks
    handles.push(
        bitcoin_follower::run(
            start_height,
            None, // no ZMQ connection
            cancel_token.clone(),
            reader.clone(),
            client,
            f,
            tx,
        )
        .await?,
    );

    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        rx,
    ));

    let block = select_block_at_height(conn, 4, cancel_token.clone()).await?;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].block_hash());

    let block = select_block_at_height(conn, 5, cancel_token.clone()).await?;
    assert_eq!(block.height, 5);
    assert_eq!(block.hash, blocks[5 - 1].block_hash());

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

#[tokio::test]
async fn test_follower_reactor_rollback() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (tx, rx) = mpsc::channel(1);
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let mut blocks = new_block_chain(3, 123);
    let conn = &writer.connection();
    assert!(insert_block(conn, block_row(1, &blocks[0])).await.is_ok());
    assert!(insert_block(conn, block_row(2, &blocks[1])).await.is_ok());
    assert!(insert_block(conn, block_row(3, &blocks[2])).await.is_ok());

    let initial_block_3_hash = blocks[2].block_hash();

    // remove last block (height 3), generate 3 new blocks with different
    // timestamp (and thus hashes) and append them to the chain.
    _ = blocks.pop();
    let more_blocks = gen_blocks(2, 5, 234, blocks[1].block_hash());
    blocks.extend(more_blocks.iter().cloned());

    let client = MockClient::new(blocks.clone());

    let mut handles = vec![];

    fn f(t: bitcoin::Transaction) -> Option<MockTransaction> {
        let raw_tx = hex::decode(SOME_TX).unwrap();
        let tx: bitcoin::Transaction =
            bitcoin::consensus::Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        assert_eq!(t, tx);

        Some(MockTransaction::new(123))
    }

    let start_height = 2; // will be overriden by stored blocks
    handles.push(
        bitcoin_follower::run(
            start_height,
            None, // no ZMQ connection
            cancel_token.clone(),
            reader.clone(),
            client,
            f,
            tx,
        )
        .await?,
    );

    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        rx,
    ));

    // by reading out the two last blocks first we ensure that the rollback has been enacted
    let block = select_block_at_height(conn, 4, cancel_token.clone()).await?;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].block_hash());

    let block = select_block_at_height(conn, 5, cancel_token.clone()).await?;
    assert_eq!(block.height, 5);
    assert_eq!(block.hash, blocks[5 - 1].block_hash());

    // reading block 3, verify that it was rolled back and hash has been updated
    let block = select_block_at_height(conn, 3, cancel_token.clone()).await?;
    assert_eq!(block.height, 3);
    assert_eq!(block.hash, blocks[3 - 1].block_hash());
    assert_ne!(block.hash, initial_block_3_hash);

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
