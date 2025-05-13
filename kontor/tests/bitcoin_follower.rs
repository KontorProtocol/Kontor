use anyhow::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use bitcoin::{
    self,
    Network,
    BlockHash,
    hashes::Hash,
};

use kontor::{
    bitcoin_follower::rpc::{
        run_producer,
        run_fetcher,
        run_processor,
        run_orderer,
    },
    bitcoin_client::{ client, types, error },
    block::{ Block },
    utils::{ MockTransaction },
};

use ntest::timeout;

#[derive(Clone)]
struct MockClient {
    height: u64,
}

impl client::BitcoinRpc for MockClient {
    async fn get_blockchain_info(&self) -> Result<types::GetBlockchainInfoResult, error::Error> {
        Ok(types::GetBlockchainInfoResult{
            chain: Network::Bitcoin,
            blocks: self.height,
            headers: self.height,
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

    async fn get_block_hash(&self, _height: u64) -> Result<BlockHash, error::Error> {
        Ok(BlockHash::from_byte_array([0x11; 32]))
    }

    async fn get_block(&self, _hash: &BlockHash) -> Result<bitcoin::Block, error::Error> {
        Ok(bitcoin::Block{
            header: bitcoin::block::Header{
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0x77; 32]),
                time: 123,
                bits: bitcoin::CompactTarget::from_consensus(3),
                nonce: 4,
            },
            txdata: vec![],
        })
    }
}

#[tokio::test]
#[timeout(100)]
async fn test_producer() -> Result<()> {
    let cancel_token = CancellationToken::new();

    let client = MockClient{ height: 1000 };
    let (producer, mut rx) = run_producer(700, client, cancel_token.clone());

    let (target_height, height) = rx.recv().await.unwrap();
    assert_eq!(target_height, 1000);
    assert_eq!(height, 700);

    let (target_height, height) = rx.recv().await.unwrap();
    assert_eq!(target_height, 1000);
    assert_eq!(height, 701);

    assert!(!producer.is_finished());

    cancel_token.cancel();
    let _ = producer.await;

    Ok(())
}

#[tokio::test]
#[timeout(100)]
async fn test_fetcher() -> Result<()> {
    let cancel_token = CancellationToken::new();

    let client = MockClient{ height: 1000 };
    let (tx_in, rx_in) = mpsc::channel(10);

    let (fetcher, mut rx_out) = run_fetcher(rx_in, client, cancel_token.clone());

    assert!(tx_in.send((1000, 700)).await.is_ok());

    let (target_height, height, block) = rx_out.recv().await.unwrap();
    assert_eq!(target_height, 1000);
    assert_eq!(height, 700);
    assert_eq!(block.header.prev_blockhash, BlockHash::from_byte_array([0x99; 32]));

    assert!(!fetcher.is_finished());
    cancel_token.cancel();
    let _ = fetcher.await;

    Ok(())
}

#[tokio::test]
#[timeout(100)]
async fn test_processor() -> Result<()> {
    let cancel_token = CancellationToken::new();

    let (tx_in, rx_in) = mpsc::channel(10);

    // dummy transaction grabbed from bitcoin-rs test-code
    const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    let raw_tx = hex::decode(SOME_TX).unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

    fn f(t: bitcoin::Transaction) -> Option<MockTransaction> {
        let raw_tx = hex::decode(SOME_TX).unwrap();
        let tx: bitcoin::Transaction = bitcoin::consensus::Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        assert_eq!(t, tx);

        Some(MockTransaction::new(123))
    }

    let (processor, mut rx_out) = run_processor(rx_in, f, cancel_token.clone());

    assert!(tx_in.send((1000, 700, bitcoin::Block{
        header: bitcoin::block::Header{
            version: bitcoin::block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0x77; 32]),
            time: 123,
            bits: bitcoin::CompactTarget::from_consensus(3),
            nonce: 4,
        },
        txdata: vec![tx],
    })).await.is_ok());

    let (target_height, block) = rx_out.recv().await.unwrap();
    assert_eq!(target_height, 1000);
    assert_eq!(block.height, 700);
    assert_eq!(block.transactions, vec![MockTransaction::new(123)]);

    assert!(!processor.is_finished());
    cancel_token.cancel();
    let _ = processor.await;

    Ok(())
}

#[tokio::test]
#[timeout(100)]
async fn test_orderer() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (tx_in, rx_in) = mpsc::channel(10);
    let (tx_out, mut rx_out) = mpsc::channel(10);

    let orderer = run_orderer::<MockTransaction>(700, rx_in, tx_out, cancel_token.clone());

    // send 3 blocks in mixed order
    assert!(tx_in.send((1000, Block{
        height: 702,
        hash: BlockHash::from_byte_array([0x44; 32]),
        prev_hash: BlockHash::from_byte_array([0x33; 32]),
        transactions: vec![],
    })).await.is_ok());
    assert!(tx_in.send((1000, Block{
        height: 700,
        hash: BlockHash::from_byte_array([0x22; 32]),
        prev_hash: BlockHash::from_byte_array([0x11; 32]),
        transactions: vec![],
    })).await.is_ok());
    assert!(tx_in.send((1000, Block{
        height: 701,
        hash: BlockHash::from_byte_array([0x33; 32]),
        prev_hash: BlockHash::from_byte_array([0x22; 32]),
        transactions: vec![],
    })).await.is_ok());

    // verify that they come out ordered
    let (target_height, block) = rx_out.recv().await.unwrap();
    assert_eq!(target_height, 1000);
    assert_eq!(block, Block{
        height: 700,
        hash: BlockHash::from_byte_array([0x22; 32]),
        prev_hash: BlockHash::from_byte_array([0x11; 32]),
        transactions: vec![],
    });
    let (target_height, block) = rx_out.recv().await.unwrap();
    assert_eq!(target_height, 1000);
    assert_eq!(block, Block{
        height: 701,
        hash: BlockHash::from_byte_array([0x33; 32]),
        prev_hash: BlockHash::from_byte_array([0x22; 32]),
        transactions: vec![],
    });
    let (target_height, block) = rx_out.recv().await.unwrap();
    assert_eq!(target_height, 1000);
    assert_eq!(block, Block{
        height: 702,
        hash: BlockHash::from_byte_array([0x44; 32]),
        prev_hash: BlockHash::from_byte_array([0x33; 32]),
        transactions: vec![],
    });

    assert!(!orderer.is_finished());
    cancel_token.cancel();
    let _ = orderer.await;

    Ok(())
}
