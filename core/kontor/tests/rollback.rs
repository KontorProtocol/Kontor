use anyhow::{Error, Result};
use clap::Parser;
use libsql::Connection;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use bitcoin::{self, BlockHash, hashes::Hash};

use kontor::{
    bitcoin_follower::{
        events::Event,
        events::{BlockId, ZmqEvent},
        info, reconciler, rpc,
        seek::{SeekChannel, SeekMessage},
    },
    block::{Block, Tx},
    config::Config,
    database::{queries, types::BlockRow},
    reactor,
    utils::{MockTransaction, new_test_db},
};

fn gen_block<T: Tx>(height: u64, hash: &BlockHash, prev_hash: &BlockHash) -> Block<T> {
    Block {
        height,
        hash: *hash,
        prev_hash: *prev_hash,
        transactions: vec![],
    }
}

fn gen_hashed_blocks<T: Tx>(
    start: u64,
    end: u64,
    prev_hash: BlockHash,
    hash_base: u8,
) -> Vec<Block<T>> {
    let mut blocks = vec![];
    let mut prev = prev_hash;

    for _i in start..end {
        let hash = BlockHash::from_byte_array([hash_base + (_i + 1) as u8; 32]);
        let block = gen_block(_i + 1, &hash, &prev);
        blocks.push(block.clone());

        prev = hash;
    }

    blocks
}

fn gen_blocks<T: Tx>(start: u64, end: u64, prev_hash: BlockHash) -> Vec<Block<T>> {
    gen_hashed_blocks(start, end, prev_hash, 0)
}

fn gen_fork<T: Tx>(start: u64, end: u64, prev_hash: BlockHash) -> Vec<Block<T>> {
    gen_hashed_blocks(start, end, prev_hash, 0x10)
}

fn new_block_chain<T: Tx>(n: u64) -> Vec<Block<T>> {
    gen_blocks(0, n, BlockHash::from_byte_array([0x00; 32]))
}

#[derive(Clone)]
struct MockInfo<T: Tx> {
    blocks: Arc<Mutex<Vec<Block<T>>>>,
}

impl<T: Tx> MockInfo<T> {
    fn new(blocks: Vec<Block<T>>) -> Self {
        Self {
            blocks: Mutex::new(blocks).into(),
        }
    }

    async fn get_blockchain_height(&self) -> Result<u64, Error> {
        Ok(self.blocks.lock().unwrap().len() as u64)
    }

    fn replace_blocks(&mut self, b: Vec<Block<T>>) {
        let mut blocks = self.blocks.lock().unwrap();
        *blocks = b;
    }
}

impl<T: Tx> info::BlockchainInfo for MockInfo<T> {
    async fn get_blockchain_height(&self) -> Result<u64, Error> {
        self.get_blockchain_height().await
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        Ok(self.blocks.lock().unwrap()[height as usize - 1].hash)
    }
}

#[derive(Clone)]
struct MockFetcher {
    height: Arc<Mutex<u64>>,
    running: Arc<Mutex<bool>>,
}

impl MockFetcher {
    fn new() -> Self {
        Self {
            height: Mutex::new(0).into(),
            running: Mutex::new(false).into(),
        }
    }

    fn running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    fn start_height(&self) -> u64 {
        *self.height.lock().unwrap()
    }

    async fn await_running(&self) {
        loop {
            if *self.running.lock().unwrap() {
                debug!("MockFetcher running");
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn await_stopped(&self) {
        loop {
            if !*self.running.lock().unwrap() {
                debug!("MockFetcher stopped");
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn await_start_height(&self, height: u64) {
        loop {
            if *self.height.lock().unwrap() == height {
                debug!("MockFetcher start_height == {}", height);
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
}

impl rpc::BlockFetcher for MockFetcher {
    fn running(&self) -> bool {
        self.running()
    }

    fn start(&mut self, start_height: u64) {
        let mut running = self.running.lock().unwrap();
        *running = true;

        let mut height = self.height.lock().unwrap();
        *height = start_height;
    }

    async fn stop(&mut self) -> Result<()> {
        let mut running = self.running.lock().unwrap();
        *running = false;
        Ok(())
    }
}

async fn await_block_at_height(conn: &Connection, height: u64) -> BlockRow {
    loop {
        match queries::select_block_at_height(conn, height).await {
            Ok(Some(row)) => return row,
            Ok(None) => {}
            Err(e) => panic!("error: {:?}", e),
        };
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn test_follower_reactor_fetching() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let blocks = new_block_chain(5);
    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[0]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2]).into())
            .await
            .is_ok()
    );

    let mut handles = vec![];

    let info = MockInfo::new(blocks.clone());
    let (ctrl, ctrl_rx) = SeekChannel::create();

    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let fetcher = MockFetcher::new();

    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        info.clone(),
        fetcher.clone(),
        rpc_rx,
        zmq_rx,
    );

    handles.push(tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    }));

    let start_height = 2; // will be overriden by stored blocks
    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    ));

    fetcher.await_running().await;

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[4 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[5 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash);

    let block = await_block_at_height(conn, 5).await;
    assert_eq!(block.height, 5);
    assert_eq!(block.hash, blocks[5 - 1].hash);

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

#[tokio::test]
async fn test_follower_reactor_rollback_during_seek() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let mut blocks = new_block_chain(3);
    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[1 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[3 - 1]).into())
            .await
            .is_ok()
    );

    let initial_block_3_hash = blocks[3 - 1].hash;

    // remove last block (height 3), generate 3 new blocks with different
    // timestamp (and thus hashes) and append them to the chain.
    _ = blocks.pop();
    let more_blocks = gen_fork(2, 5, blocks[2 - 1].hash);
    blocks.extend(more_blocks.iter().cloned());

    let mut handles = vec![];

    let info = MockInfo::new(blocks.clone());
    let (ctrl, ctrl_rx) = SeekChannel::create();

    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let fetcher = MockFetcher::new();

    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        info.clone(),
        fetcher.clone(),
        rpc_rx,
        zmq_rx,
    );

    handles.push(tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    }));

    let start_height = 1; // will be overriden by stored blocks
    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    ));

    fetcher.await_running().await;

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[3 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[4 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[5 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    // by reading out the two last blocks first we ensure that the rollback has been enacted
    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash);

    let block = await_block_at_height(conn, 5).await;
    assert_eq!(block.height, 5);
    assert_eq!(block.hash, blocks[5 - 1].hash);

    // reading block 3, verify that it was rolled back and hash has been updated
    let block = await_block_at_height(conn, 3).await;
    assert_eq!(block.height, 3);
    assert_eq!(block.hash, blocks[3 - 1].hash);
    assert_ne!(block.hash, initial_block_3_hash);

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

#[tokio::test]
async fn test_follower_reactor_rollback_during_catchup() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let mut blocks = new_block_chain(5);

    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[1 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2 - 1]).into())
            .await
            .is_ok()
    );

    let mut handles = vec![];

    let mut info = MockInfo::new(blocks.clone());
    let (ctrl, ctrl_rx) = SeekChannel::create();

    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let fetcher = MockFetcher::new();

    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        info.clone(),
        fetcher.clone(),
        rpc_rx,
        zmq_rx,
    );

    handles.push(tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    }));

    let start_height = 3;
    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    ));

    fetcher.await_running().await;

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[3 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[4 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let conn = &writer.connection();
    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash);

    // roll back all but the first block (height 1), generate new blocks with mismatching hashes
    blocks.truncate(1);
    let more_blocks = gen_fork(1, 5, blocks[1 - 1].hash);
    blocks.extend(more_blocks.iter().cloned());
    info.replace_blocks(blocks.clone());

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[5 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    // wait for fetcher to be rewinded to new start height
    fetcher.await_start_height(2).await;

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[2 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[3 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[4 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash); // matches new hash

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

#[tokio::test]
async fn test_follower_handle_control_signal() -> Result<()> {
    let cancel_token = CancellationToken::new();

    let blocks = new_block_chain::<MockTransaction>(5);

    let info = MockInfo::new(blocks.clone());

    // start-up at block height 3
    let (_rpc_tx, rpc_rx) = mpsc::channel(1);
    let fetcher = MockFetcher::new();

    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<MockTransaction>>();

    let mut rec =
        reconciler::Reconciler::new(cancel_token.clone(), info.clone(), fetcher, rpc_rx, zmq_rx);
    let (event_tx, _event_rx) = mpsc::channel(1);
    let res = rec
        .handle_seek(SeekMessage {
            start_height: 3,
            last_hash: None,
            event_tx,
        })
        .await
        .unwrap();
    assert_eq!(res, vec![]);
    assert_eq!(rec.state.latest_block_height, Some(2));
    assert_eq!(rec.state.target_block_height, Some(5));
    assert_eq!(rec.state.mode, reconciler::Mode::Rpc);
    assert!(rec.fetcher.running());

    // start-up at block height 3 with mismatching hash for last block at 2
    let (_rpc_tx, rpc_rx) = mpsc::channel(1);
    let fetcher = MockFetcher::new();
    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<MockTransaction>>();
    let mut rec =
        reconciler::Reconciler::new(cancel_token.clone(), info.clone(), fetcher, rpc_rx, zmq_rx);
    let (event_tx, _event_rx) = mpsc::channel(1);
    let res = rec
        .handle_seek(SeekMessage {
            start_height: 3,
            last_hash: Some(BlockHash::from_byte_array([0x00; 32])), // not matching
            event_tx,
        })
        .await
        .unwrap();
    assert_eq!(res, vec![Event::Rollback(BlockId::Height(1))]);
    assert!(!rec.fetcher.running());

    // start-up at block height 3 with matching hash for last block at 2
    let (_rpc_tx, rpc_rx) = mpsc::channel(1);
    let fetcher = MockFetcher::new();
    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<MockTransaction>>();
    let mut rec =
        reconciler::Reconciler::new(cancel_token.clone(), info.clone(), fetcher, rpc_rx, zmq_rx);
    let (event_tx, _event_rx) = mpsc::channel(1);
    let res = rec
        .handle_seek(SeekMessage {
            start_height: 3,
            last_hash: Some(blocks[2 - 1].hash),
            event_tx,
        })
        .await
        .unwrap();
    assert_eq!(res, vec![]);
    assert_eq!(rec.state.latest_block_height, Some(2));
    assert_eq!(rec.state.target_block_height, Some(5));
    assert_eq!(rec.state.mode, reconciler::Mode::Rpc);
    assert!(rec.fetcher.running());

    Ok(())
}

#[tokio::test]
// test_follower_reactor_rollback_zmq_message_multiple_blocks tests handling of a ZMQ
// BlockDisconnected message several blocks deep. The system should purge the blocks
// down to it and start fetching new blocks from that height.
async fn test_follower_reactor_rollback_zmq_message_multiple_blocks() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let mut blocks = new_block_chain(2);

    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[1 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2 - 1]).into())
            .await
            .is_ok()
    );

    let mut handles = vec![];

    let mut info = MockInfo::new(blocks.clone());
    let (ctrl, ctrl_rx) = SeekChannel::create();

    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let fetcher = MockFetcher::new();

    let (zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        info.clone(),
        fetcher.clone(),
        rpc_rx,
        zmq_rx,
    );

    handles.push(tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    }));

    let start_height = 3;
    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    ));

    fetcher.await_running().await;

    assert!(zmq_tx.send(ZmqEvent::Connected).is_ok());

    fetcher.await_stopped().await;

    // add more blocks
    blocks.extend(gen_blocks(2, 5, blocks[2 - 1].hash).iter().cloned());
    info.replace_blocks(blocks.clone());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[3 - 1].clone()))
            .is_ok()
    );

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[4 - 1].clone()))
            .is_ok()
    );

    let conn = &writer.connection();
    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash);

    let initial_block_2_hash = blocks[2 - 1].hash;

    // roll back all but the first block (height 1), generate new blocks with mismatching hashes
    blocks.truncate(1);
    let more_blocks = gen_fork(1, 5, blocks[1 - 1].hash);
    blocks.extend(more_blocks.iter().cloned());
    info.replace_blocks(blocks.clone());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockDisconnected(initial_block_2_hash))
            .is_ok()
    );

    fetcher.await_running().await;
    assert_eq!(fetcher.start_height(), 2);

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[2 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let block = await_block_at_height(conn, 2).await;
    assert_eq!(block.height, 2);
    assert_eq!(block.hash, blocks[2 - 1].hash); // matches new hash

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

#[tokio::test]
// test_follower_reactor_rollback_zmq_message_redundant_messages tests handling of multiple
// ZMQ BlockDisconnected messages, including a redundant message for a block that was already
// removed.
async fn test_follower_reactor_rollback_zmq_message_redundant_messages() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let mut blocks = new_block_chain(2);

    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[1 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2 - 1]).into())
            .await
            .is_ok()
    );

    let mut handles = vec![];

    let mut info = MockInfo::new(blocks.clone());
    let (ctrl, ctrl_rx) = SeekChannel::create();

    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let fetcher = MockFetcher::new();

    let (zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        info.clone(),
        fetcher.clone(),
        rpc_rx,
        zmq_rx,
    );

    handles.push(tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    }));

    let start_height = 3;
    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    ));

    fetcher.await_running().await;

    assert!(zmq_tx.send(ZmqEvent::Connected).is_ok());

    fetcher.await_stopped().await;

    // add one more block
    blocks.extend(gen_blocks(2, 3, blocks[2 - 1].hash).iter().cloned());
    info.replace_blocks(blocks.clone());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[3 - 1].clone()))
            .is_ok()
    );

    let conn = &writer.connection();
    let block = await_block_at_height(conn, 3).await;
    assert_eq!(block.height, 3);
    assert_eq!(block.hash, blocks[3 - 1].hash);

    let initial_block_2_hash = blocks[2 - 1].hash;
    let initial_block_3_hash = blocks[3 - 1].hash;

    // roll back all but the first block (height 1), generate new blocks with mismatching hashes
    blocks.truncate(1);
    let more_blocks = gen_fork(1, 3, blocks[1 - 1].hash);
    blocks.extend(more_blocks.iter().cloned());
    info.replace_blocks(blocks.clone());

    let unknown_hash = BlockHash::from_byte_array([0xff; 32]);
    assert!(
        zmq_tx
            .send(ZmqEvent::BlockDisconnected(unknown_hash))
            .is_ok()
    );

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockDisconnected(initial_block_2_hash))
            .is_ok()
    );

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockDisconnected(initial_block_3_hash))
            .is_ok()
    );

    fetcher.await_running().await;
    assert_eq!(fetcher.start_height(), 2);

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[2 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[3 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let block = await_block_at_height(conn, 2).await;
    assert_eq!(block.height, 2);
    assert_eq!(block.hash, blocks[2 - 1].hash); // matches new hash

    fetcher.await_stopped().await;

    // add one more block
    blocks.extend(gen_blocks(4 - 1, 5 - 1, blocks[3 - 1].hash).iter().cloned());
    info.replace_blocks(blocks.clone());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[4 - 1].clone()))
            .is_ok()
    );

    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash);

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
