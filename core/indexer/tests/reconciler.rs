use anyhow::{Error, Result};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

use bitcoin::{self, BlockHash, hashes::Hash};

use indexer::{
    bitcoin_follower::{
        ctrl::CtrlChannel,
        events::{BlockId, Event, ZmqEvent},
        info,
        reconciler::{self},
        rpc,
    },
    block::{Block, Tx},
    test_utils::MockTransaction,
};

fn gen_block<T: Tx>(height: u64, hash: &BlockHash, prev_hash: &BlockHash) -> Block<T> {
    Block {
        height,
        hash: *hash,
        prev_hash: *prev_hash,
        transactions: vec![],
    }
}

fn gen_blocks<T: Tx>(start: u64, end: u64, prev_hash: BlockHash) -> Vec<Block<T>> {
    let mut blocks = vec![];
    let mut prev = prev_hash;

    for _i in start..end {
        let hash = BlockHash::from_byte_array([(_i + 1) as u8; 32]);
        let block = gen_block(_i + 1, &hash, &prev);
        blocks.push(block.clone());

        prev = hash;
    }

    blocks
}

fn new_block_chain<T: Tx>(n: u64) -> Vec<Block<T>> {
    gen_blocks(0, n, BlockHash::from_byte_array([0x00; 32]))
}

#[derive(Clone)]
struct MockInfo<T: Tx> {
    blocks: Vec<Block<T>>,
}

impl<T: Tx> MockInfo<T> {
    fn new(blocks: Vec<Block<T>>) -> Self {
        Self { blocks }
    }

    async fn get_blockchain_height(&self) -> Result<u64, Error> {
        Ok(self.blocks.len() as u64)
    }
}

impl<T: Tx> info::BlockchainInfo for MockInfo<T> {
    async fn get_blockchain_height(&self) -> Result<u64, Error> {
        self.get_blockchain_height().await
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        Ok(self.blocks[height as usize - 1].hash)
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

    fn start_height(&self) -> u64 {
        *self.height.lock().unwrap()
    }
}

impl rpc::BlockFetcher for MockFetcher {
    fn running(&self) -> bool {
        *self.running.lock().unwrap()
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

async fn await_running(fetcher: &MockFetcher) {
    loop {
        if *fetcher.running.lock().unwrap() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn await_stopped(fetcher: &MockFetcher) {
    loop {
        if !*fetcher.running.lock().unwrap() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn test_reconciler_switch_to_zmq_after_catchup() -> Result<()> {
    let cancel_token = CancellationToken::new();

    let mut blocks = new_block_chain(3);

    let info = MockInfo::new(blocks.clone());
    let (ctrl, ctrl_rx) = CtrlChannel::<MockTransaction>::create();

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

    let handle = tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    });

    assert!(zmq_tx.send(ZmqEvent::Connected).is_ok());

    let mut event_rx = ctrl.clone().start(2, None).await.unwrap();
    await_running(&fetcher).await;
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

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolSet(vec![]));
    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockInsert((3, blocks[2 - 1].clone())));

    assert!(
        rpc_tx
            .send((
                info.get_blockchain_height().await.unwrap(),
                blocks[3 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolSet(vec![]));
    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockInsert((3, blocks[3 - 1].clone())));
    await_stopped(&fetcher).await; // switched to ZMQ

    let more_blocks = gen_blocks(3, 5, blocks[3 - 1].hash);
    blocks.extend(more_blocks.iter().cloned());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[4 - 1].clone()))
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolSet(vec![]));
    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolRemove(vec![]));
    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockInsert((4, blocks[4 - 1].clone())));

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[5 - 1].clone()))
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolRemove(vec![]));
    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockInsert((5, blocks[5 - 1].clone())));

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn test_reconciler_zmq_rollback_message() -> Result<()> {
    let cancel_token = CancellationToken::new();

    let mut blocks = new_block_chain::<MockTransaction>(3);

    let info = MockInfo::new(blocks.clone());
    let (ctrl, ctrl_rx) = CtrlChannel::<MockTransaction>::create();

    let (_rpc_tx, rpc_rx) = mpsc::channel(10);
    let fetcher = MockFetcher::new();

    let (zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        info.clone(),
        fetcher.clone(),
        rpc_rx,
        zmq_rx,
    );

    let handle = tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    });

    let mut event_rx = ctrl
        .clone()
        .start(4, Some(blocks[3 - 1].hash))
        .await
        .unwrap();
    await_running(&fetcher).await;
    assert_eq!(fetcher.start_height(), 4);

    assert!(zmq_tx.send(ZmqEvent::Connected).is_ok());
    await_stopped(&fetcher).await; // switched to ZMQ

    let more_blocks = gen_blocks(3, 5, blocks[3 - 1].hash);
    blocks.extend(more_blocks.iter().cloned());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[4 - 1].clone()))
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolSet(vec![]));
    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolRemove(vec![]));
    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockInsert((4, blocks[4 - 1].clone())));

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockDisconnected(blocks[2 - 1].hash))
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockRemove(BlockId::Hash(blocks[2 - 1].hash)));

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}
