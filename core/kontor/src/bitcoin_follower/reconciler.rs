use anyhow::Result;
use bitcoin::{BlockHash, Txid};
use indexmap::{IndexMap, IndexSet, map::Entry};
use tokio::{
    select,
    sync::mpsc::{Receiver, Sender, UnboundedReceiver},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    bitcoin_follower::seek::SeekMessage,
    bitcoin_follower::{info::BlockchainInfo, rpc::BlockFetcher},
    block::{Block, Tx},
};

use super::events::{Event, ZmqEvent};

#[derive(Clone, Debug, PartialEq)]
pub enum Mode {
    Zmq,
    Rpc,
}

pub struct State<T: Tx> {
    mempool_cache: IndexMap<Txid, T>,
    pub latest_block_height: Option<u64>,
    pub target_block_height: Option<u64>,
    zmq_connected: bool,
    pub mode: Mode,
}

impl<T: Tx> State<T> {
    pub fn new() -> Self {
        Self {
            mempool_cache: IndexMap::new(),
            latest_block_height: None,
            target_block_height: None,
            zmq_connected: false,
            mode: Mode::Rpc,
        }
    }
}

pub struct Reconciler<T: Tx, I: BlockchainInfo, F: BlockFetcher> {
    pub cancel_token: CancellationToken,
    pub info: I,
    pub fetcher: F,
    pub rpc_rx: Receiver<(u64, Block<T>)>,
    pub zmq_rx: UnboundedReceiver<ZmqEvent<T>>,

    pub state: State<T>,
    event_tx: Option<Sender<Event<T>>>,
}

impl<T: Tx + 'static, I: BlockchainInfo, F: BlockFetcher> Reconciler<T, I, F> {
    pub fn new(
        cancel_token: CancellationToken,
        info: I,
        fetcher: F,
        rpc_rx: Receiver<(u64, Block<T>)>,
        zmq_rx: UnboundedReceiver<ZmqEvent<T>>,
    ) -> Self {
        let state = State::new();
        Self {
            cancel_token,
            info,
            fetcher,
            rpc_rx,
            zmq_rx,
            state,
            event_tx: None,
        }
    }

    async fn handle_zmq_event(&mut self, zmq_event: ZmqEvent<T>) -> Result<Vec<Event<T>>> {
        let events = match zmq_event {
            ZmqEvent::Connected => {
                info!("ZMQ connected");
                self.state.zmq_connected = true;

                let mut events = vec![];
                if self.state.mode == Mode::Rpc {
                    let caught_up = self.state.latest_block_height.is_some()
                        && self.state.target_block_height == self.state.latest_block_height;

                    // RPC fetching is caught up (or not necessary), switching to ZMQ
                    if caught_up {
                        if self.fetcher.running() {
                            self.stop_fetcher().await;
                        }

                        self.state.mode = Mode::Zmq;

                        events.push(Event::MempoolSet(
                            self.state.mempool_cache.values().cloned().collect(),
                        ))
                    }
                }

                events
            }
            ZmqEvent::Disconnected(e) => {
                error!("ZMQ disconnected: {}", e);
                self.state.zmq_connected = false;
                if self.state.mode == Mode::Zmq {
                    self.state.mode = Mode::Rpc;
                    let last_height = self
                        .state
                        .latest_block_height
                        .expect("must have start height before using ZMQ");
                    self.fetcher.start(last_height + 1);
                }
                while !self.zmq_rx.is_empty() {
                    self.zmq_rx.recv().await;
                }
                vec![]
            }
            ZmqEvent::MempoolTransactions(txs) => {
                vec![handle_new_mempool_transactions(
                    &mut self.state.mempool_cache,
                    txs,
                )]
            }
            ZmqEvent::MempoolTransactionAdded(t) => {
                let txid = t.txid();
                if let Entry::Vacant(_) = self.state.mempool_cache.entry(txid) {
                    self.state.mempool_cache.insert(txid, t.clone());
                    vec![Event::MempoolUpdate {
                        removed: vec![],
                        added: vec![t],
                    }]
                } else {
                    vec![]
                }
            }
            ZmqEvent::MempoolTransactionRemoved(txid) => {
                if self.state.mempool_cache.shift_remove(&txid).is_some() {
                    vec![Event::MempoolUpdate {
                        removed: vec![txid],
                        added: vec![],
                    }]
                } else {
                    vec![]
                }
            }
            ZmqEvent::BlockDisconnected(block_hash) => {
                if self.state.mode == Mode::Zmq {
                    vec![Event::RollbackHash(block_hash)]
                } else {
                    vec![]
                }
            }
            ZmqEvent::BlockConnected(block) => {
                if self.state.mode == Mode::Zmq {
                    let last_height = self
                        .state
                        .latest_block_height
                        .expect("must have start height before using ZMQ");
                    if block.height == last_height + 1 {
                        self.state.latest_block_height = Some(block.height);
                        handle_block(&mut self.state.mempool_cache, block.height, block)
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            }
        };

        Ok(match self.state.mode {
            Mode::Zmq => events,
            Mode::Rpc => vec![],
        })
    }

    async fn stop_fetcher(&mut self) {
        if let Err(e) = self.fetcher.stop().await {
            error!("Fetcher panicked on join: {}", e);
        }
        while !self.rpc_rx.is_empty() {
            let _ = self.rpc_rx.recv().await;
        }
    }

    async fn handle_rpc_event(
        &mut self,
        (target_height, block): (u64, Block<T>),
    ) -> Result<Vec<Event<T>>> {
        let height = block.height;
        self.state.latest_block_height = Some(height);

        match self.state.target_block_height {
            Some(target) => {
                if target < target_height {
                    self.state.target_block_height = Some(target_height);
                }
            }
            None => {
                self.state.target_block_height = Some(target_height);
            }
        }

        let mut events = handle_block(&mut self.state.mempool_cache, target_height, block);
        events[0] = Event::MempoolSet(vec![]);

        if self.state.zmq_connected && target_height == height {
            let blockchain_height = self.info.get_blockchain_height().await?;
            if target_height == blockchain_height {
                info!("RPC caught up: {}", target_height);

                self.state.mode = Mode::Zmq;
                self.stop_fetcher().await;

                events.push(Event::MempoolSet(
                    self.state.mempool_cache.values().cloned().collect(),
                ));
            }
        }

        Ok(events)
    }

    pub async fn seek(
        &mut self,
        start_height: u64,
        option_last_hash: Option<BlockHash>,
    ) -> Result<Vec<Event<T>>> {
        info!("Received Seek to height {}", start_height);

        // stop event handling and fetcher before (re)starting from new height
        if self.fetcher.running() {
            self.stop_fetcher().await;
        }

        // check if we need to roll back before we start fetching
        if let Some(last_hash) = option_last_hash {
            let block_hash = self
                .info
                .get_block_hash(start_height - 1)
                .await?;

            if last_hash != block_hash {
                warn!(
                    "Seek to height {} failed: hash of last block doesn't match \
                        (db {} != blockchain {})",
                    start_height, last_hash, block_hash
                );

                return Ok(vec![Event::Rollback(start_height - 2)]);
            }
        }

        let blockchain_height = self
            .info
            .get_blockchain_height()
            .await?;

        self.state.mode = Mode::Rpc;
        self.state.latest_block_height = Some(start_height - 1);

        // set initial target, may get pushed higher by RPC Fetcher events
        self.state.target_block_height = Some(blockchain_height);

        self.fetcher.start(start_height);

        Ok(vec![])
    }

    pub async fn handle_seek(&mut self, msg: SeekMessage<T>) -> Result<Vec<Event<T>>> {
        self.event_tx = Some(msg.event_tx);
        self.seek(msg.start_height, msg.last_hash).await
    }

    pub async fn run_event_loop(&mut self, mut ctrl_rx: Receiver<SeekMessage<T>>) {
        loop {
            let result = select! {
                option_seek = ctrl_rx.recv() => {
                    match option_seek {
                        Some(msg) => {
                            self.handle_seek(msg).await
                        },
                        None => {
                            info!("Received None seek message, exiting");
                            return;
                        }
                    }
                }
                 option_zmq_event = self.zmq_rx.recv() => {
                    match option_zmq_event {
                        Some(zmq_event) => {
                            self.handle_zmq_event(zmq_event) .await
                        },
                        None => {
                            // Occurs when runner fails to start up and drops channel sender
                            info!("Received None event from zmq, exiting");
                            return;
                        },
                    }
                }
                option_rpc_event = self.rpc_rx.recv() => {
                    match option_rpc_event {
                        Some(rpc_event) => {
                            self.handle_rpc_event(rpc_event).await
                        },
                        None => {
                            info!("Received None event from rpc, exiting");
                            return;
                        }
                    }
                }
                _ = self.cancel_token.cancelled() => {
                    info!("Cancelled");
                    return;
                }
            };

            match result {
                Ok(events) => {
                    if let Some(tx) = &self.event_tx {
                        for event in events {
                            if tx.send(event).await.is_err() {
                                info!("Send channel closed, exiting");
                                return;
                            }
                        }
                    } else {
                        warn!("Dropping events due to missing event channel");
                    }
                }
                Err(e) => {
                    warn!(
                        "Event handing resulted in error. Cancelling program and exiting: {}",
                        e
                    );
                    self.cancel_token.cancel();
                    return;
                }
            }
        }
    }

    pub async fn run(&mut self, ctrl_rx: Receiver<SeekMessage<T>>) {
        self.run_event_loop(ctrl_rx).await;

        self.stop_fetcher().await;
    }
}

fn handle_block<T: Tx>(
    mempool_cache: &mut IndexMap<Txid, T>,
    target_height: u64,
    block: Block<T>,
) -> Vec<Event<T>> {
    let mut removed = vec![];
    for t in block.transactions.iter() {
        let txid = t.txid();
        if mempool_cache.shift_remove(&txid).is_some() {
            removed.push(txid);
        }
    }
    vec![
        Event::MempoolUpdate {
            removed,
            added: vec![],
        },
        Event::Block((target_height, block)),
    ]
}

pub fn handle_new_mempool_transactions<T: Tx>(
    mempool_cache: &mut IndexMap<Txid, T>,
    txs: Vec<T>,
) -> Event<T> {
    let new_mempool_cache: IndexMap<Txid, T> = txs.into_iter().map(|t| (t.txid(), t)).collect();
    let new_mempool_cache_txids: IndexSet<Txid> = new_mempool_cache.keys().cloned().collect();
    let mempool_cache_txids: IndexSet<Txid> = mempool_cache.keys().cloned().collect();
    let removed: Vec<Txid> = mempool_cache_txids
        .difference(&new_mempool_cache_txids)
        .cloned()
        .collect();
    let added: Vec<T> = new_mempool_cache_txids
        .difference(&mempool_cache_txids)
        .map(|txid| {
            new_mempool_cache
                .get(txid)
                .expect("Txid should exist")
                .clone()
        })
        .collect();

    *mempool_cache = new_mempool_cache;
    Event::MempoolUpdate { removed, added }
}
