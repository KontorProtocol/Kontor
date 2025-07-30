use anyhow::{Result, bail};
use bitcoin::BlockHash;
use tokio::{
    select,
    sync::mpsc::{Receiver, Sender, UnboundedReceiver},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    bitcoin_follower::ctrl::StartMessage,
    bitcoin_follower::{info::BlockchainInfo, rpc::BlockFetcher, rpc::MempoolFetcher},
    block::{Block, Tx},
};

use super::events::{BlockId, Event, ZmqEvent};

#[derive(Clone, Debug, PartialEq)]
pub enum Mode {
    Zmq,
    Rpc,
}

pub struct State {
    pub latest_block_height: Option<u64>,
    pub target_block_height: Option<u64>,
    zmq_connected: bool,
    pub mode: Mode,
}

impl State {
    pub fn new() -> Self {
        Self {
            latest_block_height: None,
            target_block_height: None,
            zmq_connected: false,
            mode: Mode::Rpc,
        }
    }
}

pub struct Reconciler<T: Tx, I: BlockchainInfo, F: BlockFetcher, M: MempoolFetcher<T>> {
    pub cancel_token: CancellationToken,
    pub info: I,
    pub fetcher: F,
    pub mempool: M,
    pub rpc_rx: Receiver<(u64, Block<T>)>,
    pub zmq_rx: UnboundedReceiver<ZmqEvent<T>>,

    pub state: State,
    event_tx: Option<Sender<Event<T>>>,
}

impl<T: Tx + 'static, I: BlockchainInfo, F: BlockFetcher, M: MempoolFetcher<T>>
    Reconciler<T, I, F, M>
{
    pub fn new(
        cancel_token: CancellationToken,
        info: I,
        fetcher: F,
        mempool: M,
        rpc_rx: Receiver<(u64, Block<T>)>,
        zmq_rx: UnboundedReceiver<ZmqEvent<T>>,
    ) -> Self {
        let state = State::new();
        Self {
            cancel_token,
            info,
            fetcher,
            mempool,
            rpc_rx,
            zmq_rx,
            state,
            event_tx: None,
        }
    }

    pub async fn handle_zmq_event(&mut self, zmq_event: ZmqEvent<T>) -> Result<Vec<Event<T>>> {
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
                        let event = self.switch_to_zmq().await?;
                        events.push(event);
                    }
                }

                events
            }
            ZmqEvent::Disconnected(e) => {
                error!("ZMQ disconnected: {}", e);
                self.state.zmq_connected = false;
                if self.state.mode == Mode::Zmq {
                    self.state.mode = Mode::Rpc;
                    let Some(last_height) = self.state.latest_block_height else {
                        bail!("must have start height before using ZMQ");
                    };
                    self.fetcher.start(last_height + 1);
                }
                while !self.zmq_rx.is_empty() {
                    self.zmq_rx.recv().await;
                }
                vec![]
            }
            ZmqEvent::MempoolTransactionAdded(t) => {
                vec![Event::MempoolInsert(vec![t])]
            }
            ZmqEvent::MempoolTransactionRemoved(txid) => {
                vec![Event::MempoolRemove(vec![txid])]
            }
            ZmqEvent::BlockDisconnected(block_hash) => {
                if self.state.mode == Mode::Zmq {
                    vec![Event::BlockRemove(BlockId::Hash(block_hash))]
                } else {
                    vec![]
                }
            }
            ZmqEvent::BlockConnected(block) => {
                if self.state.mode == Mode::Zmq {
                    let Some(last_height) = self.state.latest_block_height else {
                        bail!("must have start height before using ZMQ");
                    };
                    if block.height == last_height + 1 {
                        self.state.latest_block_height = Some(block.height);
                        vec![Event::BlockInsert((block.height, block))]
                    } else {
                        warn!(
                            "ZMQ BlockConnected at unexpected height {}, last height was {}",
                            block.height, last_height
                        );
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
            error!("RPC Fetcher panicked on join: {}", e);
        }
        while !self.rpc_rx.is_empty() {
            let _ = self.rpc_rx.recv().await;
        }
    }

    pub async fn handle_rpc_event(
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

        let mut events = vec![Event::BlockInsert((target_height, block))];

        if self.state.zmq_connected && target_height == height {
            let blockchain_height = self.info.get_blockchain_height().await?;
            if target_height == blockchain_height {
                let event = self.switch_to_zmq().await?;
                events.push(event);
            }
        }

        Ok(events)
    }

    async fn switch_to_zmq(&mut self) -> Result<Event<T>> {
        let target_height = self.state.latest_block_height.unwrap();
        info!(
            "RPC Fetcher caught up to {}, switching to ZMQ",
            target_height
        );

        if self.fetcher.running() {
            self.stop_fetcher().await;
        }
        self.state.mode = Mode::Zmq;

        let txs = self.mempool.get_mempool().await?;
        Ok(Event::MempoolSet(txs))
    }

    pub async fn start(
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
            let block_hash = self.info.get_block_hash(start_height - 1).await?;

            if last_hash != block_hash {
                warn!(
                    "Seek to height {} failed: hash of last block doesn't match \
                        (db {} != blockchain {})",
                    start_height, last_hash, block_hash
                );

                return Ok(vec![Event::BlockRemove(BlockId::Height(start_height - 2))]);
            }
        }

        let blockchain_height = self.info.get_blockchain_height().await?;

        self.state.mode = Mode::Rpc;
        self.state.latest_block_height = Some(start_height - 1);

        // set initial target, may get pushed higher by RPC Fetcher events
        self.state.target_block_height = Some(blockchain_height);

        self.fetcher.start(start_height);

        Ok(vec![])
    }

    pub async fn handle_start(&mut self, msg: StartMessage<T>) -> Result<Vec<Event<T>>> {
        self.event_tx = Some(msg.event_tx);
        self.start(msg.start_height, msg.last_hash).await
    }

    pub async fn run_event_loop(&mut self, mut ctrl_rx: Receiver<StartMessage<T>>) {
        loop {
            let result = select! {
                option_start = ctrl_rx.recv() => {
                    match option_start {
                        Some(msg) => {
                            self.handle_start(msg).await
                        },
                        None => {
                            info!("Received None start message, exiting");
                            return;
                        }
                    }
                }
                 option_zmq_event = self.zmq_rx.recv() => {
                    match option_zmq_event {
                        Some(zmq_event) => {
                            self.handle_zmq_event(zmq_event).await
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
                                warn!("Dropping events due to stale event channel");
                            }
                        }
                    } else {
                        warn!("Dropping events due to missing event channel");
                    }
                }
                Err(e) => {
                    warn!(
                        "Event handling resulted in error. Cancelling program and exiting: {}",
                        e
                    );
                    self.cancel_token.cancel();
                    return;
                }
            }
        }
    }

    pub async fn run(&mut self, ctrl_rx: Receiver<StartMessage<T>>) {
        self.run_event_loop(ctrl_rx).await;

        self.stop_fetcher().await;
    }
}
