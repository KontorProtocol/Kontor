use std::time::Duration;

use anyhow::Result;
use bitcoin::{BlockHash, Transaction, Txid};
use futures_util::future::OptionFuture;
use indexmap::{IndexMap, IndexSet, map::Entry};
use tokio::{
    select,
    sync::mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    bitcoin_client::client::BitcoinRpc,
    bitcoin_follower::queries::{select_block_at_height, select_block_with_hash},
    bitcoin_follower::rpc,
    block::{Block, Tx},
    database,
    retry::{new_backoff_unlimited, retry},
};

use super::{
    events::{Event, Signal, ZmqEvent},
    zmq,
};

#[derive(Clone, Debug, PartialEq)]
pub enum Mode {
    Zmq,
    Rpc,
}

pub struct State<T: Tx> {
    mempool_cache: IndexMap<Txid, T>,
    zmq_latest_block_height: Option<u64>,
    pub rpc_latest_block_height: Option<u64>,
    pub target_block_height: Option<u64>,
    zmq_connected: bool,
    pub mode: Mode,
}

impl<T: Tx> State<T> {
    pub fn new() -> Self {
        Self {
            mempool_cache: IndexMap::new(),
            zmq_latest_block_height: None,
            rpc_latest_block_height: None,
            target_block_height: None,
            zmq_connected: false,
            mode: Mode::Rpc,
        }
    }
}

pub struct Reconciler<T: Tx, C: BitcoinRpc> {
    pub cancel_token: CancellationToken,
    pub reader: database::Reader,
    pub bitcoin: C,
    pub fetcher: rpc::Fetcher<T, C>,
    pub rpc_rx: Receiver<(u64, Block<T>)>,
    pub zmq_rx: UnboundedReceiver<ZmqEvent<T>>,
    pub zmq_tx: UnboundedSender<ZmqEvent<T>>,

    pub state: State<T>,
}

impl<T: Tx + 'static, C: BitcoinRpc> Reconciler<T, C> {
    pub fn new(
        cancel_token: CancellationToken,
        reader: database::Reader,
        bitcoin: C,
        f: fn(Transaction) -> Option<T>,
    ) -> Self {
        let (zmq_tx, zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<T>>();
        let (rpc_tx, rpc_rx) = mpsc::channel(10);
        let fetcher = rpc::Fetcher::new(bitcoin.clone(), f, rpc_tx);
        let state = State::new();
        Self {
            cancel_token,
            reader,
            bitcoin,
            fetcher,
            rpc_rx,
            zmq_rx,
            zmq_tx,
            state,
        }
    }

    async fn handle_zmq_event(&mut self, zmq_event: ZmqEvent<T>) -> Result<Vec<Event<T>>> {
        let events = match zmq_event {
            ZmqEvent::Connected => {
                info!("ZMQ connected");
                self.state.zmq_connected = true;

                let mut events = vec![];
                if self.state.mode == Mode::Rpc {
                    let caught_up = self.state.rpc_latest_block_height.is_some()
                        && self.state.target_block_height == self.state.rpc_latest_block_height;

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
                    let height = if let Some(height) = self.state.zmq_latest_block_height {
                        height + 1
                    } else {
                        let height = self
                            .state
                            .rpc_latest_block_height
                            .expect("must have start height before using ZMQ");
                        height + 1
                    };
                    self.fetcher.start(height);
                }
                self.state.zmq_latest_block_height = None;
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
                let conn = &*self.reader.connection().await?;
                if self.state.mode == Mode::Zmq {
                    let block_row =
                        select_block_with_hash(conn, &block_hash, self.cancel_token.clone())
                            .await?;
                    let prev_block_row = select_block_at_height(
                        conn,
                        block_row.height - 1,
                        self.cancel_token.clone(),
                    )
                    .await?;
                    self.state.zmq_latest_block_height = Some(prev_block_row.height);
                    vec![Event::Rollback(prev_block_row.height)]
                } else {
                    self.state.zmq_latest_block_height = None;
                    vec![]
                }
            }
            ZmqEvent::BlockConnected(block) => {
                let last_height = self
                    .state
                    .rpc_latest_block_height
                    .expect("must have start height before using ZMQ");
                if block.height > last_height {
                    self.state.zmq_latest_block_height = Some(block.height);
                    handle_block(&mut self.state.mempool_cache, block.height, block)
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
        self.state.rpc_latest_block_height = Some(height);

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
            let info = retry(
                || self.bitcoin.get_blockchain_info(),
                "get blockchain info",
                new_backoff_unlimited(),
                self.cancel_token.clone(),
            )
            .await?;
            if target_height == info.blocks {
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
            let block_hash = retry(
                || self.bitcoin.get_block_hash(start_height - 1),
                "get block hash",
                new_backoff_unlimited(),
                self.cancel_token.clone(),
            )
            .await
            .expect("failed to get block hash of previous block");

            if last_hash != block_hash {
                warn!(
                    "Seek to height {} failed: hash of last block doesn't match \
                        (db {} != blockchain {})",
                    start_height, last_hash, block_hash
                );

                return Ok(vec![Event::Rollback(start_height - 2)]);
            }
        }

        let info = retry(
            || self.bitcoin.get_blockchain_info(),
            "get blockchain info",
            new_backoff_unlimited(),
            self.cancel_token.clone(),
        )
        .await
        .expect("failed to get blockchain info");

        self.state.mode = Mode::Rpc;
        self.state.rpc_latest_block_height = Some(start_height - 1);

        // set initial target, may get pushed higher by RPC Fetcher events
        self.state.target_block_height = Some(info.blocks);

        self.fetcher.start(start_height);

        Ok(vec![])
    }

    pub async fn handle_control_signal(&mut self, signal: Signal) -> Result<Vec<Event<T>>> {
        match signal {
            Signal::Seek((start_height, option_last_hash)) => {
                self.seek(start_height, option_last_hash).await
            }
        }
    }

    pub async fn run_event_handler(&mut self, mut ctrl_rx: Receiver<Signal>, tx: Sender<Event<T>>) {
        loop {
            let result = select! {
                option_signal = ctrl_rx.recv() => {
                    match option_signal {
                        Some(signal) => {
                            self.handle_control_signal(signal).await
                        },
                        None => {
                            info!("Received None signal, exiting");
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
                    for event in events {
                        if tx.send(event).await.is_err() {
                            info!("Send channel closed, exiting");
                            return;
                        }
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
}

async fn zmq_runner<T: Tx + 'static, C: BitcoinRpc>(
    addr: String,
    cancel_token: CancellationToken,
    bitcoin: C,
    f: fn(Transaction) -> Option<T>,
    tx: UnboundedSender<ZmqEvent<T>>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            let handle =
                zmq::run(&addr, cancel_token.clone(), bitcoin.clone(), f, tx.clone()).await?;

            match handle.await {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => {
                    if tx.send(ZmqEvent::Disconnected(e)).is_err() {
                        return Ok(());
                    }
                }
                Err(e) => {
                    if tx.send(ZmqEvent::Disconnected(e.into())).is_err() {
                        return Ok(());
                    }
                }
            }

            info!("start sleep");
            select! {
                _ = sleep(Duration::from_secs(10)) => {}
                _ = cancel_token.cancelled() => {
                    return Ok(());
                }
            }

            info!("Restarting ZMQ listener");
        }
    })
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

pub async fn run<T: Tx + 'static, C: BitcoinRpc>(
    addr: Option<String>,
    cancel_token: CancellationToken,
    reader: database::Reader,
    bitcoin: C,
    f: fn(Transaction) -> Option<T>,
    ctrl_rx: Receiver<Signal>,
    tx: Sender<Event<T>>,
) -> Result<JoinHandle<()>> {
    let mut reconciler = Reconciler::new(cancel_token.clone(), reader.clone(), bitcoin.clone(), f);

    let runner_cancel_token = CancellationToken::new();
    let runner_handle = OptionFuture::from(addr.map(|a| {
        zmq_runner(
            a,
            runner_cancel_token.clone(),
            bitcoin.clone(),
            f,
            reconciler.zmq_tx.clone(),
        )
    }))
    .await;

    if runner_handle.is_none() {
        warn!("No ZMQ connection");
    }

    Ok(tokio::spawn(async move {
        reconciler.run_event_handler(ctrl_rx, tx).await;

        runner_cancel_token.cancel();

        reconciler.rpc_rx.close();
        while reconciler.rpc_rx.recv().await.is_some() {}

        if let Some(handle) = runner_handle {
            match handle.await {
                Err(_) => error!("ZMQ runner panicked on join"),
                Ok(Err(e)) => error!("ZMQ runner failed to start with error: {}", e),
                Ok(Ok(_)) => (),
            }
        }
        if (reconciler.fetcher.stop().await).is_err() {
            error!("RPC fetcher panicked on join");
        }

        info!("Exited");
    }))
}
