use std::time::Duration;

use anyhow::{Result, anyhow};
use bitcoin::{Transaction, Txid};
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
    bitcoin_client,
    bitcoin_follower::rpc,
    block::{Block, Tx},
    config::Config,
    database,
    retry::{new_backoff_unlimited, retry},
};

use super::{
    events::{Event, ZmqEvent},
    zmq,
};

#[derive(Clone, PartialEq)]
enum Mode {
    Zmq,
    Rpc,
}

struct State<T: Tx> {
    cancel_token: CancellationToken,
    mempool_cache: IndexMap<Txid, T>,
    zmq_latest_block_height: Option<u64>,
    rpc_latest_block_height: u64,
    zmq_connected: bool,
    mode: Mode,
}

impl<T: Tx> State<T> {
    pub fn new(cancel_token: CancellationToken, start_height: u64) -> Self {
        Self {
            cancel_token,
            mempool_cache: IndexMap::new(),
            zmq_latest_block_height: None,
            rpc_latest_block_height: start_height - 1,
            zmq_connected: false,
            mode: Mode::Rpc,
        }
    }
}

async fn zmq_runner<T: Tx + 'static>(
    config: Config,
    cancel_token: CancellationToken,
    bitcoin: bitcoin_client::Client,
    f: fn(Transaction) -> T,
    tx: UnboundedSender<ZmqEvent<T>>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            if cancel_token.is_cancelled() {
                return Ok(());
            }

            let handle = zmq::run(
                config.clone(),
                cancel_token.clone(),
                bitcoin.clone(),
                f,
                tx.clone(),
            )
            .await?;

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

            select! {
                _ = sleep(Duration::from_secs(10)) => {}
                _ = cancel_token.cancelled() => {}
            }

            info!("Restarting ZMQ listener");
        }
    })
}

fn in_reorg_window(target_height: u64, height: u64, reorg_window: u64) -> bool {
    height >= target_height - reorg_window
}

fn handle_block<T: Tx>(mempool_cache: &mut IndexMap<Txid, T>, block: Block<T>) -> Vec<Event<T>> {
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
        Event::Block(block),
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

pub async fn get_last_matching_block_height<T: Tx>(
    cancel_token: CancellationToken,
    reader: &database::Reader,
    bitcoin: &bitcoin_client::Client,
    block: &Block<T>,
) -> Result<u64> {
    let mut prev_block_hash = block.prev_hash;
    let mut subtrahend = 1;
    loop {
        let prev_block_row = retry(
            async || match reader.get_block_at_height(block.height - subtrahend).await {
                Ok(Some(row)) => Ok(row),
                Ok(None) => Err(anyhow!(
                    "Block at height not found: {}",
                    block.height - subtrahend
                )),
                Err(e) => Err(e),
            },
            "read block at height",
            new_backoff_unlimited(),
            cancel_token.clone(),
        )
        .await?;

        if prev_block_row.hash == prev_block_hash {
            break;
        }

        subtrahend += 1;

        prev_block_hash = retry(
            || bitcoin.get_block_hash(block.height - subtrahend),
            "get block hash",
            new_backoff_unlimited(),
            cancel_token.clone(),
        )
        .await?;
    }

    Ok(block.height - subtrahend)
}

async fn handle_zmq_event<T: Tx + 'static>(
    config: &Config,
    reader: &database::Reader,
    fetcher: &mut rpc::Fetcher<T>,
    rx: &mut UnboundedReceiver<ZmqEvent<T>>,
    state: &mut State<T>,
    zmq_event: ZmqEvent<T>,
) -> Result<Vec<Event<T>>> {
    let events = match zmq_event {
        ZmqEvent::Connected => {
            info!("ZMQ connected: {}", config.zmq_pub_sequence_address);
            state.zmq_connected = true;
            // At program start, only run the fetcher after zmq is connected
            if state.mode == Mode::Rpc && !fetcher.running() {
                fetcher.start(state.rpc_latest_block_height + 1);
            }
            vec![]
        }
        ZmqEvent::Disconnected(e) => {
            error!("ZMQ disconnected: {}", e);
            state.zmq_connected = false;
            if state.mode == Mode::Zmq {
                state.mode = Mode::Rpc;
                let height = if let Some(height) = state.zmq_latest_block_height {
                    height + 1
                } else {
                    state.rpc_latest_block_height + 1
                };
                fetcher.start(height);
            }
            state.zmq_latest_block_height = None;
            // Drain zmq event receiver
            while !rx.is_empty() {
                rx.recv().await;
            }
            vec![]
        }
        ZmqEvent::MempoolTransactions(txs) => {
            vec![handle_new_mempool_transactions(
                &mut state.mempool_cache,
                txs,
            )]
        }
        ZmqEvent::MempoolTransactionAdded(t) => {
            let txid = t.txid();
            if let Entry::Vacant(_) = state.mempool_cache.entry(txid) {
                state.mempool_cache.insert(txid, t.clone());
                vec![Event::MempoolUpdate {
                    removed: vec![],
                    added: vec![t],
                }]
            } else {
                vec![]
            }
        }
        ZmqEvent::MempoolTransactionRemoved(txid) => {
            if state.mempool_cache.shift_remove(&txid).is_some() {
                vec![Event::MempoolUpdate {
                    removed: vec![txid],
                    added: vec![],
                }]
            } else {
                vec![]
            }
        }
        ZmqEvent::BlockDisconnected(block_hash) => {
            if state.mode == Mode::Zmq {
                let block_row = retry(
                    async || match reader.get_block_with_hash(&block_hash).await {
                        Ok(Some(row)) => Ok(row),
                        Ok(None) => Err(anyhow!("Block with hash not found: {}", &block_hash)),
                        Err(e) => Err(e),
                    },
                    "get block with hash",
                    new_backoff_unlimited(),
                    state.cancel_token.clone(),
                )
                .await?;

                let prev_block_row = retry(
                    async || match reader.get_block_at_height(block_row.height - 1).await {
                        Ok(Some(row)) => Ok(row),
                        Ok(None) => Err(anyhow!(
                            "Block at height not found: {}",
                            block_row.height - 1
                        )),
                        Err(e) => Err(e),
                    },
                    "get block at height",
                    new_backoff_unlimited(),
                    state.cancel_token.clone(),
                )
                .await?;

                state.zmq_latest_block_height = Some(prev_block_row.height);
                vec![Event::Rollback(prev_block_row.height)]
            } else {
                state.zmq_latest_block_height = None;
                vec![]
            }
        }
        ZmqEvent::BlockConnected(block) => {
            if block.height > state.rpc_latest_block_height {
                state.zmq_latest_block_height = Some(block.height);
                handle_block(&mut state.mempool_cache, block)
            } else {
                vec![]
            }
        }
    };

    Ok(match state.mode {
        Mode::Zmq => events,
        Mode::Rpc => vec![],
    })
}

async fn handle_rpc_event<T: Tx + 'static>(
    reader: &database::Reader,
    bitcoin: &bitcoin_client::Client,
    fetcher: &mut rpc::Fetcher<T>,
    rx: &mut Receiver<(u64, Block<T>)>,
    state: &mut State<T>,
    (target_height, block): (u64, Block<T>),
) -> Result<Vec<Event<T>>> {
    if in_reorg_window(target_height, block.height, 20) {
        info!("In reorg window: {} {}", target_height, block.height);
        let last_matching_block_height =
            get_last_matching_block_height(state.cancel_token.clone(), reader, bitcoin, &block)
                .await?;
        if last_matching_block_height != block.height - 1 {
            warn!(
                "Reorganization occured while RPC fetching: {}, {}",
                block.height, last_matching_block_height
            );
            if let Err(e) = fetcher.stop().await {
                error!("Fetcher panicked on join: {}", e);
            }
            // drain receive channel
            while !rx.is_empty() {
                let _ = rx.recv().await;
            }
            fetcher.start(last_matching_block_height + 1);
            return Ok(vec![Event::Rollback(last_matching_block_height)]);
        }
    }

    state.rpc_latest_block_height = block.height;

    let mut events = handle_block(&mut state.mempool_cache, block);
    events[0] = Event::MempoolSet(vec![]);

    if state.zmq_connected && target_height == state.rpc_latest_block_height {
        let info = retry(
            || bitcoin.get_blockchain_info(),
            "get blockchain info",
            new_backoff_unlimited(),
            state.cancel_token.clone(),
        )
        .await?;
        if target_height == info.blocks {
            info!("RPC caught up to ZMQ: {}", target_height);

            state.mode = Mode::Zmq;

            if let Err(e) = fetcher.stop().await {
                error!("Fetcher panicked on join: {}", e);
            }

            // drain receive channel
            while !rx.is_empty() {
                let _ = rx.recv().await;
            }

            events.push(Event::MempoolSet(
                state.mempool_cache.values().cloned().collect(),
            ));
        }
    }

    Ok(events)
}

pub async fn run<T: Tx + 'static>(
    config: Config,
    cancel_token: CancellationToken,
    reader: database::Reader,
    bitcoin: bitcoin_client::Client,
    f: fn(Transaction) -> T,
    tx: Sender<Event<T>>,
) -> Result<JoinHandle<()>> {
    let (zmq_tx, mut zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<T>>();
    let runner_cancel_token = CancellationToken::new();
    let runner_handle = zmq_runner(
        config.clone(),
        runner_cancel_token.clone(),
        bitcoin.clone(),
        f,
        zmq_tx,
    )
    .await;

    let (rpc_tx, mut rpc_rx) = mpsc::channel(10);
    let mut fetcher = rpc::Fetcher::new(bitcoin.clone(), f, rpc_tx);

    let start_height = reader
        .get_block_latest()
        .await?
        .map(|block_row| block_row.height)
        .unwrap_or(config.starting_block_height - 1)
        + 1;

    Ok(tokio::spawn(async move {
        let mut state = State::new(cancel_token.clone(), start_height);
        'outer: loop {
            select! {
                option_zmq_event = zmq_rx.recv() => {
                    match option_zmq_event {
                        Some(zmq_event) => {
                            match handle_zmq_event(
                                &config,
                                &reader,
                                &mut fetcher,
                                &mut zmq_rx,
                                &mut state,
                                zmq_event
                            )
                            .await {
                                Ok(events) => {
                                    for event in events {
                                        if tx.send(event).await.is_err() {
                                            info!("Send channel closed, exiting");
                                            break 'outer;
                                        }
                                    }
                                },
                                Err(e) => {
                                    warn!("Handling zmq event resulted in error implying cancellation, exiting: {}", e);
                                    break;
                                }
                            }
                        },
                        None => {
                            // Occurs when runner fails to start up and drops channel sender
                            info!("Received None event from zmq, exiting");
                            break;
                        },
                    }
                }
                option_rpc_event = rpc_rx.recv() => {
                    match option_rpc_event {
                        Some(rpc_event) => {
                            match handle_rpc_event(
                                &reader,
                                &bitcoin,
                                &mut fetcher,
                                &mut rpc_rx,
                                &mut state,
                                rpc_event
                            )
                            .await {
                                Ok(events) => {
                                    for event in events {
                                        if tx.send(event).await.is_err() {
                                            info!("Send channel closed, exiting");
                                            break 'outer;
                                        }
                                    }
                                },
                                Err(e) => {
                                    warn!("Handling rpc event resulted in error implying cancellation, exiting: {}", e);
                                    break;
                                }
                            }
                        },
                        None => {
                            info!("Received None event from rpc, exiting");
                            break;
                        }
                    }
                }
                _ = cancel_token.cancelled() => {
                    info!("Cancelled");
                    break;
                }
            }
        }

        runner_cancel_token.cancel();
        rpc_rx.close();
        while rpc_rx.recv().await.is_some() {}
        match runner_handle.await {
            Err(_) => error!("ZMQ runner panicked on join"),
            Ok(Err(e)) => error!("ZMQ runner failed to start with error: {}", e),
            Ok(Ok(_)) => (),
        }
        if (fetcher.stop().await).is_err() {
            error!("RPC fetcher panicked on join");
        }

        info!("Exited");
    }))
}
