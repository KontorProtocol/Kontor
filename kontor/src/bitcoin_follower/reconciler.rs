use std::time::Duration;

use anyhow::Result;
use bitcoin::{BlockHash, Transaction, Txid};
use indexmap::{IndexMap, IndexSet, map::Entry};
use libsql::Connection;
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
    bitcoin_follower::queries::{select_block_at_height, select_block_with_hash},
    bitcoin_follower::rpc,
    block::{Block, Tx},
    config::Config,
    database::{self, queries::select_block_latest},
    retry::{new_backoff_unlimited, retry},
};

use super::{
    events::{Event, ZmqEvent},
    zmq,
};

struct Env<T: Tx> {
    pub cancel_token: CancellationToken,
    pub config: Config,
    pub reader: database::Reader,
    pub bitcoin: bitcoin_client::Client,
    pub fetcher: rpc::Fetcher<T>,
    pub rpc_rx: Receiver<(u64, Block<T>)>,
    pub zmq_rx: UnboundedReceiver<ZmqEvent<T>>,
    pub zmq_tx: UnboundedSender<ZmqEvent<T>>,
}

impl<T: Tx + 'static> Env<T> {
    pub fn new(
        cancel_token: CancellationToken,
        config: Config,
        reader: database::Reader,
        bitcoin: bitcoin_client::Client,
        f: fn(Transaction) -> Option<T>,
    ) -> Self {
        let (zmq_tx, zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<T>>();
        let (rpc_tx, rpc_rx) = mpsc::channel(10);
        let fetcher = rpc::Fetcher::new(bitcoin.clone(), f, rpc_tx);
        Self {
            cancel_token,
            config,
            reader,
            bitcoin,
            fetcher,
            rpc_rx,
            zmq_rx,
            zmq_tx,
        }
    }
}

#[derive(Clone, PartialEq)]
enum Mode {
    Zmq,
    Rpc,
}

struct State<T: Tx> {
    mempool_cache: IndexMap<Txid, T>,
    zmq_latest_block_height: Option<u64>,
    rpc_latest_block_height: u64,
    zmq_connected: bool,
    mode: Mode,
}

impl<T: Tx> State<T> {
    pub fn new(start_height: u64) -> Self {
        Self {
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
    f: fn(Transaction) -> Option<T>,
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

pub async fn get_last_matching_block_height(
    cancel_token: CancellationToken,
    conn: &Connection,
    bitcoin: &bitcoin_client::Client,
    block_height: u64,
    block_prev_hash: BlockHash,
) -> Result<u64> {
    let mut prev_block_hash = block_prev_hash;
    let mut subtrahend = 1;
    loop {
        let prev_block_row =
            select_block_at_height(conn, block_height - subtrahend, cancel_token.clone()).await?;
        if prev_block_row.hash == prev_block_hash {
            break;
        }

        subtrahend += 1;

        prev_block_hash = retry(
            || bitcoin.get_block_hash(block_height - subtrahend),
            "get block hash",
            new_backoff_unlimited(),
            cancel_token.clone(),
        )
        .await?;
    }

    Ok(block_height - subtrahend)
}

async fn handle_zmq_event<T: Tx + 'static>(
    env: &mut Env<T>,
    state: &mut State<T>,
    zmq_event: ZmqEvent<T>,
) -> Result<Vec<Event<T>>> {
    let events = match zmq_event {
        ZmqEvent::Connected => {
            info!("ZMQ connected: {}", env.config.zmq_address);
            state.zmq_connected = true;
            let mut events = vec![];
            let conn = &*env.reader.connection().await?;
            if state.mode == Mode::Rpc {
                let info = retry(
                    || env.bitcoin.get_blockchain_info(),
                    "get blockchain info",
                    new_backoff_unlimited(),
                    env.cancel_token.clone(),
                )
                .await?;

                let option_block_row = select_block_latest(conn).await?;
                let caught_up = option_block_row
                    .as_ref()
                    .is_some_and(|b| b.height == info.blocks);

                // Program just started and is not caught up
                if !caught_up && !env.fetcher.running() {
                    env.fetcher.start(state.rpc_latest_block_height + 1);
                // Program just started and is already caught up
                } else if caught_up && !env.fetcher.running() {
                    let block_row = option_block_row
                        .expect("option_block_row is None despite caught_up being true");
                    let block_hash = retry(
                        || env.bitcoin.get_block_hash(block_row.height),
                        "get block hash",
                        new_backoff_unlimited(),
                        env.cancel_token.clone(),
                    )
                    .await?;

                    if block_row.hash == block_hash {
                        state.mode = Mode::Zmq;
                        events.push(Event::MempoolSet(
                            state.mempool_cache.values().cloned().collect(),
                        ))
                    } else {
                        let block = retry(
                            || env.bitcoin.get_block(&block_hash),
                            "get block hash",
                            new_backoff_unlimited(),
                            env.cancel_token.clone(),
                        )
                        .await?;
                        let last_matching_block_height = get_last_matching_block_height(
                            env.cancel_token.clone(),
                            conn,
                            &env.bitcoin,
                            block_row.height,
                            block.header.prev_blockhash,
                        )
                        .await?;

                        env.fetcher.start(last_matching_block_height + 1);
                        events.push(Event::Rollback(last_matching_block_height))
                    }
                // Program has recovered from ZMQ disconnect and no new blocks have arrrived in that time
                } else if caught_up && env.fetcher.running() {
                    if let Err(e) = env.fetcher.stop().await {
                        error!("Fetcher panicked on join: {}", e);
                    }
                    while !env.rpc_rx.is_empty() {
                        let _ = env.rpc_rx.recv().await;
                    }

                    state.mode = Mode::Zmq;

                    events.push(Event::MempoolSet(
                        state.mempool_cache.values().cloned().collect(),
                    ))
                }
            }

            events
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
                env.fetcher.start(height);
            }
            state.zmq_latest_block_height = None;
            while !env.zmq_rx.is_empty() {
                env.zmq_rx.recv().await;
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
            let conn = &*env.reader.connection().await?;
            if state.mode == Mode::Zmq {
                let block_row =
                    select_block_with_hash(conn, &block_hash, env.cancel_token.clone()).await?;
                let prev_block_row =
                    select_block_at_height(conn, block_row.height - 1, env.cancel_token.clone())
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
                handle_block(&mut state.mempool_cache, block.height, block)
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
    env: &mut Env<T>,
    state: &mut State<T>,
    (target_height, block): (u64, Block<T>),
) -> Result<Vec<Event<T>>> {
    if in_reorg_window(target_height, block.height, 20) {
        info!("In reorg window: {} {}", target_height, block.height);
        let last_matching_block_height = get_last_matching_block_height(
            env.cancel_token.clone(),
            &*env.reader.connection().await?,
            &env.bitcoin,
            block.height,
            block.prev_hash,
        )
        .await?;
        if last_matching_block_height != block.height - 1 {
            warn!(
                "Reorganization occured while RPC fetching: {}, {}",
                block.height, last_matching_block_height
            );
            if let Err(e) = env.fetcher.stop().await {
                error!("Fetcher panicked on join: {}", e);
            }
            while !env.rpc_rx.is_empty() {
                let _ = env.rpc_rx.recv().await;
            }
            env.fetcher.start(last_matching_block_height + 1);
            return Ok(vec![Event::Rollback(last_matching_block_height)]);
        }
    }

    state.rpc_latest_block_height = block.height;

    let mut events = handle_block(&mut state.mempool_cache, target_height, block);
    events[0] = Event::MempoolSet(vec![]);

    if state.zmq_connected && target_height == state.rpc_latest_block_height {
        let info = retry(
            || env.bitcoin.get_blockchain_info(),
            "get blockchain info",
            new_backoff_unlimited(),
            env.cancel_token.clone(),
        )
        .await?;
        if target_height == info.blocks {
            info!("RPC caught up: {}", target_height);

            state.mode = Mode::Zmq;

            if let Err(e) = env.fetcher.stop().await {
                error!("Fetcher panicked on join: {}", e);
            }
            while !env.rpc_rx.is_empty() {
                let _ = env.rpc_rx.recv().await;
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
    f: fn(Transaction) -> Option<T>,
    tx: Sender<Event<T>>,
) -> Result<JoinHandle<()>> {
    let mut env = Env::new(
        cancel_token.clone(),
        config.clone(),
        reader.clone(),
        bitcoin.clone(),
        f,
    );

    let start_height = select_block_latest(&*env.reader.connection().await?)
        .await?
        .map(|block_row| block_row.height)
        .unwrap_or(config.starting_block_height - 1)
        + 1;
    let mut state = State::new(start_height);

    let runner_cancel_token = CancellationToken::new();
    let runner_handle = zmq_runner(
        config.clone(),
        runner_cancel_token.clone(),
        bitcoin.clone(),
        f,
        env.zmq_tx.clone(),
    )
    .await;

    Ok(tokio::spawn(async move {
        'outer: loop {
            select! {
                option_zmq_event = env.zmq_rx.recv() => {
                    match option_zmq_event {
                        Some(zmq_event) => {
                            match handle_zmq_event(
                                &mut env,
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
                                    warn!("Handling zmq event resulted in error. Cancelling program and exiting: {}", e);
                                    cancel_token.cancel();
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
                option_rpc_event = env.rpc_rx.recv() => {
                    match option_rpc_event {
                        Some(rpc_event) => {
                            match handle_rpc_event(
                                &mut env,
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
                                    warn!("Handling rpc event resulted in error. Cancelling program and exiting: {}", e);
                                    cancel_token.cancel();
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
        env.rpc_rx.close();
        while env.rpc_rx.recv().await.is_some() {}
        match runner_handle.await {
            Err(_) => error!("ZMQ runner panicked on join"),
            Ok(Err(e)) => error!("ZMQ runner failed to start with error: {}", e),
            Ok(Ok(_)) => (),
        }
        if (env.fetcher.stop().await).is_err() {
            error!("RPC fetcher panicked on join");
        }

        info!("Exited");
    }))
}
