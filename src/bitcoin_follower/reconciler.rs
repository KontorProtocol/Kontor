use std::time::Duration;

use anyhow::{Result, anyhow};
use bitcoin::{BlockHash, Transaction, Txid};
use indexmap::{IndexMap, IndexSet, map::Entry};
use tokio::{
    select,
    sync::mpsc::{self, Receiver, Sender, UnboundedSender},
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

            sleep(Duration::from_secs(10)).await;
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
        Event::MempoolUpdates {
            removed,
            added: vec![],
        },
        Event::Block(block),
    ]
}

#[derive(Clone)]
enum Mode {
    Zmq,
    Rpc,
}

pub fn handle_new_mempool_transactions<T: Tx>(
    initial_mempool_txids: &mut IndexSet<Txid>,
    mempool_cache: &mut IndexMap<Txid, T>,
    txs: Vec<T>,
) -> Event<T> {
    let new_mempool_cache: IndexMap<Txid, T> = txs.into_iter().map(|t| (t.txid(), t)).collect();
    let new_mempool_cache_txids: IndexSet<Txid> = new_mempool_cache.keys().cloned().collect();
    let removed_from_initial: IndexSet<Txid> = initial_mempool_txids
        .difference(&new_mempool_cache_txids)
        .cloned()
        .collect();
    let mempool_cache_txids: IndexSet<Txid> = mempool_cache.keys().cloned().collect();
    let removed: Vec<Txid> = removed_from_initial
        .union(
            &mempool_cache_txids
                .difference(&new_mempool_cache_txids)
                .cloned()
                .collect::<IndexSet<Txid>>(),
        )
        .cloned()
        .collect();
    let added: Vec<T> = new_mempool_cache_txids
        .difference(
            &initial_mempool_txids
                .union(&mempool_cache_txids)
                .cloned()
                .collect::<IndexSet<Txid>>(),
        )
        .map(|txid| {
            new_mempool_cache
                .get(txid)
                .expect("Txid should exist")
                .clone()
        })
        .collect();

    // After being taken into account, reset initial mempool txids so they are not referenced again
    *initial_mempool_txids = IndexSet::new();

    *mempool_cache = new_mempool_cache;
    Event::MempoolUpdates { removed, added }
}

pub async fn get_last_matching_block_height<T: Tx>(
    cancel_token: CancellationToken,
    reader: &database::Reader,
    bitcoin: &bitcoin_client::Client,
    block: &Block<T>,
) -> u64 {
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
            "get block at height",
            new_backoff_unlimited(),
            cancel_token.clone(),
        )
        .await
        .expect("Block at height below new block should exist in database");

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
        .await
        .expect("Block hash should be returned by bitcoin");
    }

    block.height - subtrahend
}

pub async fn run<T: Tx + 'static>(
    config: Config,
    cancel_token: CancellationToken,
    reader: database::Reader,
    bitcoin: bitcoin_client::Client,
    mut initial_mempool_txids: IndexSet<Txid>,
    f: fn(Transaction) -> T,
    tx: Sender<Event<T>>,
) -> Result<JoinHandle<()>> {
    let (zmq_tx, mut zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<T>>();
    let (rpc_tx, mut rpc_rx) = mpsc::channel(10);
    let runner_cancel_token = CancellationToken::new();
    let runner_handle = zmq_runner(
        config.clone(),
        runner_cancel_token.clone(),
        bitcoin.clone(),
        f,
        zmq_tx,
    )
    .await;

    info!(
        "Initializing reconciler with mempool cache: {}",
        initial_mempool_txids.len()
    );

    let mut fetcher = rpc::Fetcher::new(bitcoin.clone(), f, rpc_tx);

    let start_height = reader
        .get_block_latest()
        .await?
        .map(|block_row| block_row.height)
        .unwrap_or(config.starting_block_height - 1)
        + 1;

    Ok(tokio::spawn(async move {
        let handle_zmq_event = async |reader: &database::Reader,
                                      initial_mempool_txids: &mut IndexSet<Txid>,
                                      mode: &mut Mode,
                                      connected: &mut bool,
                                      fetcher: &mut rpc::Fetcher<T>,
                                      mempool_cache: &mut IndexMap<Txid, T>,
                                      start_height: u64,
                                      rpc_latest_block: &Option<(u64, BlockHash)>,
                                      latest_block: &mut Option<(u64, BlockHash)>,
                                      zmq_event: ZmqEvent<T>|
               -> Vec<Event<T>> {
            let events = match zmq_event {
                ZmqEvent::Connected => {
                    info!(
                        "Connected to Bitcoin ZMQ @ {}",
                        config.zmq_pub_sequence_address
                    );
                    *connected = true;
                    vec![]
                }
                ZmqEvent::Disconnected(e) => {
                    error!("ZMQ disconnected: {}", e);
                    *connected = false;
                    if let Mode::Zmq = mode {
                        *mode = Mode::Rpc;
                        let height = if let Some((height, _)) = latest_block {
                            *height + 1
                        } else if let Some((height, _)) = rpc_latest_block {
                            height + 1
                        } else {
                            start_height
                        };
                        fetcher.start(height);
                    }
                    vec![]
                }
                ZmqEvent::MempoolTransactions(txs) => {
                    vec![handle_new_mempool_transactions(
                        initial_mempool_txids,
                        mempool_cache,
                        txs,
                    )]
                }
                ZmqEvent::MempoolTransactionAdded(t) => {
                    let txid = t.txid();
                    if let Entry::Vacant(_) = mempool_cache.entry(txid) {
                        mempool_cache.insert(txid, t.clone());
                        vec![Event::MempoolUpdates {
                            removed: vec![],
                            added: vec![t],
                        }]
                    } else {
                        vec![]
                    }
                }
                ZmqEvent::MempoolTransactionRemoved(txid) => {
                    if mempool_cache.shift_remove(&txid).is_some() {
                        vec![Event::MempoolUpdates {
                            removed: vec![txid],
                            added: vec![],
                        }]
                    } else {
                        vec![]
                    }
                }
                ZmqEvent::BlockDisconnected(block_hash) => {
                    if let Mode::Zmq = mode {
                        let block_row = retry(
                            async || match reader.get_block_with_hash(&block_hash).await {
                                Ok(Some(row)) => Ok(row),
                                Ok(None) => {
                                    Err(anyhow!("Block with hash not found: {}", &block_hash))
                                }
                                Err(e) => Err(e),
                            },
                            "get block with hash",
                            new_backoff_unlimited(),
                            cancel_token.clone(),
                        )
                        .await
                        .expect("Disconnect block should eventually exist in database");

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
                            cancel_token.clone(),
                        )
                        .await
                        .expect(
                            "Block at height below disconnected block should exist in database",
                        );

                        *latest_block = Some((prev_block_row.height, prev_block_row.hash));
                        vec![Event::Rollback(prev_block_row.height)]
                    } else {
                        *latest_block = None;
                        vec![]
                    }
                }
                ZmqEvent::BlockConnected(block) => {
                    *latest_block = Some((block.height, block.hash));
                    handle_block(mempool_cache, block)
                }
            };

            match mode {
                Mode::Zmq => events,
                Mode::Rpc => vec![],
            }
        };

        let handle_rpc_event = async |reader: &database::Reader,
                                      bitcoin: &bitcoin_client::Client,
                                      mode: &mut Mode,
                                      zmq_connected: &bool,
                                      fetcher: &mut rpc::Fetcher<T>,
                                      rpc_rx: &mut Receiver<(u64, Block<T>)>,
                                      mempool_cache: &mut IndexMap<Txid, T>,
                                      zmq_latest_block: &Option<(u64, BlockHash)>,
                                      rpc_latest_block: &mut Option<(u64, BlockHash)>,
                                      (target_height, block): (u64, Block<T>)|
               -> Vec<Event<T>> {
            if in_reorg_window(target_height, block.height, 20) {
                info!("In reorg window: {} {}", target_height, block.height);
                let last_matching_block_height =
                    get_last_matching_block_height(cancel_token.clone(), reader, bitcoin, &block)
                        .await;
                if last_matching_block_height != block.height - 1 {
                    warn!(
                        "Reorganization occured while RPC fetching: {}, {}",
                        block.height, last_matching_block_height
                    );
                    *rpc_latest_block = None;
                    if let Err(e) = fetcher.stop().await {
                        error!("Fetcher panicked on join: {}", e);
                    }
                    // drain receive channel
                    while !rpc_rx.is_empty() {
                        let _ = rpc_rx.recv().await;
                    }
                    fetcher.start(last_matching_block_height + 1);
                    return vec![Event::Rollback(last_matching_block_height)];
                }
            }

            *rpc_latest_block = Some((block.height, block.hash));

            (if match zmq_latest_block {
                Some((zmq_latest_block_height, zmq_latest_block_hash)) => {
                    *zmq_latest_block_height == block.height && *zmq_latest_block_hash == block.hash
                }
                None => target_height == block.height,
            } && *zmq_connected
            {
                info!("RPC caught up to ZMQ");
                *mode = Mode::Zmq;
                if let Err(e) = fetcher.stop().await {
                    error!("Fetcher panicked on join: {}", e);
                }
                // drain receive channel
                while !rpc_rx.is_empty() {
                    let _ = rpc_rx.recv().await;
                }

                vec![Event::MempoolUpdates {
                    removed: vec![],
                    added: mempool_cache.values().cloned().collect(),
                }]
            } else {
                vec![]
            })
            .into_iter()
            .chain(handle_block(mempool_cache, block))
            .collect()
        };

        fetcher.start(start_height);
        let mut mempool_cache = IndexMap::new();
        let mut zmq_latest_block = None;
        let mut rpc_latest_block = None;
        let mut zmq_connected = false;
        let mut mode = Mode::Rpc;
        'outer: loop {
            select! {
                option_zmq_event = zmq_rx.recv() => {
                    match option_zmq_event {
                        Some(zmq_event) => {
                            for event in handle_zmq_event(
                                &reader,
                                &mut initial_mempool_txids,
                                &mut mode,
                                &mut zmq_connected,
                                &mut fetcher,
                                &mut mempool_cache,
                                start_height,
                                &rpc_latest_block,
                                &mut zmq_latest_block,
                                zmq_event
                            ).await {
                                if tx.send(event).await.is_err() {
                                    info!("Send channel closed, exiting");
                                    break 'outer;
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
                            for event in handle_rpc_event(
                                &reader,
                                &bitcoin,
                                &mut mode,
                                &zmq_connected,
                                &mut fetcher,
                                &mut rpc_rx,
                                &mut mempool_cache,
                                &zmq_latest_block,
                                &mut rpc_latest_block,
                                rpc_event
                            ).await {
                                if tx.send(event).await.is_err() {
                                    info!("Send channel closed, exiting");
                                    break 'outer;
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
            error!("Panicked on join");
        }

        info!("Exited");
    }))
}
