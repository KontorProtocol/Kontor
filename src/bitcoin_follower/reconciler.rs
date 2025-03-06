use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    time::Duration,
};

use anyhow::{Result, anyhow};
use bitcoin::{BlockHash, Transaction, Txid};
use tokio::{
    select,
    sync::mpsc::{self, Receiver, UnboundedSender},
    task::JoinHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    bitcoin_client,
    bitcoin_follower::rpc::{self, BlockHeight, TargetBlockHeight},
    block::{Block, Tx},
    config::Config,
    database,
    retry::{new_backoff_unlimited, retry},
};

use super::{
    event::{Event, ZmqEvent},
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

fn in_reorg_window(
    target_height: TargetBlockHeight,
    height: BlockHeight,
    reorg_window: u64,
) -> bool {
    height >= target_height - reorg_window
}

fn handle_block<T: Tx>(mempool_cache: &mut HashMap<Txid, T>, block: Block<T>) -> Vec<Event<T>> {
    let mut removed = vec![];
    for t in block.transactions.iter() {
        let txid = t.txid();
        if mempool_cache.remove(&txid).is_some() {
            removed.push(txid);
        }
    }
    vec![
        Event::MempoolUpdates {
            added: vec![],
            removed,
        },
        Event::Block(block),
    ]
}

#[derive(Clone)]
enum Mode {
    Zmq,
    Rpc,
}

pub async fn run<T: Tx + 'static>(
    config: Config,
    cancel_token: CancellationToken,
    reader: database::Reader,
    bitcoin: bitcoin_client::Client,
    mut initial_mempool_txids: HashSet<Txid>,
    f: fn(Transaction) -> T,
    tx: UnboundedSender<Event<T>>,
) -> JoinHandle<()> {
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

    tokio::spawn(async move {
        let handle_zmq_event = async |reader: &database::Reader,
                                      initial_mempool_txids: &mut HashSet<Txid>,
                                      mode: &mut Mode,
                                      connected: &mut bool,
                                      fetcher: &mut rpc::Fetcher<T>,
                                      mempool_cache: &mut HashMap<Txid, T>,
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
                    let mut new_mempool_cache: HashMap<Txid, T> =
                        txs.into_iter().map(|t| (t.txid(), t)).collect();
                    let new_mempool_cache_txids: HashSet<Txid> =
                        new_mempool_cache.keys().cloned().collect();
                    let removed_from_initial: HashSet<Txid> = initial_mempool_txids
                        .difference(&new_mempool_cache_txids)
                        .cloned()
                        .collect();
                    let mempool_cache_txids: HashSet<Txid> =
                        mempool_cache.keys().cloned().collect();
                    let removed: Vec<Txid> = removed_from_initial
                        .union(
                            &mempool_cache_txids
                                .difference(&new_mempool_cache_txids)
                                .cloned()
                                .collect(),
                        )
                        .cloned()
                        .collect();
                    let added: Vec<T> = new_mempool_cache_txids
                        .difference(
                            &initial_mempool_txids
                                .union(&mempool_cache_txids)
                                .cloned()
                                .collect(),
                        )
                        .map(|txid| new_mempool_cache.remove(txid).expect("Txid should exist"))
                        .collect();

                    // After being taken into account, reset initial mempool txids so they are not referenced again
                    *initial_mempool_txids = HashSet::new();

                    *mempool_cache = new_mempool_cache;
                    vec![Event::MempoolUpdates { added, removed }]
                }
                ZmqEvent::MempoolTransactionAdded(t) => {
                    let txid = t.txid();
                    if let Entry::Vacant(_) = mempool_cache.entry(txid) {
                        mempool_cache.insert(txid, t.clone());
                        vec![Event::MempoolUpdates {
                            added: vec![t],
                            removed: vec![],
                        }]
                    } else {
                        vec![]
                    }
                }
                ZmqEvent::MempoolTransactionRemoved(txid) => {
                    if mempool_cache.remove(&txid).is_some() {
                        vec![Event::MempoolUpdates {
                            added: vec![],
                            removed: vec![txid],
                        }]
                    } else {
                        vec![]
                    }
                }
                ZmqEvent::BlockDisconnected(block_hash) => {
                    let block_row = retry(
                        async || match reader.get_block_with_hash(&block_hash).await {
                            Ok(Some(row)) => Ok(row),
                            Ok(None) => Err(anyhow!("Block with hash not found: {}", &block_hash)),
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
                    .expect("Block at height below disconnected block should exist in database");

                    *latest_block = Some((prev_block_row.height, prev_block_row.hash));

                    vec![Event::Rollback(prev_block_row.height)]
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
                                      rpc_rx: &mut Receiver<(TargetBlockHeight, Block<T>)>,
                                      mempool_cache: &mut HashMap<Txid, T>,
                                      zmq_latest_block: &Option<(u64, BlockHash)>,
                                      rpc_latest_block: &mut Option<(u64, BlockHash)>,
                                      (target_height, block): (u64, Block<T>)|
               -> Vec<Event<T>> {
            if in_reorg_window(target_height, block.height, 20) {
                info!("In reorg window: {} {}", target_height, block.height);
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

                if subtrahend > 1 {
                    warn!(
                        "Reorganization occured while RPC fetching: {}, {}",
                        block.height,
                        block.height - subtrahend
                    );
                    *rpc_latest_block = None;
                    let rollback_height = block.height - subtrahend;
                    if let Err(e) = fetcher.stop().await {
                        error!("Fetcher panicked on join: {}", e);
                    }
                    // drain receive channel
                    while !rpc_rx.is_empty() {
                        let _ = rpc_rx.recv().await;
                    }
                    fetcher.start(rollback_height + 1);
                    return vec![Event::Rollback(rollback_height)];
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
                    added: mempool_cache.values().cloned().collect(),
                    removed: vec![],
                }]
            } else {
                vec![]
            })
            .into_iter()
            .chain(handle_block(mempool_cache, block))
            .collect()
        };

        let start_height = 850000;
        fetcher.start(start_height);
        let mut mempool_cache = HashMap::new();
        let mut zmq_latest_block = None;
        let mut rpc_latest_block = None;
        let mut zmq_connected = false;
        let mut mode = Mode::Rpc;
        loop {
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
                                if tx.send(event).is_err() {
                                    info!("Send channel closed, exiting");
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
                                if tx.send(event).is_err() {
                                    info!("Send channel closed, exiting");
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
        match runner_handle.await {
            Err(_) => error!("ZMQ runner panicked on join"),
            Ok(Err(e)) => error!("ZMQ runner failed to start with error: {}", e),
            Ok(Ok(_)) => (),
        }
        if (fetcher.stop().await).is_err() {
            error!("RPC fetcher panicked on join");
        }

        info!("Exited");
    })
}
