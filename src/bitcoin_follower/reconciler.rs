use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use anyhow::Result;
use bitcoin::{Block, BlockHash, Transaction, Txid};
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
    bitcoin_follower::{
        message::SequenceMessage,
        rpc::{self, BlockHeight, TargetBlockHeight},
    },
    config::Config,
    retry::{new_backoff_limited, retry},
};

use super::{
    event::{Event, ZmqEvent},
    zmq,
};

async fn zmq_runner(
    config: Config,
    cancel_token: CancellationToken,
    bitcoin: bitcoin_client::Client,
    tx: UnboundedSender<ZmqEvent>,
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

fn handle_block(mempool_cache: &mut HashSet<Txid>, block: Block) -> Vec<Event> {
    let mut removed = vec![];
    for t in block.txdata.iter() {
        let txid = t.compute_txid();
        if mempool_cache.remove(&txid) {
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

pub async fn run(
    config: Config,
    cancel_token: CancellationToken,
    bitcoin: bitcoin_client::Client,
    initial_mempool_cache: HashSet<Txid>,
    tx: UnboundedSender<Event>,
) -> JoinHandle<()> {
    let (zmq_tx, mut zmq_rx) = mpsc::unbounded_channel::<ZmqEvent>();
    let (rpc_tx, mut rpc_rx) = mpsc::channel(10);
    let runner_cancel_token = CancellationToken::new();
    let runner_handle = zmq_runner(
        config.clone(),
        runner_cancel_token.clone(),
        bitcoin.clone(),
        zmq_tx,
    )
    .await;

    info!(
        "Initializing reconciler with mempool cache: {}",
        initial_mempool_cache.len()
    );

    let mut fetcher = rpc::Fetcher::new(bitcoin.clone(), rpc_tx);

    tokio::spawn(async move {
        let handle_zmq_event = async |mode: &mut Mode,
                                      connected: &mut bool,
                                      fetcher: &mut rpc::Fetcher,
                                      mempool_cache: &mut HashSet<Txid>,
                                      start_height: u64,
                                      rpc_latest_block: &Option<(u64, BlockHash)>,
                                      latest_block: &mut Option<(u64, BlockHash)>,
                                      event: ZmqEvent|
               -> Vec<Event> {
            match event {
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
                        fetcher.start(if let Some((height, _)) = latest_block {
                            *height + 1
                        } else if let Some((height, _)) = rpc_latest_block {
                            height + 1
                        } else {
                            start_height
                        });
                    }
                    vec![]
                }
                ZmqEvent::MempoolTransactions(txs) => {
                    let mut txid_to_transaction: HashMap<Txid, Transaction> =
                        txs.into_iter().map(|tx| (tx.compute_txid(), tx)).collect();
                    let txids: HashSet<Txid> = txid_to_transaction.keys().cloned().collect();
                    let removed: Vec<Txid> = mempool_cache.difference(&txids).cloned().collect();
                    let added: Vec<Transaction> = txids
                        .difference(mempool_cache)
                        .map(|txid| txid_to_transaction.remove(txid).expect("Txid should exist"))
                        .collect();
                    *mempool_cache = txids;
                    vec![Event::MempoolUpdates { added, removed }]
                }
                ZmqEvent::SequenceMessage(SequenceMessage::TransactionAdded { txid, .. }) => {
                    if mempool_cache.insert(txid) {
                        match retry(
                            || bitcoin.get_raw_transaction(&txid),
                            "get raw transaction",
                            new_backoff_limited(),
                            cancel_token.clone(),
                        )
                        .await
                        {
                            Ok(t) => vec![Event::MempoolUpdates {
                                added: vec![t],
                                removed: vec![],
                            }],
                            Err(e) => {
                                warn!(
                                    "Skipping adding mempool transaction due to get error: {}",
                                    e
                                );
                                vec![]
                            }
                        }
                    } else {
                        vec![]
                    }
                }
                ZmqEvent::SequenceMessage(SequenceMessage::TransactionRemoved { txid, .. }) => {
                    if mempool_cache.remove(&txid) {
                        vec![Event::MempoolUpdates {
                            added: vec![],
                            removed: vec![txid],
                        }]
                    } else {
                        vec![]
                    }
                }
                ZmqEvent::SequenceMessage(SequenceMessage::BlockDisconnected(block_hash)) => {
                    vec![Event::Rollback(block_hash)]
                }
                ZmqEvent::BlockConnected(block) => {
                    *latest_block = Some((block.bip34_block_height().unwrap(), block.block_hash()));
                    handle_block(mempool_cache, block)
                }
                _ => vec![],
            }
        };

        let handle_rpc_event =
            async |mode: &mut Mode,
                   zmq_connected: &bool,
                   fetcher: &mut rpc::Fetcher,
                   rpc_rx: &mut Receiver<(TargetBlockHeight, BlockHeight, BlockHash, Block)>,
                   mempool_cache: &mut HashSet<Txid>,
                   zmq_latest_block: &Option<(u64, BlockHash)>,
                   rpc_latest_block: &mut Option<(u64, BlockHash)>,
                   (target_height, height, block_hash, block): (
                TargetBlockHeight,
                BlockHeight,
                BlockHash,
                Block,
            )|
                   -> Vec<Event> {
                if in_reorg_window(target_height, height, 10) {
                    info!("In reorg window");
                }

                *rpc_latest_block = Some((height, block_hash));

                if match zmq_latest_block {
                    Some((zmq_latest_block_height, zmq_latest_block_hash)) => {
                        *zmq_latest_block_height == height && *zmq_latest_block_hash == block_hash
                    }
                    None => target_height == height,
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
                }

                handle_block(mempool_cache, block)
            };

        let start_height = 850000;
        fetcher.start(start_height);
        let mut mempool_cache = initial_mempool_cache;
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
