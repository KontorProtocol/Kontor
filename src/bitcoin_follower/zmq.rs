use std::thread;

use anyhow::{Context, Result, anyhow};
use bitcoin::Transaction;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use scopeguard::defer;
use tokio::{
    select,
    sync::mpsc::{self, UnboundedSender},
    task::{self, JoinHandle},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use zmq::Socket;

use crate::{
    bitcoin_client,
    bitcoin_follower::messages::SEQUENCE,
    block::{Block, Tx},
    config::Config,
    retry::{new_backoff_limited, new_backoff_unlimited, retry},
};

use super::{
    events::ZmqEvent,
    messages::{MonitorMessage, SequenceMessage},
};

fn run_monitor_socket(
    socket: Socket,
    cancel_token: CancellationToken,
    tx: UnboundedSender<Result<MonitorMessage>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if cancel_token.is_cancelled() {
                info!("Cancelling monitor socket thread");
                break;
            }

            match socket.recv_multipart(0) {
                Ok(multipart) => {
                    if tx
                        .send(MonitorMessage::from_zmq_message(multipart))
                        .is_err()
                    {
                        info!("Send channel is closed, exiting monitor socket thread");
                        break;
                    }
                }
                Err(zmq::Error::EAGAIN) => {
                    continue;
                }
                Err(e) => {
                    if tx.send(Err(e.into())).is_err() {
                        info!("Send channel is closed, exiting monitor socket thread");
                        break;
                    }
                }
            }
        }

        info!("Monitor socket thread exited");
    })
}

fn run_socket(
    socket: Socket,
    cancel_token: CancellationToken,
    tx: UnboundedSender<Result<(u32, SequenceMessage)>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if cancel_token.is_cancelled() {
                info!("Cancelling socket thread");
                break;
            }

            match socket.recv_multipart(0) {
                Ok(zmq_message) => {
                    if tx
                        .send(SequenceMessage::from_zmq_message(zmq_message))
                        .is_err()
                    {
                        info!("Send channel is closed, exiting socket thread");
                        break;
                    }
                }
                Err(zmq::Error::EAGAIN) => {
                    continue;
                }
                Err(e) => {
                    if tx.send(Err(e.into())).is_err() {
                        info!("Send channel is closed, exiting socket thread");
                        break;
                    }
                }
            }
        }

        info!("Socket thread exited");
    })
}

pub async fn run<T: Tx + 'static>(
    config: Config,
    cancel_token: CancellationToken,
    bitcoin: bitcoin_client::Client,
    f: fn(Transaction) -> T,
    tx: UnboundedSender<ZmqEvent<T>>,
) -> Result<JoinHandle<Result<()>>> {
    let (socket_tx, mut socket_rx) = mpsc::unbounded_channel();
    let (monitor_tx, mut monitor_rx) = mpsc::unbounded_channel();
    let socket_cancel_token = CancellationToken::new();
    let ctx = zmq::Context::new();
    let socket = ctx
        .socket(zmq::SUB)
        .context("Failed to create ZMQ socket")?;
    socket.set_subscribe(SEQUENCE.as_bytes())?;
    socket.set_rcvhwm(0)?;
    socket.set_rcvtimeo(1000)?;

    let monitor_endpoint = format!("inproc://{}-monitor", SEQUENCE);
    socket
        .monitor(&monitor_endpoint, MonitorMessage::all_events_mask())
        .context("Failed to set up socket monitor")?;
    let monitor_socket = ctx
        .socket(zmq::PAIR)
        .context("Failed to create monitor socket")?;
    monitor_socket
        .connect(&monitor_endpoint)
        .context("Failed to connect monitor socket")?;
    monitor_socket.set_rcvhwm(0)?;
    monitor_socket.set_rcvtimeo(1000)?;
    let monitor_socket_handle =
        run_monitor_socket(monitor_socket, socket_cancel_token.clone(), monitor_tx);

    socket
        .connect(&config.zmq_pub_sequence_address)
        .context("Could not connect to ZMQ address")?;
    let socket_handle = run_socket(socket, socket_cancel_token.clone(), socket_tx.clone());

    Ok(task::spawn(async move {
        defer! {
            socket_cancel_token.cancel();
            if socket_handle.join().is_err() {
                error!("Socket thread panicked on join");
            }
            if monitor_socket_handle.join().is_err() {
                error!("Monitor socket thread panicked on join");
            }

            info!("Exited");
        }

        let mut last_sequence_number: Option<u32> = None;
        loop {
            select! {
                biased;
                _ = cancel_token.cancelled() => {
                    info!("Cancelled");
                    return Ok(())
                },
                option_monitor_event = monitor_rx.recv() => {
                    match option_monitor_event {
                        Some(Ok(event)) => {
                            if event.is_failure() {
                                return Err(anyhow!("Received failure event from monitor socket: {:?}", event));
                            }
                            if let MonitorMessage::HandshakeSucceeded = event {
                                if tx.send(ZmqEvent::Connected).is_err() {
                                    info!("Send channel is closed, exiting");
                                    return Ok(())
                                }

                                tokio::spawn({
                                    let bitcoin = bitcoin.clone();
                                    let tx = tx.clone();
                                    let cancel_token = cancel_token.clone();
                                    async move {
                                        let mempool_txids = retry(
                                            || bitcoin.get_raw_mempool(),
                                            "get raw mempool",
                                            new_backoff_unlimited(),
                                            cancel_token.clone(),
                                        )
                                        .await
                                        .expect("Unexpected error getting raw mempool");
                                        info!("Getting mempool transactions: {}", mempool_txids.len());
                                        let mut txs: Vec<Transaction> = vec![];
                                        for txids in mempool_txids.chunks(100) {
                                            if cancel_token.is_cancelled() {
                                                break;
                                            }

                                            let results = retry(
                                                || bitcoin.get_raw_transactions(txids),
                                                "get raw transactions",
                                                new_backoff_unlimited(),
                                                cancel_token.clone(),
                                            )
                                            .await
                                            .expect("Unexpected error getting raw mempool transactions");
                                            txs.extend(results.into_iter().filter_map(Result::ok));
                                            info!(
                                                "Got mempool transaction: {}/{}",
                                                txs.len(),
                                                mempool_txids.len()
                                            );
                                        }
                                        let _ = tx.send(ZmqEvent::MempoolTransactions(
                                            txs.into_par_iter().map(f).collect(),
                                        ));
                                    }
                                });
                            }
                        },
                        Some(Err(e)) => {
                            return Err(e.context("Received Err from monitor socket thread, exiting"));
                        },
                        None => {
                            warn!("Received None message from monitor socket thread, exiting");
                            return Ok(());
                        },
                    }
                },
                option_message = socket_rx.recv() => {
                    match option_message {
                        Some(Ok((sequence_number, sequence_message))) => {
                            if let Some(n) = last_sequence_number {
                                if sequence_number != n.wrapping_add(1) {
                                    return Err(anyhow!(
                                        "Received out of sequence messages: {} {}",
                                        n, sequence_number
                                    ));
                                }
                            }
                            last_sequence_number = Some(sequence_number);
                            if let Some(event) = match sequence_message {
                                SequenceMessage::BlockConnected(block_hash) => {
                                    let block = retry(
                                        || bitcoin.get_block(&block_hash),
                                        "get block",
                                        new_backoff_limited(),
                                        cancel_token.clone(),
                                    )
                                    .await
                                    .context("Failed to get block handling BlockConnected sequence message")?;
                                    Some(ZmqEvent::BlockConnected(Block {
                                        height: block.bip34_block_height().unwrap(),
                                        hash: block.block_hash(),
                                        prev_hash: block.header.prev_blockhash,
                                        transactions: block.txdata.into_par_iter().map(f).collect(),
                                    }))
                                },
                                SequenceMessage::TransactionAdded{txid, ..} => {
                                    match retry(
                                        || bitcoin.get_raw_transaction(&txid),
                                        "get raw transaction",
                                        new_backoff_limited(),
                                        cancel_token.clone(),
                                    )
                                    .await
                                    {
                                        Ok(transaction) => {
                                            let t = f(transaction);
                                            Some(ZmqEvent::MempoolTransactionAdded(t))
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Skipping adding mempool transaction due to get error: {}",
                                                e
                                            );
                                            None
                                        }
                                    }
                                },
                                SequenceMessage::BlockDisconnected(block_hash) => {
                                    Some(ZmqEvent::BlockDisconnected(block_hash))
                                },
                                SequenceMessage::TransactionRemoved {txid, ..} => {
                                    Some(ZmqEvent::MempoolTransactionRemoved(txid))
                                }
                            }
                            {
                                if tx.send(event).is_err() {
                                    info!("Send channel is closed, exiting");
                                    return Ok(())
                                }
                            }
                        },
                        Some(Err(e)) => {
                            return Err(e.context("Received Err from socket thread, exiting"));
                        },
                        None => {
                            warn!("Received None message from socket thread, exiting");
                            return Ok(());
                        },
                    }
                },
            }
        }
    }))
}
