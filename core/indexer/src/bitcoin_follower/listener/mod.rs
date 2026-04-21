use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use tokio::sync::{
    Notify,
    mpsc::{self, Sender, UnboundedSender},
};
use tokio::{select, task, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use zmq::Socket;

use crate::bitcoin_client::client::BitcoinRpc;
use crate::block::TransactionFilterMap;
use crate::retry::{new_backoff_limited, retry};

use super::event::MempoolEvent;
use super::messages::{DataMessage, MonitorMessage};

pub struct ListenerConfig {
    pub zmq_address: String,
    pub reconnect_delay: Duration,
}

impl ListenerConfig {
    pub fn new(zmq_address: String) -> Self {
        Self {
            zmq_address,
            reconnect_delay: Duration::from_secs(10),
        }
    }
}

/// Top-level mempool listener with auto-reconnect.
pub async fn run<C: BitcoinRpc>(
    bitcoin: C,
    f: TransactionFilterMap,
    event_tx: Sender<MempoolEvent>,
    cancel_token: CancellationToken,
    poll_notify: Arc<Notify>,
    config: ListenerConfig,
) -> Result<()> {
    loop {
        match run_session(
            &bitcoin,
            f,
            &event_tx,
            cancel_token.clone(),
            &config.zmq_address,
            poll_notify.clone(),
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!("ZMQ session ended with error: {:#}", e);
            }
        }

        select! {
            _ = sleep(config.reconnect_delay) => {
                info!("Reconnecting ZMQ listener");
            }
            _ = cancel_token.cancelled() => {
                info!("Cancelled during reconnect delay");
                return Ok(());
            }
        }
    }
}

/// A single ZMQ connection session. Returns Ok on clean cancellation,
/// Err on any failure (triggers reconnect in the outer loop).
async fn run_session<C: BitcoinRpc>(
    bitcoin: &C,
    f: TransactionFilterMap,
    event_tx: &Sender<MempoolEvent>,
    cancel_token: CancellationToken,
    zmq_address: &str,
    poll_notify: Arc<Notify>,
) -> Result<()> {
    let (socket_tx, socket_rx) = mpsc::unbounded_channel();
    let (monitor_tx, monitor_rx) = mpsc::unbounded_channel();

    let socket_cancel_token = CancellationToken::new();

    let ctx = zmq::Context::new();

    let socket = ctx
        .socket(zmq::SUB)
        .context("Failed to create ZMQ socket")?;
    socket.set_subscribe(b"sequence")?;
    socket.set_rcvhwm(0)?;
    socket.set_rcvtimeo(1000)?;

    let monitor_endpoint = "inproc://mempool-monitor";
    socket
        .monitor(monitor_endpoint, MonitorMessage::all_events_mask())
        .context("Failed to set up socket monitor")?;
    let monitor_socket = ctx
        .socket(zmq::PAIR)
        .context("Failed to create monitor socket")?;
    monitor_socket
        .connect(monitor_endpoint)
        .context("Failed to connect monitor socket")?;
    monitor_socket.set_rcvhwm(0)?;
    monitor_socket.set_rcvtimeo(1000)?;

    let monitor_handle =
        run_monitor_socket(monitor_socket, socket_cancel_token.clone(), monitor_tx);

    socket
        .connect(zmq_address)
        .context("Could not connect to ZMQ address")?;

    let socket_handle = run_data_socket(socket, socket_cancel_token.clone(), socket_tx);

    // Clean up threads when this function exits (for any reason)
    let _cleanup = CleanupGuard {
        cancel_token: socket_cancel_token,
        handles: vec![socket_handle, monitor_handle],
    };

    run_event_loop(
        bitcoin,
        f,
        event_tx,
        cancel_token,
        socket_rx,
        monitor_rx,
        poll_notify,
    )
    .await
}

/// Core event loop: processes monitor events and data messages.
/// Separated from `run_session` so tests can inject channels directly.
async fn run_event_loop<C: BitcoinRpc>(
    bitcoin: &C,
    f: TransactionFilterMap,
    event_tx: &Sender<MempoolEvent>,
    cancel_token: CancellationToken,
    mut socket_rx: mpsc::UnboundedReceiver<Result<(u32, DataMessage)>>,
    mut monitor_rx: mpsc::UnboundedReceiver<Result<MonitorMessage>>,
    poll_notify: Arc<Notify>,
) -> Result<()> {
    let mut last_sequence_number: Option<u32> = None;
    let mut synced = false;

    loop {
        select! {
            biased;

            _ = cancel_token.cancelled() => {
                info!("ZMQ session cancelled");
                return Ok(());
            }

            event = monitor_rx.recv() => {
                match event {
                    Some(Ok(msg)) => {
                        if msg.is_failure() {
                            return Err(anyhow!("Monitor failure event: {:?}", msg));
                        }
                        if let MonitorMessage::HandshakeSucceeded = msg {
                            info!("ZMQ connected, fetching mempool snapshot");

                            // Fetch snapshot with mempool sequence number
                            let (txs, snapshot_seq) =
                                fetch_mempool(bitcoin, f, &cancel_token).await?;
                            if event_tx.send(MempoolEvent::Sync(txs)).await.is_err() {
                                return Ok(());
                            }

                            // Drain and replay buffered ZMQ messages that arrived
                            // during the snapshot fetch. Skip events already covered
                            // by the snapshot (mempool_sequence_number <= snapshot_seq).
                            let mut buffer = Vec::new();
                            while let Ok(msg) = socket_rx.try_recv() {
                                buffer.push(msg?);
                            }
                            let (to_replay, new_seq) =
                                filter_buffered_messages(buffer, snapshot_seq, last_sequence_number)?;
                            last_sequence_number = new_seq;

                            for data_message in to_replay {
                                if !process_delta(data_message, bitcoin, f, event_tx, &cancel_token, &poll_notify)
                                    .await?
                                {
                                    return Ok(());
                                }
                            }

                            synced = true;
                        }
                    }
                    Some(Err(e)) => {
                        return Err(e.context("Monitor socket error"));
                    }
                    None => {
                        return Err(anyhow!("Monitor channel closed"));
                    }
                }
            }

            msg = socket_rx.recv() => {
                match msg {
                    Some(Ok((seq, data_message))) => {
                        if let Some(prev) = last_sequence_number
                            && seq != prev.wrapping_add(1)
                        {
                            return Err(anyhow!(
                                "Out of sequence: expected {}, got {}",
                                prev.wrapping_add(1),
                                seq
                            ));
                        }
                        last_sequence_number = Some(seq);

                        // Before sync completes, messages will be drained
                        // in the HandshakeSucceeded handler above
                        if !synced {
                            continue;
                        }

                        if !process_delta(data_message, bitcoin, f, event_tx, &cancel_token, &poll_notify)
                            .await?
                        {
                            return Ok(());
                        }
                    }
                    Some(Err(e)) => {
                        return Err(e.context("Data socket error"));
                    }
                    None => {
                        return Err(anyhow!("Data channel closed"));
                    }
                }
            }
        }
    }
}

/// Filter buffered ZMQ messages against a mempool snapshot sequence number.
/// Validates ZMQ envelope sequence continuity, then returns only messages
/// with mempool_sequence_number > snapshot_seq (or block events, which have
/// no mempool sequence and are always passed through).
fn filter_buffered_messages(
    buffer: Vec<(u32, DataMessage)>,
    snapshot_seq: u64,
    mut last_sequence_number: Option<u32>,
) -> Result<(Vec<DataMessage>, Option<u32>)> {
    let mut result = Vec::new();
    for (seq, data_message) in buffer {
        if let Some(prev) = last_sequence_number
            && seq != prev.wrapping_add(1)
        {
            return Err(anyhow!(
                "Out of sequence: expected {}, got {}",
                prev.wrapping_add(1),
                seq
            ));
        }
        last_sequence_number = Some(seq);

        if mempool_sequence_number(&data_message).is_some_and(|ms| ms <= snapshot_seq) {
            continue;
        }

        result.push(data_message);
    }
    Ok((result, last_sequence_number))
}

/// Extract the mempool sequence number from a data message, if it has one.
/// Block events don't carry a mempool sequence number.
fn mempool_sequence_number(msg: &DataMessage) -> Option<u64> {
    match msg {
        DataMessage::TransactionAdded {
            mempool_sequence_number,
            ..
        }
        | DataMessage::TransactionRemoved {
            mempool_sequence_number,
            ..
        } => Some(*mempool_sequence_number),
        DataMessage::BlockConnected(_) | DataMessage::BlockDisconnected(_) => None,
    }
}

/// Fetch the full mempool via RPC with mempool sequence number, and apply the transaction filter.
/// Returns (filtered_transactions, mempool_sequence).
async fn fetch_mempool<C: BitcoinRpc>(
    bitcoin: &C,
    f: TransactionFilterMap,
    cancel_token: &CancellationToken,
) -> Result<(Vec<(bitcoin::Transaction, indexer_types::Transaction)>, u64)> {
    let snapshot = retry(
        || bitcoin.get_raw_mempool_sequence(),
        "get raw mempool",
        new_backoff_limited(),
        cancel_token.clone(),
    )
    .await?;

    let mempool_sequence = snapshot.mempool_sequence;
    let mempool_txids = snapshot.txids;

    info!(
        "Fetching {} mempool transactions (sequence {})",
        mempool_txids.len(),
        mempool_sequence
    );

    let mut txs: Vec<bitcoin::Transaction> = vec![];
    for chunk in mempool_txids.chunks(100) {
        if cancel_token.is_cancelled() {
            break;
        }

        let results = retry(
            || bitcoin.get_raw_transactions(chunk),
            "get raw transactions",
            new_backoff_limited(),
            cancel_token.clone(),
        )
        .await?;

        txs.extend(results.into_iter().filter_map(Result::ok));
        info!(
            "Fetched {}/{} mempool transactions",
            txs.len(),
            mempool_txids.len()
        );
    }

    // Filter and parse transactions in parallel, keeping both raw and parsed forms.
    let filtered: Vec<(bitcoin::Transaction, indexer_types::Transaction)> =
        task::spawn_blocking(move || {
            txs.into_par_iter()
                .enumerate()
                .filter_map(|(i, tx)| f((i, tx.clone())).map(|parsed| (tx, parsed)))
                .collect()
        })
        .await?;

    Ok((filtered, mempool_sequence))
}

/// Process a single mempool delta message. Returns Ok(true) if the event channel is still open,
/// Ok(false) if the receiver has been dropped.
async fn process_delta<C: BitcoinRpc>(
    data_message: DataMessage,
    bitcoin: &C,
    f: TransactionFilterMap,
    event_tx: &Sender<MempoolEvent>,
    cancel_token: &CancellationToken,
    poll_notify: &Notify,
) -> Result<bool> {
    match data_message {
        DataMessage::TransactionAdded { txid, .. } => {
            let bitcoin = bitcoin.clone();
            let cancel_token = cancel_token.clone();
            match retry(
                || bitcoin.get_raw_transaction(&txid),
                "get raw transaction",
                new_backoff_limited(),
                cancel_token,
            )
            .await
            {
                Ok(tx) => {
                    if let Some(parsed) = f((0, tx.clone()))
                        && event_tx
                            .send(MempoolEvent::Insert(tx, parsed))
                            .await
                            .is_err()
                    {
                        return Ok(false);
                    }
                }
                Err(e) => {
                    // Tx may have been confirmed or evicted between
                    // the ZMQ notification and our RPC call
                    warn!("Failed to fetch mempool tx {}: {:#}", txid, e);
                }
            }
        }
        DataMessage::TransactionRemoved { txid, .. } => {
            if event_tx.send(MempoolEvent::Remove(txid)).await.is_err() {
                return Ok(false);
            }
        }
        DataMessage::BlockConnected(_) | DataMessage::BlockDisconnected(_) => {
            poll_notify.notify_one();
        }
    }
    Ok(true)
}

/// Native thread that reads from the ZMQ data socket and sends parsed messages to an async channel.
fn run_data_socket(
    socket: Socket,
    cancel_token: CancellationToken,
    tx: UnboundedSender<Result<(u32, DataMessage)>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if cancel_token.is_cancelled() {
                break;
            }

            match socket.recv_multipart(0) {
                Ok(multipart) => {
                    if tx.send(DataMessage::from_zmq_message(multipart)).is_err() {
                        break;
                    }
                }
                Err(zmq::Error::EAGAIN) => continue,
                Err(e) => {
                    let _ = tx.send(Err(e.into()));
                    break;
                }
            }
        }
    })
}

/// Native thread that reads from the ZMQ monitor socket and sends parsed events to an async channel.
fn run_monitor_socket(
    socket: Socket,
    cancel_token: CancellationToken,
    tx: UnboundedSender<Result<MonitorMessage>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if cancel_token.is_cancelled() {
                break;
            }

            match socket.recv_multipart(0) {
                Ok(multipart) => {
                    if tx
                        .send(MonitorMessage::from_zmq_message(multipart))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(zmq::Error::EAGAIN) => continue,
                Err(e) => {
                    let _ = tx.send(Err(e.into()));
                    break;
                }
            }
        }
    })
}

/// Cancels the socket threads and joins them on drop.
struct CleanupGuard {
    cancel_token: CancellationToken,
    handles: Vec<thread::JoinHandle<()>>,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                error!("Socket thread panicked on join");
            }
        }
    }
}

#[cfg(test)]
mod tests;
