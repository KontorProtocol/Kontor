use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use tokio::sync::{Notify, mpsc::{self, Sender, UnboundedSender}};
use tokio::{select, task, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use zmq::Socket;

use crate::bitcoin_client::client::BitcoinRpc;
use crate::block::TransactionFilterMap;
use crate::retry::{new_backoff_limited, retry};

use super::event::BitcoinEvent;
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
    event_tx: Sender<BitcoinEvent>,
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
    event_tx: &Sender<BitcoinEvent>,
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

    run_event_loop(bitcoin, f, event_tx, cancel_token, socket_rx, monitor_rx, poll_notify).await
}

/// Core event loop: processes monitor events and data messages.
/// Separated from `run_session` so tests can inject channels directly.
async fn run_event_loop<C: BitcoinRpc>(
    bitcoin: &C,
    f: TransactionFilterMap,
    event_tx: &Sender<BitcoinEvent>,
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
                            if event_tx.send(BitcoinEvent::MempoolSync(txs)).await.is_err() {
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
) -> Result<(Vec<indexer_types::Transaction>, u64)> {
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

    let filtered =
        task::spawn_blocking(move || txs.into_par_iter().enumerate().filter_map(f).collect())
            .await?;

    Ok((filtered, mempool_sequence))
}

/// Process a single mempool delta message. Returns Ok(true) if the event channel is still open,
/// Ok(false) if the receiver has been dropped.
async fn process_delta<C: BitcoinRpc>(
    data_message: DataMessage,
    bitcoin: &C,
    f: TransactionFilterMap,
    event_tx: &Sender<BitcoinEvent>,
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
                    if let Some(filtered) = f((0, tx))
                        && event_tx
                            .send(BitcoinEvent::MempoolInsert(filtered))
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
            if event_tx
                .send(BitcoinEvent::MempoolRemove(txid))
                .await
                .is_err()
            {
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
mod tests {
    use super::*;
    use crate::bitcoin_client::mock::MockBitcoinRpc;
    use bitcoin::hashes::Hash;
    use bitcoin::locktime::absolute::LockTime;
    use bitcoin::transaction::Version;
    use indexer_types::Block;

    fn make_block(height: u64) -> Block {
        use bitcoin::hashes::Hash;
        Block {
            height,
            hash: bitcoin::BlockHash::from_byte_array([height as u8; 32]),
            prev_hash: if height == 0 {
                bitcoin::BlockHash::all_zeros()
            } else {
                bitcoin::BlockHash::from_byte_array([(height - 1) as u8; 32])
            },
            transactions: vec![],
        }
    }

    /// Create a minimal bitcoin::Transaction with a unique txid.
    /// The nonce in lock_time makes each call produce a distinct txid.
    fn make_tx(nonce: u32) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: Version::ONE,
            lock_time: LockTime::from_consensus(nonce),
            input: vec![],
            output: vec![],
        }
    }

    /// Filter that accepts all transactions.
    fn accept_all(pair: (usize, bitcoin::Transaction)) -> Option<indexer_types::Transaction> {
        let (index, tx) = pair;
        Some(indexer_types::Transaction {
            txid: tx.compute_txid(),
            index: index as i64,
            ops: vec![],
            op_return_data: Default::default(),
        })
    }

    /// Filter that rejects all transactions.
    fn reject_all(_: (usize, bitcoin::Transaction)) -> Option<indexer_types::Transaction> {
        None
    }

    #[tokio::test]
    async fn fetch_mempool_empty() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        let cancel = CancellationToken::new();

        let (result, seq) = fetch_mempool(&mock, reject_all, &cancel).await.unwrap();
        assert!(result.is_empty());
        assert_eq!(seq, 0);
    }

    #[tokio::test]
    async fn fetch_mempool_returns_sequence() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        mock.set_mempool(vec![make_tx(1)]);
        mock.set_mempool_sequence(42);

        let cancel = CancellationToken::new();
        let (result, seq) = fetch_mempool(&mock, accept_all, &cancel).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(seq, 42);
    }

    #[tokio::test]
    async fn fetch_mempool_returns_filtered_transactions() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        let tx1 = make_tx(1);
        let tx2 = make_tx(2);
        let tx3 = make_tx(3);
        let txid1 = tx1.compute_txid();
        let txid3 = tx3.compute_txid();
        mock.set_mempool(vec![tx1, tx2, tx3]);

        let cancel = CancellationToken::new();

        // Filter that only accepts odd nonces (tx1 and tx3)
        let f: TransactionFilterMap = |pair| {
            let (index, tx) = pair;
            if tx.lock_time.to_consensus_u32() % 2 == 1 {
                Some(indexer_types::Transaction {
                    txid: tx.compute_txid(),
                    index: index as i64,
                    ops: vec![],
                    op_return_data: Default::default(),
                })
            } else {
                None
            }
        };

        let (result, _) = fetch_mempool(&mock, f, &cancel).await.unwrap();
        assert_eq!(result.len(), 2);
        let txids: Vec<_> = result.iter().map(|t| t.txid).collect();
        assert!(txids.contains(&txid1));
        assert!(txids.contains(&txid3));
    }

    #[tokio::test]
    async fn fetch_mempool_all_accepted() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        let txs: Vec<_> = (0..5).map(make_tx).collect();
        let expected_txids: Vec<_> = txs.iter().map(|tx| tx.compute_txid()).collect();
        mock.set_mempool(txs);

        let cancel = CancellationToken::new();
        let (result, _) = fetch_mempool(&mock, accept_all, &cancel).await.unwrap();

        assert_eq!(result.len(), 5);
        for txid in &expected_txids {
            assert!(result.iter().any(|t| t.txid == *txid));
        }
    }

    #[tokio::test]
    async fn fetch_mempool_all_rejected() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        mock.set_mempool(vec![make_tx(1), make_tx(2)]);

        let cancel = CancellationToken::new();
        let (result, _) = fetch_mempool(&mock, reject_all, &cancel).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn fetch_mempool_batches_large_mempool() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        // 250 transactions should require 3 batches of 100
        let txs: Vec<_> = (0..250).map(make_tx).collect();
        mock.set_mempool(txs);

        let cancel = CancellationToken::new();
        let (result, _) = fetch_mempool(&mock, accept_all, &cancel).await.unwrap();
        assert_eq!(result.len(), 250);
    }

    #[tokio::test]
    async fn mempool_sequence_number_extraction() {
        let txid = bitcoin::Txid::from_byte_array([0xaa; 32]);
        let hash = bitcoin::BlockHash::from_byte_array([0xbb; 32]);

        assert_eq!(
            mempool_sequence_number(&DataMessage::TransactionAdded {
                txid,
                mempool_sequence_number: 10,
            }),
            Some(10)
        );
        assert_eq!(
            mempool_sequence_number(&DataMessage::TransactionRemoved {
                txid,
                mempool_sequence_number: 20,
            }),
            Some(20)
        );
        assert_eq!(
            mempool_sequence_number(&DataMessage::BlockConnected(hash)),
            None
        );
        assert_eq!(
            mempool_sequence_number(&DataMessage::BlockDisconnected(hash)),
            None
        );
    }

    #[tokio::test]
    async fn process_delta_transaction_added() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        let tx = make_tx(1);
        let txid = tx.compute_txid();
        mock.set_mempool(vec![tx]);

        let (event_tx, mut event_rx) = mpsc::channel(10);
        let cancel = CancellationToken::new();

        let msg = DataMessage::TransactionAdded {
            txid,
            mempool_sequence_number: 1,
        };

        let notify = Notify::new();
        let open = process_delta(msg, &mock, accept_all, &event_tx, &cancel, &notify)
            .await
            .unwrap();
        assert!(open);

        match event_rx.try_recv().unwrap() {
            BitcoinEvent::MempoolInsert(t) => assert_eq!(t.txid, txid),
            other => panic!("Expected MempoolInsert, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn process_delta_transaction_removed() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        let txid = bitcoin::Txid::from_byte_array([0xcc; 32]);

        let (event_tx, mut event_rx) = mpsc::channel(10);
        let cancel = CancellationToken::new();

        let msg = DataMessage::TransactionRemoved {
            txid,
            mempool_sequence_number: 5,
        };

        let notify = Notify::new();
        let open = process_delta(msg, &mock, accept_all, &event_tx, &cancel, &notify)
            .await
            .unwrap();
        assert!(open);

        match event_rx.try_recv().unwrap() {
            BitcoinEvent::MempoolRemove(id) => assert_eq!(id, txid),
            other => panic!("Expected MempoolRemove, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn process_delta_block_events_ignored() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        let hash = bitcoin::BlockHash::from_byte_array([0xdd; 32]);

        let (event_tx, mut event_rx) = mpsc::channel(10);
        let cancel = CancellationToken::new();

        let notify = Notify::new();
        let open = process_delta(
            DataMessage::BlockConnected(hash),
            &mock,
            accept_all,
            &event_tx,
            &cancel,
            &notify,
        )
        .await
        .unwrap();
        assert!(open);
        assert!(event_rx.try_recv().is_err());
    }

    fn tx_added(seq: u32, mempool_seq: u64) -> (u32, DataMessage) {
        (
            seq,
            DataMessage::TransactionAdded {
                txid: bitcoin::Txid::from_byte_array([seq as u8; 32]),
                mempool_sequence_number: mempool_seq,
            },
        )
    }

    fn tx_removed(seq: u32, mempool_seq: u64) -> (u32, DataMessage) {
        (
            seq,
            DataMessage::TransactionRemoved {
                txid: bitcoin::Txid::from_byte_array([seq as u8; 32]),
                mempool_sequence_number: mempool_seq,
            },
        )
    }

    fn block_connected(seq: u32) -> (u32, DataMessage) {
        (
            seq,
            DataMessage::BlockConnected(bitcoin::BlockHash::from_byte_array([seq as u8; 32])),
        )
    }

    #[test]
    fn filter_empty_buffer() {
        let (msgs, last_seq) = filter_buffered_messages(vec![], 10, None).unwrap();
        assert!(msgs.is_empty());
        assert_eq!(last_seq, None);
    }

    #[test]
    fn filter_skips_stale_messages() {
        let buffer = vec![
            tx_added(0, 8),
            tx_added(1, 9),
            tx_added(2, 10), // equal to snapshot_seq, still skipped
        ];
        let (msgs, last_seq) = filter_buffered_messages(buffer, 10, None).unwrap();
        assert!(msgs.is_empty());
        assert_eq!(last_seq, Some(2));
    }

    #[test]
    fn filter_keeps_fresh_messages() {
        let buffer = vec![
            tx_added(0, 9),  // stale
            tx_added(1, 10), // stale (equal)
            tx_added(2, 11), // fresh
            tx_added(3, 12), // fresh
        ];
        let (msgs, last_seq) = filter_buffered_messages(buffer, 10, None).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(mempool_sequence_number(&msgs[0]), Some(11));
        assert_eq!(mempool_sequence_number(&msgs[1]), Some(12));
        assert_eq!(last_seq, Some(3));
    }

    #[test]
    fn filter_passes_through_block_events() {
        // Block events have no mempool sequence, so they're always included
        let buffer = vec![
            tx_added(0, 5), // stale
            block_connected(1),
            tx_added(2, 11), // fresh
        ];
        let (msgs, _) = filter_buffered_messages(buffer, 10, None).unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(msgs[0], DataMessage::BlockConnected(_)));
        assert_eq!(mempool_sequence_number(&msgs[1]), Some(11));
    }

    #[test]
    fn filter_includes_removed_events() {
        let buffer = vec![
            tx_removed(0, 8),  // stale
            tx_removed(1, 11), // fresh
        ];
        let (msgs, _) = filter_buffered_messages(buffer, 10, None).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(msgs[0], DataMessage::TransactionRemoved { .. }));
        assert_eq!(mempool_sequence_number(&msgs[0]), Some(11));
    }

    #[test]
    fn filter_detects_sequence_gap() {
        let buffer = vec![
            tx_added(0, 11),
            tx_added(5, 12), // gap: expected 1, got 5
        ];
        let err = filter_buffered_messages(buffer, 10, None).unwrap_err();
        assert!(err.to_string().contains("Out of sequence"));
    }

    #[test]
    fn filter_continues_from_previous_sequence() {
        let buffer = vec![tx_added(8, 11), tx_added(9, 12)];
        // last_sequence_number was 7 from before the buffer
        let (msgs, last_seq) = filter_buffered_messages(buffer, 10, Some(7)).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(last_seq, Some(9));
    }

    #[test]
    fn filter_detects_gap_with_previous_sequence() {
        let buffer = vec![
            tx_added(10, 11), // expected 8 (7+1), got 10
        ];
        let err = filter_buffered_messages(buffer, 10, Some(7)).unwrap_err();
        assert!(err.to_string().contains("Out of sequence"));
    }

    #[test]
    fn filter_handles_zmq_sequence_wrapping() {
        let buffer = vec![
            tx_added(u32::MAX, 11),
            tx_added(0, 12), // wraps around
        ];
        let (msgs, last_seq) = filter_buffered_messages(buffer, 10, Some(u32::MAX - 1)).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(last_seq, Some(0));
    }

    // --- run_event_loop tests ---

    /// Collect all events from the receiver until it's empty.
    fn collect_events(rx: &mut mpsc::Receiver<BitcoinEvent>) -> Vec<BitcoinEvent> {
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        events
    }

    #[tokio::test]
    async fn event_loop_snapshot_then_live_deltas() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        let tx1 = make_tx(1);
        let tx2 = make_tx(2);
        let tx3 = make_tx(3);
        let txid3 = tx3.compute_txid();
        mock.set_mempool(vec![tx1, tx2, tx3]);
        mock.set_mempool_sequence(10);

        let (event_tx, mut event_rx) = mpsc::channel(100);
        let cancel = CancellationToken::new();

        let (socket_tx, socket_rx) = mpsc::unbounded_channel();
        let (monitor_tx, monitor_rx) = mpsc::unbounded_channel();

        // Send handshake — triggers snapshot fetch
        monitor_tx
            .send(Ok(MonitorMessage::HandshakeSucceeded))
            .unwrap();

        // Live delta after snapshot (mempool_seq 11 > snapshot 10)
        socket_tx
            .send(Ok((
                0,
                DataMessage::TransactionAdded {
                    txid: txid3,
                    mempool_sequence_number: 11,
                },
            )))
            .unwrap();

        // Close channels so the event loop exits
        drop(monitor_tx);
        drop(socket_tx);

        let _ = run_event_loop(&mock, accept_all, &event_tx, cancel, socket_rx, monitor_rx, Arc::new(Notify::new())).await;

        let events = collect_events(&mut event_rx);
        assert!(matches!(&events[0], BitcoinEvent::MempoolSync(txs) if txs.len() == 3));
        assert!(matches!(&events[1], BitcoinEvent::MempoolInsert(t) if t.txid == txid3));
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn event_loop_filters_buffered_stale_replays_fresh() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        let tx1 = make_tx(1);
        let txid1 = tx1.compute_txid();
        let tx2 = make_tx(2);
        let txid2 = tx2.compute_txid();
        let tx3 = make_tx(3);
        let txid3 = tx3.compute_txid();
        mock.set_mempool(vec![tx1, tx2, tx3]);
        mock.set_mempool_sequence(10);

        let (event_tx, mut event_rx) = mpsc::channel(100);
        let cancel = CancellationToken::new();

        let (socket_tx, socket_rx) = mpsc::unbounded_channel();
        let (monitor_tx, monitor_rx) = mpsc::unbounded_channel();

        // Pre-load data messages BEFORE handshake (simulates messages
        // arriving between ZMQ connect and snapshot fetch)
        socket_tx
            .send(Ok((
                0,
                DataMessage::TransactionAdded {
                    txid: txid1,
                    mempool_sequence_number: 9, // stale
                },
            )))
            .unwrap();
        socket_tx
            .send(Ok((
                1,
                DataMessage::TransactionAdded {
                    txid: txid2,
                    mempool_sequence_number: 10, // stale (equal)
                },
            )))
            .unwrap();
        socket_tx
            .send(Ok((
                2,
                DataMessage::TransactionAdded {
                    txid: txid3,
                    mempool_sequence_number: 11, // fresh
                },
            )))
            .unwrap();

        // Handshake triggers snapshot + buffer drain
        monitor_tx
            .send(Ok(MonitorMessage::HandshakeSucceeded))
            .unwrap();

        drop(monitor_tx);
        drop(socket_tx);

        let _ = run_event_loop(&mock, accept_all, &event_tx, cancel, socket_rx, monitor_rx, Arc::new(Notify::new())).await;

        let events = collect_events(&mut event_rx);
        assert!(matches!(&events[0], BitcoinEvent::MempoolSync(_)));
        // Only tx3 replayed (stale ones skipped)
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[1], BitcoinEvent::MempoolInsert(t) if t.txid == txid3));
    }

    #[tokio::test]
    async fn event_loop_pre_handshake_messages_not_emitted_as_deltas() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        let tx1 = make_tx(1);
        let txid1 = tx1.compute_txid();
        mock.set_mempool(vec![tx1]);
        mock.set_mempool_sequence(5);

        let (event_tx, mut event_rx) = mpsc::channel(100);
        let cancel = CancellationToken::new();

        let (socket_tx, socket_rx) = mpsc::unbounded_channel();
        let (monitor_tx, monitor_rx) = mpsc::unbounded_channel();

        // Data arrives before handshake — must not appear as a delta
        socket_tx
            .send(Ok((
                0,
                DataMessage::TransactionAdded {
                    txid: txid1,
                    mempool_sequence_number: 4, // stale
                },
            )))
            .unwrap();

        monitor_tx
            .send(Ok(MonitorMessage::HandshakeSucceeded))
            .unwrap();

        drop(monitor_tx);
        drop(socket_tx);

        let _ = run_event_loop(&mock, accept_all, &event_tx, cancel, socket_rx, monitor_rx, Arc::new(Notify::new())).await;

        let events = collect_events(&mut event_rx);
        // Only MempoolSync, no spurious delta
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], BitcoinEvent::MempoolSync(_)));
    }

    #[tokio::test]
    async fn event_loop_monitor_failure_returns_error() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);

        let (event_tx, _event_rx) = mpsc::channel(100);
        let cancel = CancellationToken::new();

        let (_socket_tx, socket_rx) = mpsc::unbounded_channel();
        let (monitor_tx, monitor_rx) = mpsc::unbounded_channel();

        monitor_tx.send(Ok(MonitorMessage::Disconnected)).unwrap();
        drop(monitor_tx);

        let result =
            run_event_loop(&mock, accept_all, &event_tx, cancel, socket_rx, monitor_rx, Arc::new(Notify::new())).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Monitor failure"));
    }

    #[tokio::test]
    async fn event_loop_live_remove_emits_mempool_remove() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        mock.set_mempool(vec![]);
        mock.set_mempool_sequence(10);

        let (event_tx, mut event_rx) = mpsc::channel(100);
        let cancel = CancellationToken::new();

        let (socket_tx, socket_rx) = mpsc::unbounded_channel();
        let (monitor_tx, monitor_rx) = mpsc::unbounded_channel();

        monitor_tx
            .send(Ok(MonitorMessage::HandshakeSucceeded))
            .unwrap();

        let removed_txid = bitcoin::Txid::from_byte_array([0xee; 32]);
        socket_tx
            .send(Ok((
                0,
                DataMessage::TransactionRemoved {
                    txid: removed_txid,
                    mempool_sequence_number: 11,
                },
            )))
            .unwrap();

        drop(monitor_tx);
        drop(socket_tx);

        let _ = run_event_loop(&mock, accept_all, &event_tx, cancel, socket_rx, monitor_rx, Arc::new(Notify::new())).await;

        let events = collect_events(&mut event_rx);
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], BitcoinEvent::MempoolSync(txs) if txs.is_empty()));
        assert!(matches!(&events[1], BitcoinEvent::MempoolRemove(txid) if *txid == removed_txid));
    }

    #[tokio::test]
    async fn event_loop_sequence_gap_returns_error() {
        let mock = MockBitcoinRpc::new(vec![make_block(1)]);
        mock.set_mempool(vec![]);
        mock.set_mempool_sequence(0);

        let (event_tx, _event_rx) = mpsc::channel(100);
        let cancel = CancellationToken::new();

        let (socket_tx, socket_rx) = mpsc::unbounded_channel();
        let (monitor_tx, monitor_rx) = mpsc::unbounded_channel();

        monitor_tx
            .send(Ok(MonitorMessage::HandshakeSucceeded))
            .unwrap();

        // After sync, send messages with a sequence gap
        socket_tx
            .send(Ok((
                0,
                DataMessage::TransactionAdded {
                    txid: bitcoin::Txid::from_byte_array([0xaa; 32]),
                    mempool_sequence_number: 1,
                },
            )))
            .unwrap();
        socket_tx
            .send(Ok((
                5, // gap: expected 1, got 5
                DataMessage::TransactionAdded {
                    txid: bitcoin::Txid::from_byte_array([0xbb; 32]),
                    mempool_sequence_number: 2,
                },
            )))
            .unwrap();

        drop(monitor_tx);
        drop(socket_tx);

        let result =
            run_event_loop(&mock, accept_all, &event_tx, cancel, socket_rx, monitor_rx, Arc::new(Notify::new())).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Out of sequence"));
    }
}
