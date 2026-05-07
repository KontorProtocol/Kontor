use super::*;
use crate::bitcoin_client::mock::MockBitcoinRpc;
use crate::bitcoin_client::types::{MempoolEntry, MempoolEntryFees};
use bitcoin::Amount;
use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::transaction::Version;
use indexer_types::Block;

/// Minimal mempool entry for listener tests — values don't matter except
/// for the fee index plumbing.
fn stub_entry() -> MempoolEntry {
    MempoolEntry {
        vsize: 1,
        ancestorsize: 1,
        fees: MempoolEntryFees {
            base: Amount::from_sat(1),
            ancestor: Amount::from_sat(1),
        },
        depends: vec![],
    }
}

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
        inputs: vec![],
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

    let snapshot = fetch_mempool(&mock, reject_all, &cancel).await.unwrap();
    assert!(snapshot.kontor_txs.is_empty());
    assert_eq!(snapshot.mempool_sequence, 0);
}

#[tokio::test]
async fn fetch_mempool_returns_sequence() {
    let mock = MockBitcoinRpc::new(vec![make_block(1)]);
    mock.set_mempool(vec![make_tx(1)]);
    mock.set_mempool_sequence(42);

    let cancel = CancellationToken::new();
    let snapshot = fetch_mempool(&mock, accept_all, &cancel).await.unwrap();
    assert_eq!(snapshot.kontor_txs.len(), 1);
    assert_eq!(snapshot.mempool_sequence, 42);
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
                inputs: vec![],
                op_return_data: Default::default(),
            })
        } else {
            None
        }
    };

    let snapshot = fetch_mempool(&mock, f, &cancel).await.unwrap();
    assert_eq!(snapshot.kontor_txs.len(), 2);
    let txids: Vec<_> = snapshot.kontor_txs.iter().map(|(t, _)| *t).collect();
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
    let snapshot = fetch_mempool(&mock, accept_all, &cancel).await.unwrap();

    assert_eq!(snapshot.kontor_txs.len(), 5);
    for txid in &expected_txids {
        assert!(snapshot.kontor_txs.iter().any(|(t, _)| *t == *txid));
    }
}

#[tokio::test]
async fn fetch_mempool_all_rejected() {
    let mock = MockBitcoinRpc::new(vec![make_block(1)]);
    mock.set_mempool(vec![make_tx(1), make_tx(2)]);

    let cancel = CancellationToken::new();
    let snapshot = fetch_mempool(&mock, reject_all, &cancel).await.unwrap();
    assert!(snapshot.kontor_txs.is_empty());
}

#[tokio::test]
async fn fetch_mempool_batches_large_mempool() {
    let mock = MockBitcoinRpc::new(vec![make_block(1)]);
    // 250 transactions should require 3 batches of 100
    let txs: Vec<_> = (0..250).map(make_tx).collect();
    mock.set_mempool(txs);

    let cancel = CancellationToken::new();
    let snapshot = fetch_mempool(&mock, accept_all, &cancel).await.unwrap();
    assert_eq!(snapshot.kontor_txs.len(), 250);
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
    mock.set_mempool_entry(txid, stub_entry());

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
        MempoolEvent::KontorTxAdded { txid: t, .. } => assert_eq!(t, txid),
        other => panic!("Expected KontorTxAdded, got {:?}", other),
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
        MempoolEvent::Remove(id) => assert_eq!(id, txid),
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
fn collect_events(rx: &mut mpsc::Receiver<MempoolEvent>) -> Vec<MempoolEvent> {
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

    let _ = run_event_loop(
        &mock,
        accept_all,
        &event_tx,
        cancel,
        socket_rx,
        monitor_rx,
        Arc::new(Notify::new()),
    )
    .await;

    let events = collect_events(&mut event_rx);
    assert!(matches!(&events[0], MempoolEvent::Sync { kontor_txs, .. } if kontor_txs.len() == 3));
    assert!(matches!(&events[1], MempoolEvent::KontorTxAdded { txid: t, .. } if *t == txid3));
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

    let _ = run_event_loop(
        &mock,
        accept_all,
        &event_tx,
        cancel,
        socket_rx,
        monitor_rx,
        Arc::new(Notify::new()),
    )
    .await;

    let events = collect_events(&mut event_rx);
    assert!(matches!(&events[0], MempoolEvent::Sync { .. }));
    // Only tx3 replayed (stale ones skipped)
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[1], MempoolEvent::KontorTxAdded { txid: t, .. } if *t == txid3));
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

    let _ = run_event_loop(
        &mock,
        accept_all,
        &event_tx,
        cancel,
        socket_rx,
        monitor_rx,
        Arc::new(Notify::new()),
    )
    .await;

    let events = collect_events(&mut event_rx);
    // Only MempoolSync, no spurious delta
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], MempoolEvent::Sync { .. }));
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

    let result = run_event_loop(
        &mock,
        accept_all,
        &event_tx,
        cancel,
        socket_rx,
        monitor_rx,
        Arc::new(Notify::new()),
    )
    .await;
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

    let _ = run_event_loop(
        &mock,
        accept_all,
        &event_tx,
        cancel,
        socket_rx,
        monitor_rx,
        Arc::new(Notify::new()),
    )
    .await;

    let events = collect_events(&mut event_rx);
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], MempoolEvent::Sync { kontor_txs, .. } if kontor_txs.is_empty()));
    assert!(matches!(&events[1], MempoolEvent::Remove(txid) if *txid == removed_txid));
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

    let result = run_event_loop(
        &mock,
        accept_all,
        &event_tx,
        cancel,
        socket_rx,
        monitor_rx,
        Arc::new(Notify::new()),
    )
    .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Out of sequence"));
}
