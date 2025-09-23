use anyhow::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use indexer::{
    bitcoin_follower::{
        ctrl::CtrlChannel,
        events::{BlockId, Event, ZmqEvent},
        reconciler::{self},
    },
    test_utils::{MockBlockchain, MockTransaction, gen_numbered_blocks, new_numbered_blockchain},
};

#[tokio::test]
async fn test_reconciler_switch_to_zmq_after_catchup() -> Result<()> {
    let cancel_token = CancellationToken::new();

    let mut blocks = new_numbered_blockchain(3);
    let initial_mempool: Vec<MockTransaction> =
        [1, 2, 3].iter().map(|i| MockTransaction::new(*i)).collect();

    let mut mock = MockBlockchain::new(blocks.clone());
    mock.set_mempool(initial_mempool.clone());
    let (ctrl, ctrl_rx) = CtrlChannel::<MockTransaction>::create();
    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let (zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        mock.clone(),
        mock.clone(),
        mock.clone(),
        rpc_rx,
        zmq_rx,
        None,
    );

    let handle = tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    });

    assert!(zmq_tx.send(ZmqEvent::Connected).is_ok());

    let mut event_rx = ctrl.clone().start(2, None).await.unwrap();
    mock.clone().await_running().await;
    assert_eq!(mock.start_height(), 2);

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[2 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockInsert((3, blocks[2 - 1].clone())));

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[3 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockInsert((3, blocks[3 - 1].clone())));
    mock.await_stopped().await; // switched to ZMQ

    let more_blocks = gen_numbered_blocks(3, 5, blocks[3 - 1].hash);
    blocks.extend(more_blocks.iter().cloned());

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolSet(initial_mempool));

    let tx1 = blocks[4 - 1].transactions[0].clone();
    assert!(
        zmq_tx
            .send(ZmqEvent::MempoolTransactionAdded(tx1.clone()))
            .is_ok()
    );

    let tx2 = blocks[5 - 1].transactions[0].clone();
    assert!(
        zmq_tx
            .send(ZmqEvent::MempoolTransactionAdded(tx2.clone()))
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolInsert(vec![tx1]));
    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolInsert(vec![tx2]));

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[4 - 1].clone()))
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockInsert((4, blocks[4 - 1].clone())));

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[5 - 1].clone()))
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockInsert((5, blocks[5 - 1].clone())));

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn test_reconciler_zmq_rollback_message() -> Result<()> {
    let cancel_token = CancellationToken::new();

    let mut blocks = new_numbered_blockchain(3);

    let initial_mempool: Vec<MockTransaction> =
        [1, 2, 3].iter().map(|i| MockTransaction::new(*i)).collect();

    let mut mock = MockBlockchain::new(blocks.clone());
    mock.set_mempool(initial_mempool.clone());
    let (ctrl, ctrl_rx) = CtrlChannel::<MockTransaction>::create();
    let (_rpc_tx, rpc_rx) = mpsc::channel(10);
    let (zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        mock.clone(),
        mock.clone(),
        mock.clone(),
        rpc_rx,
        zmq_rx,
        None,
    );

    let handle = tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    });

    let mut event_rx = ctrl
        .clone()
        .start(4, Some(blocks[3 - 1].hash))
        .await
        .unwrap();
    mock.clone().await_running().await;
    assert_eq!(mock.start_height(), 4);

    assert!(zmq_tx.send(ZmqEvent::Connected).is_ok());
    mock.await_stopped().await; // switched to ZMQ

    let more_blocks = gen_numbered_blocks(3, 5, blocks[3 - 1].hash);
    blocks.extend(more_blocks.iter().cloned());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[4 - 1].clone()))
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolSet(initial_mempool));
    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockInsert((4, blocks[4 - 1].clone())));

    let tx1 = MockTransaction::new(123);
    assert!(
        zmq_tx
            .send(ZmqEvent::MempoolTransactionAdded(tx1.clone()))
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::MempoolInsert(vec![tx1]));

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockDisconnected(blocks[2 - 1].hash))
            .is_ok()
    );

    let e = event_rx.recv().await.unwrap();
    assert_eq!(e, Event::BlockRemove(BlockId::Hash(blocks[2 - 1].hash)));

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}
