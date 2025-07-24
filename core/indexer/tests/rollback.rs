use anyhow::Result;
use clap::Parser;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use bitcoin::{self, BlockHash, hashes::Hash};

use indexer::{
    bitcoin_follower::{
        ctrl::{CtrlChannel, StartMessage},
        events::Event,
        events::{BlockId, ZmqEvent},
        reconciler,
    },
    config::Config,
    database::queries,
    reactor,
    test_utils::{
        MockBlockchain, MockTransaction, await_block_at_height, gen_random_blocks,
        new_random_blockchain, new_test_db,
    },
};

#[tokio::test]
async fn test_follower_reactor_fetching() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let blocks = new_random_blockchain(5);
    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[0]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2]).into())
            .await
            .is_ok()
    );

    let mut handles = vec![];

    let mock = MockBlockchain::new(blocks.clone());
    let (ctrl, ctrl_rx) = CtrlChannel::create();

    let (rpc_tx, rpc_rx) = mpsc::channel(10);

    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        mock.clone(),
        mock.clone(),
        mock.clone(),
        rpc_rx,
        zmq_rx,
    );

    handles.push(tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    }));

    let start_height = 2; // will be overriden by stored blocks
    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    ));

    mock.clone().await_running().await;

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[4 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[5 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash);

    let block = await_block_at_height(conn, 5).await;
    assert_eq!(block.height, 5);
    assert_eq!(block.hash, blocks[5 - 1].hash);

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

#[tokio::test]
async fn test_follower_reactor_rollback_during_start() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let mut blocks = new_random_blockchain(3);
    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[1 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[3 - 1]).into())
            .await
            .is_ok()
    );

    let initial_block_3_hash = blocks[3 - 1].hash;

    // remove last block (height 3), generate 3 new blocks with different
    // timestamp (and thus hashes) and append them to the chain.
    _ = blocks.pop();
    let more_blocks = gen_random_blocks(2, 5, Some(blocks[2 - 1].hash));
    blocks.extend(more_blocks.iter().cloned());

    let mut handles = vec![];

    let mock = MockBlockchain::new(blocks.clone());
    let (ctrl, ctrl_rx) = CtrlChannel::create();

    let (rpc_tx, rpc_rx) = mpsc::channel(10);

    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        mock.clone(),
        mock.clone(),
        mock.clone(),
        rpc_rx,
        zmq_rx,
    );

    handles.push(tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    }));

    let start_height = 1; // will be overriden by stored blocks
    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    ));

    mock.clone().await_running().await;

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[3 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[4 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[5 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    // by reading out the two last blocks first we ensure that the rollback has been enacted
    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash);

    let block = await_block_at_height(conn, 5).await;
    assert_eq!(block.height, 5);
    assert_eq!(block.hash, blocks[5 - 1].hash);

    // reading block 3, verify that it was rolled back and hash has been updated
    let block = await_block_at_height(conn, 3).await;
    assert_eq!(block.height, 3);
    assert_eq!(block.hash, blocks[3 - 1].hash);
    assert_ne!(block.hash, initial_block_3_hash);

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

#[tokio::test]
async fn test_follower_reactor_rollback_during_catchup() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let mut blocks = new_random_blockchain(5);

    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[1 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2 - 1]).into())
            .await
            .is_ok()
    );

    let mut handles = vec![];

    let mut mock = MockBlockchain::new(blocks.clone());
    let (ctrl, ctrl_rx) = CtrlChannel::create();
    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        mock.clone(),
        mock.clone(),
        mock.clone(),
        rpc_rx,
        zmq_rx,
    );

    handles.push(tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    }));

    let start_height = 3;
    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    ));

    mock.await_running().await;

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[3 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[4 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let conn = &writer.connection();
    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash);

    // roll back all but the first block (height 1), generate new blocks with mismatching hashes
    blocks.truncate(1);
    let more_blocks = gen_random_blocks(1, 5, Some(blocks[1 - 1].hash));
    blocks.extend(more_blocks.iter().cloned());
    mock.replace_blocks(blocks.clone());

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[5 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    // wait for fetcher mock to be rewinded to new start height
    mock.await_start_height(2).await;

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[2 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[3 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[4 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash); // matches new hash

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

#[tokio::test]
async fn test_follower_handle_control_signal() -> Result<()> {
    let cancel_token = CancellationToken::new();

    let blocks = new_random_blockchain(5);
    let mock = MockBlockchain::new(blocks.clone());

    // start-up at block height 3
    let (_rpc_tx, rpc_rx) = mpsc::channel(1);
    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<MockTransaction>>();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        mock.clone(),
        mock.clone(),
        mock.clone(),
        rpc_rx,
        zmq_rx,
    );
    let (event_tx, _event_rx) = mpsc::channel(1);
    let res = rec
        .handle_start(StartMessage {
            start_height: 3,
            last_hash: None,
            event_tx,
        })
        .await
        .unwrap();
    assert_eq!(res, vec![]);
    assert_eq!(rec.state.latest_block_height, Some(2));
    assert_eq!(rec.state.target_block_height, Some(5));
    assert_eq!(rec.state.mode, reconciler::Mode::Rpc);
    assert!(rec.fetcher.running());

    // start-up at block height 3 with mismatching hash for last block at 2
    let (_rpc_tx, rpc_rx) = mpsc::channel(1);
    let mock = MockBlockchain::new(blocks.clone());
    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<MockTransaction>>();
    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        mock.clone(),
        mock.clone(),
        mock.clone(),
        rpc_rx,
        zmq_rx,
    );
    let (event_tx, _event_rx) = mpsc::channel(1);
    let res = rec
        .handle_start(StartMessage {
            start_height: 3,
            last_hash: Some(BlockHash::from_byte_array([0x00; 32])), // not matching
            event_tx,
        })
        .await
        .unwrap();
    assert_eq!(res, vec![Event::BlockRemove(BlockId::Height(1))]);
    assert!(!rec.fetcher.running());

    // start-up at block height 3 with matching hash for last block at 2
    let (_rpc_tx, rpc_rx) = mpsc::channel(1);
    let mock = MockBlockchain::new(blocks.clone());
    let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<MockTransaction>>();
    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        mock.clone(),
        mock.clone(),
        mock.clone(),
        rpc_rx,
        zmq_rx,
    );
    let (event_tx, _event_rx) = mpsc::channel(1);
    let res = rec
        .handle_start(StartMessage {
            start_height: 3,
            last_hash: Some(blocks[2 - 1].hash),
            event_tx,
        })
        .await
        .unwrap();
    assert_eq!(res, vec![]);
    assert_eq!(rec.state.latest_block_height, Some(2));
    assert_eq!(rec.state.target_block_height, Some(5));
    assert_eq!(rec.state.mode, reconciler::Mode::Rpc);
    assert!(rec.fetcher.running());

    Ok(())
}

#[tokio::test]
// test_follower_reactor_rollback_zmq_message_multiple_blocks tests handling of a ZMQ
// BlockDisconnected message several blocks deep. The system should purge the blocks
// down to it and start fetching new blocks from that height.
async fn test_follower_reactor_rollback_zmq_message_multiple_blocks() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let mut blocks = new_random_blockchain(2);

    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[1 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2 - 1]).into())
            .await
            .is_ok()
    );

    let mut handles = vec![];

    let mut mock = MockBlockchain::new(blocks.clone());
    let (ctrl, ctrl_rx) = CtrlChannel::create();
    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let (zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        mock.clone(),
        mock.clone(),
        mock.clone(),
        rpc_rx,
        zmq_rx,
    );

    handles.push(tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    }));

    let start_height = 3;
    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    ));

    mock.await_running().await;

    assert!(zmq_tx.send(ZmqEvent::Connected).is_ok());

    mock.await_stopped().await;

    // add more blocks
    blocks.extend(
        gen_random_blocks(2, 5, Some(blocks[2 - 1].hash))
            .iter()
            .cloned(),
    );
    mock.replace_blocks(blocks.clone());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[3 - 1].clone()))
            .is_ok()
    );

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[4 - 1].clone()))
            .is_ok()
    );

    let conn = &writer.connection();
    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash);

    let initial_block_2_hash = blocks[2 - 1].hash;

    // roll back all but the first block (height 1), generate new blocks with mismatching hashes
    blocks.truncate(1);
    let more_blocks = gen_random_blocks(1, 5, Some(blocks[1 - 1].hash));
    blocks.extend(more_blocks.iter().cloned());
    mock.replace_blocks(blocks.clone());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockDisconnected(initial_block_2_hash))
            .is_ok()
    );

    mock.await_running().await;
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

    let block = await_block_at_height(conn, 2).await;
    assert_eq!(block.height, 2);
    assert_eq!(block.hash, blocks[2 - 1].hash); // matches new hash

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

#[tokio::test]
// test_follower_reactor_rollback_zmq_message_redundant_messages tests handling of multiple
// ZMQ BlockDisconnected messages, including a redundant message for a block that was already
// removed.
async fn test_follower_reactor_rollback_zmq_message_redundant_messages() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (reader, writer, _temp_dir) = new_test_db(&Config::try_parse()?).await?;

    let mut blocks = new_random_blockchain(2);

    let conn = &writer.connection();
    assert!(
        queries::insert_block(conn, (&blocks[1 - 1]).into())
            .await
            .is_ok()
    );
    assert!(
        queries::insert_block(conn, (&blocks[2 - 1]).into())
            .await
            .is_ok()
    );

    let mut handles = vec![];

    let mut mock = MockBlockchain::new(blocks.clone());
    let (ctrl, ctrl_rx) = CtrlChannel::create();
    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let (zmq_tx, zmq_rx) = mpsc::unbounded_channel();

    let mut rec = reconciler::Reconciler::new(
        cancel_token.clone(),
        mock.clone(),
        mock.clone(),
        mock.clone(),
        rpc_rx,
        zmq_rx,
    );

    handles.push(tokio::spawn(async move {
        rec.run(ctrl_rx).await;
    }));

    let start_height = 3;
    handles.push(reactor::run::<MockTransaction>(
        start_height,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
    ));

    mock.await_running().await;

    assert!(zmq_tx.send(ZmqEvent::Connected).is_ok());

    mock.await_stopped().await;

    // add one more block
    blocks.extend(
        gen_random_blocks(2, 3, Some(blocks[2 - 1].hash))
            .iter()
            .cloned(),
    );
    mock.replace_blocks(blocks.clone());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[3 - 1].clone()))
            .is_ok()
    );

    let conn = &writer.connection();
    let block = await_block_at_height(conn, 3).await;
    assert_eq!(block.height, 3);
    assert_eq!(block.hash, blocks[3 - 1].hash);

    let initial_block_2_hash = blocks[2 - 1].hash;
    let initial_block_3_hash = blocks[3 - 1].hash;

    // roll back all but the first block (height 1), generate new blocks with mismatching hashes
    blocks.truncate(1);
    let more_blocks = gen_random_blocks(1, 3, Some(blocks[1 - 1].hash));
    blocks.extend(more_blocks.iter().cloned());
    mock.replace_blocks(blocks.clone());

    let unknown_hash = BlockHash::from_byte_array([0xff; 32]);
    assert!(
        zmq_tx
            .send(ZmqEvent::BlockDisconnected(unknown_hash))
            .is_ok()
    );

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockDisconnected(initial_block_2_hash))
            .is_ok()
    );

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockDisconnected(initial_block_3_hash))
            .is_ok()
    );

    mock.await_running().await;
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

    assert!(
        rpc_tx
            .send((
                mock.get_blockchain_height().await.unwrap(),
                blocks[3 - 1].clone(),
            ))
            .await
            .is_ok()
    );

    let block = await_block_at_height(conn, 2).await;
    assert_eq!(block.height, 2);
    assert_eq!(block.hash, blocks[2 - 1].hash); // matches new hash

    mock.await_stopped().await;

    // add one more block
    blocks.extend(
        gen_random_blocks(4 - 1, 5 - 1, Some(blocks[3 - 1].hash))
            .iter()
            .cloned(),
    );
    mock.replace_blocks(blocks.clone());

    assert!(
        zmq_tx
            .send(ZmqEvent::BlockConnected(blocks[4 - 1].clone()))
            .is_ok()
    );

    let block = await_block_at_height(conn, 4).await;
    assert_eq!(block.height, 4);
    assert_eq!(block.hash, blocks[4 - 1].hash);

    cancel_token.cancel();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
