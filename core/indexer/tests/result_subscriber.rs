use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    database::types::OpResultId,
    reactor::results::{ResultEvent, ResultEventMetadata, ResultSubscriber},
    test_utils::new_test_db,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_subscriber_subscribe_and_receive_event() -> Result<()> {
    let mut subscriber = ResultSubscriber::default();
    let (tx, rx) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let id = OpResultId::builder()
        .txid("tx1".to_string())
        .input_index(1)
        .op_index(2)
        .build();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    // Start the run task
    let handle = subscriber.run(cancel_token.clone(), rx);

    // Subscribe
    let (_, mut receiver) = subscriber.subscribe(&conn, id.clone().into()).await?;

    // Send an event through the mpsc channel
    let event = ResultEvent::Ok {
        metadata: ResultEventMetadata::builder().op_result_id(id).build(),
        value: "success".to_string(),
    };
    tx.send(event.clone()).await?;

    // Receive the event
    let received = tokio::time::timeout(Duration::from_secs(1), receiver.recv()).await??;
    assert_eq!(format!("{:?}", received), format!("{:?}", event));

    // Clean up
    cancel_token.cancel();
    handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_subscriber_multiple_subscribers() -> Result<()> {
    let mut subscriber = ResultSubscriber::default();
    let (tx, rx) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let id = OpResultId::builder().txid("tx1".to_string()).build();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    // Start the run task
    let handle = subscriber.run(cancel_token.clone(), rx);

    // Subscribe multiple times
    let (_, mut receiver1) = subscriber.subscribe(&conn, id.clone().into()).await?;
    let (_, mut receiver2) = subscriber.subscribe(&conn, id.clone().into()).await?;

    // Send an event
    let event = ResultEvent::Ok {
        metadata: ResultEventMetadata::builder().op_result_id(id).build(),
        value: "success".to_string(),
    };
    tx.send(event.clone()).await?;

    // Both receivers should get the event
    let received1 = tokio::time::timeout(Duration::from_secs(1), receiver1.recv()).await??;
    let received2 = tokio::time::timeout(Duration::from_secs(1), receiver2.recv()).await??;
    assert_eq!(format!("{:?}", received1), format!("{:?}", event));
    assert_eq!(format!("{:?}", received2), format!("{:?}", event));

    // Clean up
    cancel_token.cancel();
    handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_subscriber_unsubscribe() -> Result<()> {
    let mut subscriber = ResultSubscriber::default();
    let id = OpResultId::builder().txid("tx1".to_string()).build();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    // Subscribe
    let (subscription_id, ..) = subscriber.subscribe(&conn, id.into()).await?;

    // Unsubscribe
    assert!(subscriber.unsubscribe(subscription_id).await?);

    // Unsubscribe non-existent ID
    assert!(!subscriber.unsubscribe(subscription_id).await?);

    Ok(())
}

#[tokio::test]
async fn test_subscriber_dispatch_nonexistent_id() -> Result<()> {
    let subscriber = ResultSubscriber::default();
    let (tx, rx) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let id = OpResultId::builder().txid("tx1".to_string()).build();

    // Start the run task
    let handle = subscriber.run(cancel_token.clone(), rx);

    // Send an event for a non-existent subscription
    let event = ResultEvent::Err {
        metadata: ResultEventMetadata::builder().op_result_id(id).build(),
        message: "error".to_string(),
    };
    tx.send(event.clone()).await?;

    // Give the run task time to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Clean up
    cancel_token.cancel();
    handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_subscriber_cancellation() -> Result<()> {
    let mut subscriber = ResultSubscriber::default();
    let (tx, rx) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let id = OpResultId::builder().txid("tx1".to_string()).build();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    // Start the run task
    let handle = subscriber.run(cancel_token.clone(), rx);

    // Subscribe
    let (_, mut receiver) = subscriber.subscribe(&conn, id.clone().into()).await?;

    // Cancel the task
    cancel_token.cancel();

    // Verify task terminates
    handle.await?;

    // Send an event after cancellation (should not be processed)
    let event = ResultEvent::Ok {
        metadata: ResultEventMetadata::builder().op_result_id(id).build(),
        value: "success".to_string(),
    };
    let send_result = tx.send(event.clone()).await;
    assert!(send_result.is_err()); // Send succeeds, but no processing

    // Try to receive (should fail due to no active sender)
    let result = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;
    assert!(result.is_err());

    Ok(())
}
