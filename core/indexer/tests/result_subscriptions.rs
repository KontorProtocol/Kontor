use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    database::types::ContractResultId,
    reactor::results::{ResultEvent, ResultSubscriptions},
    test_utils::new_test_db,
};

#[tokio::test]
async fn test_subscribe_and_receive_event() -> Result<()> {
    let mut subscriptions = ResultSubscriptions::default();
    let id = ContractResultId::builder()
        .txid("tx1".to_string())
        .input_index(1)
        .op_index(2)
        .build();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    // Subscribe
    let mut receiver = subscriptions.subscribe(&conn, &id).await?;

    // Dispatch an event
    let event = ResultEvent::Ok {
        value: Some("success".to_string()),
    };
    subscriptions.dispatch(&id, event.clone());

    // Receive the event
    let received = receiver.recv().await?;
    assert_eq!(format!("{:?}", received), format!("{:?}", event));

    // Verify subscription is removed
    assert!(!subscriptions.subscriptions.contains_key(&id));

    Ok(())
}

#[tokio::test]
async fn test_multiple_subscribers() -> Result<()> {
    let mut subscriptions = ResultSubscriptions::default();
    let id = ContractResultId::builder().txid("tx1".to_string()).build();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    // Subscribe multiple times
    let mut receiver1 = subscriptions.subscribe(&conn, &id).await?;
    let mut receiver2 = subscriptions.subscribe(&conn, &id).await?;

    // Check subscriber count
    assert_eq!(subscriptions.subscriptions.get(&id).unwrap().count(), 2);

    // Dispatch an event
    let event = ResultEvent::Ok {
        value: Some("success".to_string()),
    };
    subscriptions.dispatch(&id, event.clone());

    // Both receivers should get the event
    let received1 = receiver1.recv().await?;
    let received2 = receiver2.recv().await?;
    assert_eq!(format!("{:?}", received1), format!("{:?}", event));
    assert_eq!(format!("{:?}", received2), format!("{:?}", event));

    Ok(())
}

#[tokio::test]
async fn test_unsubscribe() -> Result<()> {
    let mut subscriptions = ResultSubscriptions::default();
    let id = ContractResultId::builder().txid("tx1".to_string()).build();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    // Subscribe
    subscriptions.subscribe(&conn, &id).await?;

    // Unsubscribe
    assert!(subscriptions.unsubscribe(&id));
    assert!(subscriptions.subscriptions.is_empty());

    // Unsubscribe non-existent ID
    assert!(!subscriptions.unsubscribe(&id));

    Ok(())
}

#[tokio::test]
async fn test_dispatch_to_nonexistent_id() -> Result<()> {
    let mut subscriptions = ResultSubscriptions::default();
    let id = ContractResultId::builder().txid("tx1".to_string()).build();

    // Dispatch to non-existent ID
    let event = ResultEvent::Err {
        message: Some("error".to_string()),
    };
    subscriptions.dispatch(&id, event);
    assert!(subscriptions.subscriptions.is_empty());

    Ok(())
}
