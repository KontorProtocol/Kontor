use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    database::types::OpResultId,
    reactor::results::{ResultEvent, ResultEventWrapper, ResultSubscriptions},
    test_utils::new_test_db,
};

#[tokio::test]
async fn test_subscribe_and_receive_event() -> Result<()> {
    let mut subscriptions = ResultSubscriptions::default();
    let op_result_id = OpResultId::builder()
        .txid("tx1".to_string())
        .input_index(1)
        .op_index(2)
        .build();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    // Subscribe
    let (_, mut receiver) = subscriptions
        .subscribe(&conn, op_result_id.clone().into())
        .await?;

    // Dispatch an event
    let event = ResultEvent::Ok {
        value: "success".to_string(),
    };
    subscriptions
        .dispatch(
            ResultEventWrapper::builder()
                .op_result_id(op_result_id.clone())
                .event(event.clone())
                .build(),
        )
        .await?;

    // Receive the event
    let received = receiver.recv().await?;
    assert_eq!(format!("{:?}", received), format!("{:?}", event));

    // Verify subscription is removed
    assert!(
        !subscriptions
            .one_shot_subscriptions
            .contains_key(&op_result_id)
    );

    Ok(())
}

#[tokio::test]
async fn test_multiple_subscribers() -> Result<()> {
    let mut subscriptions = ResultSubscriptions::default();
    let id = OpResultId::builder().txid("tx1".to_string()).build();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    // Subscribe multiple times
    let (_, mut receiver1) = subscriptions.subscribe(&conn, id.clone().into()).await?;
    let (_, mut receiver2) = subscriptions.subscribe(&conn, id.clone().into()).await?;

    // Check subscriber count
    assert_eq!(
        subscriptions
            .one_shot_subscriptions
            .get(&id)
            .unwrap()
            .count(),
        2
    );

    // Dispatch an event
    let event = ResultEvent::Ok {
        value: "success".to_string(),
    };
    subscriptions
        .dispatch(
            ResultEventWrapper::builder()
                .op_result_id(id.clone())
                .event(event.clone())
                .build(),
        )
        .await?;

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
    let id = OpResultId::builder().txid("tx1".to_string()).build();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    // Subscribe
    let (id, ..) = subscriptions.subscribe(&conn, id.clone().into()).await?;

    // Unsubscribe
    assert!(subscriptions.unsubscribe(&conn, id).await?);
    assert!(subscriptions.one_shot_subscriptions.is_empty());

    // Unsubscribe non-existent ID
    assert!(!subscriptions.unsubscribe(&conn, id).await?);

    Ok(())
}

#[tokio::test]
async fn test_dispatch_to_nonexistent_id() -> Result<()> {
    let mut subscriptions = ResultSubscriptions::default();
    let id = OpResultId::builder().txid("tx1".to_string()).build();

    // Dispatch to non-existent ID
    let event = ResultEvent::Err {
        message: "error".to_string(),
    };
    subscriptions
        .dispatch(
            ResultEventWrapper::builder()
                .op_result_id(id.clone())
                .event(event.clone())
                .build(),
        )
        .await?;
    assert!(subscriptions.one_shot_subscriptions.is_empty());

    Ok(())
}
