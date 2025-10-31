use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    database::{
        queries::{insert_block, insert_contract},
        types::{BlockRow, ContractRow, OpResultId},
    },
    reactor::results::{ResultEvent, ResultEventFilter, ResultEventMetadata, ResultSubscriptions},
    test_utils::{new_mock_block_hash, new_test_db},
};
use testlib::ContractAddress;

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
        metadata: ResultEventMetadata::builder()
            .op_result_id(op_result_id.clone())
            .build(),
        value: "success".to_string(),
    };
    subscriptions.dispatch(event.clone()).await?;

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
        metadata: ResultEventMetadata::builder()
            .op_result_id(id.clone())
            .build(),
        value: "success".to_string(),
    };
    subscriptions.dispatch(event.clone()).await?;

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
    assert!(subscriptions.unsubscribe(id).await?);
    assert!(subscriptions.one_shot_subscriptions.is_empty());

    // Unsubscribe non-existent ID
    assert!(!subscriptions.unsubscribe(id).await?);

    Ok(())
}

#[tokio::test]
async fn test_dispatch_to_nonexistent_id() -> Result<()> {
    let mut subscriptions = ResultSubscriptions::default();
    let id = OpResultId::builder().txid("tx1".to_string()).build();

    // Dispatch to non-existent ID
    let event = ResultEvent::Err {
        metadata: ResultEventMetadata::builder()
            .op_result_id(id.clone())
            .build(),
        message: "error".to_string(),
    };
    subscriptions.dispatch(event.clone()).await?;
    assert!(subscriptions.one_shot_subscriptions.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_subscriber_recurring() -> Result<()> {
    let mut subscriptions = ResultSubscriptions::default();

    let (reader, _writer, _dir) = new_test_db(&Config::try_parse()?).await?;
    let conn = reader.connection().await?;

    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(new_mock_block_hash(1))
            .build(),
    )
    .await?;
    let func_name = "foo";
    let contract_address = ContractAddress {
        name: "test".to_string(),
        height: 1,
        tx_index: 1,
    };
    insert_contract(
        &conn,
        ContractRow::builder()
            .name(contract_address.name.clone())
            .height(contract_address.height)
            .tx_index(contract_address.tx_index)
            .bytes(vec![])
            .build(),
    )
    .await?;

    let contract_address_1 = ContractAddress {
        name: "test1".to_string(),
        height: 1,
        tx_index: 1,
    };
    insert_contract(
        &conn,
        ContractRow::builder()
            .name(contract_address_1.name.clone())
            .height(contract_address_1.height)
            .tx_index(contract_address_1.tx_index)
            .bytes(vec![])
            .build(),
    )
    .await?;

    // Start the run task
    let (sub_id_1, mut receiver1) = subscriptions
        .subscribe(&conn, ResultEventFilter::All)
        .await?;
    let (sub_id_2, mut receiver2) = subscriptions
        .subscribe(
            &conn,
            ResultEventFilter::Contract {
                contract_address: contract_address.clone(),
                func_name: None,
            },
        )
        .await?;
    let (sub_id_3, mut receiver3) = subscriptions
        .subscribe(
            &conn,
            ResultEventFilter::Contract {
                contract_address: contract_address.clone(),
                func_name: Some(func_name.to_string()),
            },
        )
        .await?;

    let event = ResultEvent::Ok {
        metadata: ResultEventMetadata::builder()
            .contract_address(contract_address.clone())
            .func_name(func_name.to_string())
            .build(),
        value: "".to_string(),
    };
    subscriptions.dispatch(event.clone()).await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), receiver1.recv()).await??,
        event
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), receiver2.recv()).await??,
        event
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), receiver3.recv()).await??,
        event
    );

    let event = ResultEvent::Ok {
        metadata: ResultEventMetadata::builder()
            .contract_address(contract_address.clone())
            .func_name("bar".to_string())
            .build(),
        value: "".to_string(),
    };

    subscriptions.dispatch(event.clone()).await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), receiver1.recv()).await??,
        event
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), receiver2.recv()).await??,
        event
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver3.recv())
            .await
            .is_err()
    );

    let event = ResultEvent::Ok {
        metadata: ResultEventMetadata::builder()
            .contract_address(contract_address_1.clone())
            .func_name(func_name.to_string())
            .build(),
        value: "".to_string(),
    };

    subscriptions.dispatch(event.clone()).await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), receiver1.recv()).await??,
        event
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver2.recv())
            .await
            .is_err(),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receiver3.recv())
            .await
            .is_err()
    );

    assert!(subscriptions.unsubscribe(sub_id_2).await?);
    assert!(
        subscriptions
            .recurring_subscriptions
            .1
            .contains_key(&contract_address.to_string())
    );

    assert!(subscriptions.unsubscribe(sub_id_3).await?);
    assert!(
        !subscriptions
            .recurring_subscriptions
            .1
            .contains_key(&contract_address.to_string())
    );

    assert!(subscriptions.unsubscribe(sub_id_1).await?);
    assert!(subscriptions.subscription_ids.is_empty());
    assert!(subscriptions.recurring_subscriptions.0.is_empty());

    Ok(())
}
