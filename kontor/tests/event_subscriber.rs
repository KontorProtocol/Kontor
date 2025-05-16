use anyhow::Result;
use kontor::reactor::events::{Event, EventFilter, EventSignatureFilter, EventSubscriber};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn dummy_event() -> Event {
    Event {
        contract_address: "0x123".to_string(),
        event_signature: "Test".to_string(),
        topic_keys: vec!["key1".to_string(), "key2".to_string()],
        data: serde_json::json!({"key1": "value1", "key2": "value2"}),
    }
}

#[tokio::test]
async fn test_subscriber_all() -> Result<()> {
    let (tx, rx) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let mut subscriber = EventSubscriber::new();
    let filter = EventFilter::All;
    let (id, mut receiver) = subscriber.subscribe(filter).await;

    let event = dummy_event();
    tx.send(event.clone()).await?;
    let handle = subscriber.run(cancel_token.clone(), rx);

    let received = receiver.recv().await?;
    assert_eq!(received.data, event.data);
    assert!(subscriber.unsubscribe(id).await);

    cancel_token.cancel();
    handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_subscriber_no_signature() -> Result<()> {
    let (tx, rx) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let mut subscriber = EventSubscriber::new();
    let filter = EventFilter::Contract {
        contract_address: "0x123".to_string(),
        event_signature: None,
    };
    let (id, mut receiver) = subscriber.subscribe(filter).await;

    let event = dummy_event();
    tx.send(event.clone()).await?;
    let handle = subscriber.run(cancel_token.clone(), rx);

    let received = receiver.recv().await?;
    assert_eq!(received.data, event.data);
    assert!(subscriber.unsubscribe(id).await);

    cancel_token.cancel();
    handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_subscriber_with_signature_no_topics() -> Result<()> {
    let (tx, rx) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let mut subscriber = EventSubscriber::new();
    let filter = EventFilter::Contract {
        contract_address: "0x123".to_string(),
        event_signature: Some(EventSignatureFilter {
            signature: "Test".to_string(),
            topic_values: None,
        }),
    };
    let (id, mut receiver) = subscriber.subscribe(filter).await;

    let event = dummy_event();
    tx.send(event.clone()).await?;
    let handle = subscriber.run(cancel_token.clone(), rx);

    let received = receiver.recv().await?;
    assert_eq!(received.data, event.data);
    assert!(subscriber.unsubscribe(id).await);

    cancel_token.cancel();
    handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_subscriber_with_topics() -> Result<()> {
    let (tx, rx) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let mut subscriber = EventSubscriber::new();
    let filter = EventFilter::Contract {
        contract_address: "0x123".to_string(),
        event_signature: Some(EventSignatureFilter {
            signature: "Test".to_string(),
            topic_values: Some(vec![Value::String("value1".to_string())]),
        }),
    };
    let (id, mut receiver) = subscriber.subscribe(filter).await;

    let event = dummy_event();
    tx.send(event.clone()).await?;
    let handle = subscriber.run(cancel_token.clone(), rx);

    let received = receiver.recv().await?;
    assert_eq!(received.data, event.data);
    assert!(subscriber.unsubscribe(id).await);

    cancel_token.cancel();
    handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_subscriber_wildcard() -> Result<()> {
    let (tx, rx) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let mut subscriber = EventSubscriber::new();
    let filter = EventFilter::Contract {
        contract_address: "0x123".to_string(),
        event_signature: Some(EventSignatureFilter {
            signature: "Test".to_string(),
            topic_values: Some(vec![Value::Null, Value::String("value2".to_string())]),
        }),
    };
    let (id, mut receiver) = subscriber.subscribe(filter).await;

    let event1 = dummy_event();
    let event2 = Event {
        contract_address: "0x123".to_string(),
        event_signature: "Test".to_string(),
        topic_keys: vec!["key1".to_string(), "key2".to_string()],
        data: serde_json::json!({"key1": "other", "key2": "value2"}),
    };
    tx.send(event1.clone()).await?;
    tx.send(event2.clone()).await?;
    let handle = subscriber.run(cancel_token.clone(), rx);

    let received1 = receiver.recv().await?;
    let received2 = receiver.recv().await?;
    assert_eq!(received1.data, event1.data);
    assert_eq!(received2.data, event2.data);
    assert!(subscriber.unsubscribe(id).await);

    cancel_token.cancel();
    handle.await?;
    Ok(())
}
