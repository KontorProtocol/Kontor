use anyhow::Result;
use kontor::reactor::events::{Event, TopicTree};
use serde_json::Value;

fn dummy_event() -> Event {
    Event {
        contract_address: "0x123".to_string(),
        event_signature: "Test".to_string(),
        topic_keys: vec!["key1".to_string(), "key2".to_string()],
        data: serde_json::json!({"key1": "value1", "key2": "value2"}),
    }
}

#[tokio::test]
async fn test_add_single_topic() -> Result<()> {
    let mut tree = TopicTree::new();
    let id = 1;
    let topics = vec![Value::String("value1".to_string())];
    let mut rx = tree.add(id, &topics);

    assert!(tree.sub_ids.is_empty());
    assert_eq!(tree.children.len(), 1);
    assert!(tree.children.contains_key(&Value::String("value1".into())));

    let event = Event {
        contract_address: "0x123".to_string(),
        event_signature: "Test".to_string(),
        topic_keys: vec!["key1".to_string()],
        data: serde_json::json!({"key1": "value1"}),
    };
    tree.dispatch(&event, &topics, 0);
    assert_eq!(rx.recv().await?.data, event.data);
    Ok(())
}

#[tokio::test]
async fn test_add_multiple_topics() -> Result<()> {
    let mut tree = TopicTree::new();
    let id = 1;
    let topics = vec![
        Value::String("value1".to_string()),
        Value::String("value2".to_string()),
    ];
    let mut rx = tree.add(id, &topics);

    assert!(tree.sub_ids.is_empty());
    assert_eq!(tree.children.len(), 1);
    let child1 = tree
        .children
        .get(&Value::String("value1".to_string()))
        .unwrap();
    assert!(child1.sub_ids.is_empty());
    assert_eq!(child1.children.len(), 1);
    assert!(
        child1
            .children
            .contains_key(&Value::String("value2".to_string()))
    );

    let event = dummy_event();
    tree.dispatch(&event, &topics, 0);
    assert_eq!(rx.recv().await?.data, event.data);
    Ok(())
}

#[tokio::test]
async fn test_add_wildcard() -> Result<()> {
    let mut tree = TopicTree::new();
    let id = 1;
    let topics = vec![Value::Null, Value::String("value2".to_string())];
    let mut rx = tree.add(id, &topics);

    assert!(tree.sub_ids.is_empty());
    assert_eq!(tree.children.len(), 1);
    let child1 = tree.children.get(&Value::Null).unwrap();
    assert!(child1.sub_ids.is_empty());
    assert_eq!(child1.children.len(), 1);
    assert!(
        child1
            .children
            .contains_key(&Value::String("value2".to_string()))
    );

    let event = dummy_event();
    tree.dispatch(&event, &topics, 0);
    assert_eq!(rx.recv().await?.data, event.data);
    Ok(())
}

#[tokio::test]
async fn test_remove_single_topic() -> Result<()> {
    let mut tree = TopicTree::new();
    let id = 1;
    let topics = vec![Value::String("value1".to_string())];
    tree.add(id, &topics);
    assert!(tree.remove(id, &topics, 0));

    assert!(tree.sub_ids.is_empty());
    assert!(tree.children.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_remove_multiple_topics() -> Result<()> {
    let mut tree = TopicTree::new();
    let id = 1;
    let topics = vec![
        Value::String("value1".to_string()),
        Value::String("value2".to_string()),
    ];
    tree.add(id, &topics);
    assert!(tree.remove(id, &topics, 0));

    assert!(tree.sub_ids.is_empty());
    assert!(tree.children.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_add_remove_multiple_subs() -> Result<()> {
    let mut tree = TopicTree::new();
    let id1 = 1;
    let id2 = 2;
    let topics1 = vec![Value::String("value1".to_string())];
    let topics2 = vec![Value::String("value2".to_string())];

    tree.add(id1, &topics1);
    tree.add(id2, &topics2);

    assert!(tree.sub_ids.is_empty());
    assert_eq!(tree.children.len(), 2);

    assert!(tree.remove(id1, &topics1, 0));
    assert_eq!(tree.children.len(), 1);
    assert!(
        tree.children
            .contains_key(&Value::String("value2".to_string()))
    );

    assert!(tree.remove(id2, &topics2, 0));
    assert!(tree.sub_ids.is_empty());
    assert!(tree.children.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_remove_nonexistent() -> Result<()> {
    let mut tree = TopicTree::new();
    let id = 1;
    let topics = vec![Value::String("value1".to_string())];
    tree.add(id, &topics);

    assert!(!tree.remove(2, &topics, 0));
    assert!(tree.sub_ids.is_empty());
    assert_eq!(tree.children.len(), 1);
    Ok(())
}

#[tokio::test]
async fn test_remove_first_shared_prefix() -> Result<()> {
    let mut tree = TopicTree::new();
    let id1 = 1;
    let id2 = 2;
    let topics1 = vec![
        Value::String("value1".to_string()),
        Value::String("value2".to_string()),
    ];
    let topics2 = vec![
        Value::String("value1".to_string()),
        Value::String("value3".to_string()),
    ];

    tree.add(id1, &topics1);
    tree.add(id2, &topics2);

    assert!(tree.sub_ids.is_empty());
    assert_eq!(tree.children.len(), 1);
    let child1 = tree
        .children
        .get(&Value::String("value1".to_string()))
        .unwrap();
    assert!(child1.sub_ids.is_empty());
    assert_eq!(child1.children.len(), 2);

    assert!(tree.remove(id1, &topics1, 0));
    assert_eq!(tree.children.len(), 1);
    let child1 = tree
        .children
        .get(&Value::String("value1".to_string()))
        .unwrap();
    assert!(
        !child1
            .children
            .contains_key(&Value::String("value2".to_string()))
    );
    assert_eq!(
        child1
            .children
            .get(&Value::String("value3".to_string()))
            .unwrap()
            .sub_ids,
        vec![id2]
    );
    Ok(())
}

#[tokio::test]
async fn test_broadcast_all_leaves() -> Result<()> {
    let mut tree = TopicTree::new();
    let id1 = 1;
    let id2 = 2;
    let topics1 = vec![Value::String("value1".to_string())];
    let topics2 = vec![
        Value::String("value1".to_string()),
        Value::String("value2".to_string()),
    ];

    let mut rx1 = tree.add(id1, &topics1);
    let mut rx2 = tree.add(id2, &topics2);

    assert!(tree.sub_ids.is_empty());
    assert_eq!(tree.children.len(), 1);
    let child1 = tree
        .children
        .get(&Value::String("value1".to_string()))
        .unwrap();
    assert_eq!(child1.sub_ids, vec![id1]);
    assert_eq!(child1.children.len(), 1);
    let child2 = child1
        .children
        .get(&Value::String("value2".to_string()))
        .unwrap();
    assert_eq!(child2.sub_ids, vec![id2]);

    let event = dummy_event();
    tree.dispatch(&event, &topics1, 0);
    tree.dispatch(&event, &topics2, 0);

    assert_eq!(rx1.recv().await?.data, event.data);
    assert_eq!(rx2.recv().await?.data, event.data);
    Ok(())
}

#[tokio::test]
async fn test_truncate_topics() -> Result<()> {
    let mut tree = TopicTree::new();
    let id = 1;
    let topics = vec![
        Value::String("a".to_string()),
        Value::String("b".to_string()),
        Value::String("c".to_string()),
    ];
    let mut rx = tree.add(id, &topics);

    assert!(tree.sub_ids.is_empty());
    assert_eq!(tree.children.len(), 1);
    let child1 = tree.children.get(&Value::String("a".to_string())).unwrap();
    assert!(child1.sub_ids.is_empty());
    assert_eq!(child1.children.len(), 1);
    let child2 = child1
        .children
        .get(&Value::String("b".to_string()))
        .unwrap();
    assert!(child2.sub_ids.is_empty());
    let child3 = child2
        .children
        .get(&Value::String("c".to_string()))
        .unwrap();
    assert_eq!(child3.sub_ids, vec![id]);

    let event = Event {
        contract_address: "0x123".to_string(),
        event_signature: "Test".to_string(),
        topic_keys: vec![
            "key1".to_string(),
            "key2".to_string(),
            "key3".to_string(),
            "key4".to_string(),
        ],
        data: serde_json::json!({"key1": "a", "key2": "b", "key3": "c", "key4": "d"}),
    };
    tree.dispatch(&event, &topics, 0);

    let received = rx.recv().await?;
    assert_eq!(received.topic_keys.len(), 4);
    assert_eq!(received.data, event.data);
    Ok(())
}

#[tokio::test]
async fn test_wildcard_broadcast() -> Result<()> {
    let mut tree = TopicTree::new();
    let id = 1;
    let topics = vec![Value::Null, Value::String("value2".to_string())];
    let mut rx = tree.add(id, &topics);

    let event1 = dummy_event();
    let event2 = Event {
        contract_address: "0x123".to_string(),
        event_signature: "Test".to_string(),
        topic_keys: vec!["key1".to_string(), "key2".to_string()],
        data: serde_json::json!({"key1": "other", "key2": "value2"}),
    };

    tree.dispatch(&event1, &topics, 0);
    tree.dispatch(&event2, &topics, 0);

    let received1 = rx.recv().await?;
    let received2 = rx.recv().await?;
    assert_eq!(received1.data, event1.data);
    assert_eq!(received2.data, event2.data);
    Ok(())
}

#[tokio::test]
async fn test_wildcard_with_non_null_event_value() -> Result<()> {
    let mut tree = TopicTree::new();
    let id = 1;
    let topics = vec![Value::Null, Value::String("value2".to_string())];
    let mut rx = tree.add(id, &topics);

    assert!(tree.sub_ids.is_empty());
    assert_eq!(tree.children.len(), 1);
    let child1 = tree.children.get(&Value::Null).unwrap();
    assert!(child1.sub_ids.is_empty());
    assert_eq!(child1.children.len(), 1);
    assert!(
        child1
            .children
            .contains_key(&Value::String("value2".to_string()))
    );

    let event = Event {
        contract_address: "0x123".to_string(),
        event_signature: "Test".to_string(),
        topic_keys: vec!["key1".to_string(), "key2".to_string()],
        data: serde_json::json!({"key1": "other", "key2": "value2"}),
    };

    let event_topic_values = vec![
        Value::String("other".to_string()),
        Value::String("value2".to_string()),
    ];
    tree.dispatch(&event, &event_topic_values, 0);

    let received = rx.recv().await?;
    assert_eq!(received.data, event.data);
    Ok(())
}
