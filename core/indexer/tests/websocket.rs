use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use indexer::{
    api::{self, Env, ws::Response},
    bitcoin_client::Client,
    config::Config,
    logging,
    reactor::events::{Event, EventSubscriber},
    test_utils::new_test_db,
};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::Message};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_websocket_server() -> Result<()> {
    logging::setup();
    let cancel_token = CancellationToken::new();
    let config = Config::try_parse()?;
    let (reader, _writer, _temp_dir) = new_test_db(&config).await?;
    let bitcoin = Client::new_from_config(&config)?;
    let (event_tx, event_rx) = mpsc::channel(10); // Channel to send test events
    let event_subscriber = EventSubscriber::new();
    let mut handles = vec![];

    // Run the event subscriber
    handles.push(event_subscriber.run(cancel_token.clone(), event_rx));

    // Run the API server
    handles.push(
        api::run(Env {
            config: config.clone(),
            cancel_token: cancel_token.clone(),
            reader: reader.clone(),
            event_subscriber: event_subscriber.clone(), // Clone for shared use
            bitcoin: bitcoin.clone(),
        })
        .await?,
    );

    // Connect to the WebSocket server
    let url = format!("wss://localhost:{}/ws", config.api_port);

    let mut root_store = rustls::RootCertStore::empty();

    #[cfg(not(windows))]
    {
        let certs = rustls_native_certs::load_native_certs().unwrap();
        for cert in certs {
            root_store.add(cert)?;
        }
    }

    #[cfg(windows)]
    {
        use std::env;
        use std::fs;
        use std::io::BufReader;

        let cert_file_path =
            env::var("ROOT_CA_FILE").expect("ROOT_CA_FILE env var not set on Windows");
        let cert_file = fs::File::open(cert_file_path)?;
        let mut reader = BufReader::new(cert_file);
        let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
        root_store.add_parsable_certificates(certs);
    }

    let connector = Connector::Rustls(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    ));

    let (mut ws_stream, _) =
        connect_async_tls_with_config(url, None, false, Some(connector)).await?;

    // Test 1: Ping/Pong
    let ping_data = vec![1, 2, 3];
    ws_stream
        .send(Message::Ping(ping_data.clone().into()))
        .await?;
    let received = ws_stream.next().await.unwrap()?;
    assert_eq!(received, Message::Pong(ping_data.into()));

    // Test 2: Subscribe to two filters
    // Filter 1: All events
    let subscribe_all = json!({"type": "Subscribe", "filter": {"type": "All"}});
    ws_stream
        .send(Message::Text(subscribe_all.to_string().into()))
        .await?;
    let received = ws_stream.next().await.unwrap()?;
    let subscribe_response: Response = serde_json::from_str(received.to_text()?)?;
    let id_all = match subscribe_response {
        Response::SubscribeResponse { id } => id,
        _ => anyhow::bail!(
            "Expected SubscribeResponse for All, got {:?}",
            subscribe_response
        ),
    };

    // Filter 2: Specific contract and signature
    let subscribe_specific = json!({
        "type": "Subscribe",
        "filter": {
            "type": "Contract",
            "contract_address": "0x123",
            "event_signature": {"signature": "Test", "topic_values": null}
        }
    });
    ws_stream
        .send(Message::Text(subscribe_specific.to_string().into()))
        .await?;
    let received = ws_stream.next().await.unwrap()?;
    let subscribe_response: Response = serde_json::from_str(received.to_text()?)?;
    let id_specific = match subscribe_response {
        Response::SubscribeResponse { id } => id,
        _ => anyhow::bail!(
            "Expected SubscribeResponse for Specific, got {:?}",
            subscribe_response
        ),
    };

    // Test 3: Receive events
    let event1 = Event {
        contract_address: "0x123".to_string(),
        event_signature: "Test".to_string(),
        topic_keys: vec!["key1".to_string(), "key2".to_string()],
        data: json!({"key1": "value1", "key2": "value2"}),
    };
    let event2 = Event {
        contract_address: "0x456".to_string(),
        event_signature: "Other".to_string(),
        topic_keys: vec!["key3".to_string()],
        data: json!({"key3": "value3"}),
    };

    // Send events
    event_tx.send(event1.clone()).await?;
    event_tx.send(event2.clone()).await?;

    // Receive first event for id_all
    let received = ws_stream.next().await.unwrap()?;
    let event_response: Response = serde_json::from_str(received.to_text()?)?;
    assert_eq!(
        event_response,
        Response::Event {
            id: id_all,
            event: event1.data.clone()
        }
    );

    // Receive event for id_specific
    let received = ws_stream.next().await.unwrap()?;
    let event_response: Response = serde_json::from_str(received.to_text()?)?;
    assert_eq!(
        event_response,
        Response::Event {
            id: id_specific,
            event: event1.data
        }
    );

    // Receive second event for id_all
    let received = ws_stream.next().await.unwrap()?;
    let event_response: Response = serde_json::from_str(received.to_text()?)?;
    assert_eq!(
        event_response,
        Response::Event {
            id: id_all,
            event: event2.data
        }
    );

    // Test 4: Unsubscribe from both
    let unsubscribe_all = json!({"type": "Unsubscribe", "id": id_all});
    ws_stream
        .send(Message::Text(unsubscribe_all.to_string().into()))
        .await?;
    let received = ws_stream.next().await.unwrap()?;
    let unsubscribe_response: Response = serde_json::from_str(received.to_text()?)?;
    assert_eq!(
        unsubscribe_response,
        Response::UnsubscribeResponse { id: id_all }
    );

    let unsubscribe_specific = json!({"type": "Unsubscribe", "id": id_specific});
    ws_stream
        .send(Message::Text(unsubscribe_specific.to_string().into()))
        .await?;
    let received = ws_stream.next().await.unwrap()?;
    let unsubscribe_response: Response = serde_json::from_str(received.to_text()?)?;
    assert_eq!(
        unsubscribe_response,
        Response::UnsubscribeResponse { id: id_specific }
    );

    // Test 5: Close the connection
    ws_stream.send(Message::Close(None)).await?;
    let close_msg = ws_stream.next().await.unwrap()?;
    assert!(close_msg.is_close());

    // Cleanup
    cancel_token.cancel();
    for handle in handles {
        handle.await?;
    }
    Ok(())
}
