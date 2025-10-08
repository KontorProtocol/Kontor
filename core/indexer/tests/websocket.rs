use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use indexer::{
    api::{
        self, Env,
        ws::{Request, Response},
    },
    bitcoin_client::Client,
    config::Config,
    database::{
        queries::{insert_block, insert_contract_result, insert_transaction},
        types::{BlockRow, ContractResultId, ContractResultRow, TransactionRow},
    },
    logging,
    reactor::results::{ResultEvent, ResultSubscriber},
    test_utils::{new_mock_block_hash, new_test_db},
};
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
    let result_subscriber = ResultSubscriber::default();
    let mut handles = vec![];

    // Run the event subscriber
    handles.push(result_subscriber.run(cancel_token.clone(), event_rx));

    // Run the API server
    handles.push(
        api::run(Env {
            config: config.clone(),
            cancel_token: cancel_token.clone(),
            reader: reader.clone(),
            result_subscriber: result_subscriber.clone(), // Clone for shared use
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
    let foo_id = ContractResultId::builder().txid("foo".to_string()).build();
    let subscribe = serde_json::to_string(&Request::Subscribe { id: foo_id.clone() })?;
    ws_stream.send(Message::Text(subscribe.into())).await?;
    let received = ws_stream.next().await.unwrap()?;
    let subscribe_response: Response = serde_json::from_str(received.to_text()?)?;
    let res_id = match subscribe_response {
        Response::SubscribeResponse { id } => id,
        _ => anyhow::bail!(
            "Expected SubscribeResponse for All, got {:?}",
            subscribe_response
        ),
    };
    assert_eq!(foo_id, res_id);

    let bar_id = ContractResultId::builder().txid("bar".to_string()).build();
    let subscribe = serde_json::to_string(&Request::Subscribe { id: bar_id.clone() })?;
    ws_stream
        .send(Message::Text(subscribe.to_string().into()))
        .await?;
    let received = ws_stream.next().await.unwrap()?;
    let subscribe_response: Response = serde_json::from_str(received.to_text()?)?;
    let res_id = match subscribe_response {
        Response::SubscribeResponse { id } => id,
        _ => anyhow::bail!(
            "Expected SubscribeResponse for Specific, got {:?}",
            subscribe_response
        ),
    };
    assert_eq!(bar_id, res_id);

    // Test 3: Receive events
    let event1 = ResultEvent::Ok {
        value: Some("1".to_string()),
    };
    let event2 = ResultEvent::Err {
        message: Some("failure".to_string()),
    };

    // // Send events
    event_tx.send((foo_id.clone(), event1.clone())).await?;
    event_tx.send((bar_id.clone(), event2.clone())).await?;

    // Receive first event for id_all
    let received = ws_stream.next().await.unwrap()?;
    let event_response: Response = serde_json::from_str(received.to_text()?)?;
    assert_eq!(
        event_response,
        Response::Result {
            id: foo_id.clone(),
            result: event1.clone()
        }
    );

    // Receive event for id_specific
    let received = ws_stream.next().await.unwrap()?;
    let event_response: Response = serde_json::from_str(received.to_text()?)?;
    assert_eq!(
        event_response,
        Response::Result {
            id: bar_id.clone(),
            result: event2.clone()
        }
    );

    let conn = reader.connection().await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(new_mock_block_hash(1))
            .build(),
    )
    .await?;
    let tx_id = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .tx_index(1)
            .txid("test".to_string())
            .build(),
    )
    .await?;
    insert_contract_result(
        &conn,
        ContractResultRow::builder().height(1).tx_id(tx_id).build(),
    )
    .await?;

    let test_id = ContractResultId::builder().txid("test".to_string()).build();
    let subscribe = serde_json::to_string(&Request::Subscribe {
        id: test_id.clone(),
    })?;
    ws_stream
        .send(Message::Text(subscribe.to_string().into()))
        .await?;
    let received = ws_stream.next().await.unwrap()?;
    let subscribe_response: Response = serde_json::from_str(received.to_text()?)?;
    let res_id = match subscribe_response {
        Response::SubscribeResponse { id } => id,
        _ => anyhow::bail!(
            "Expected SubscribeResponse for Specific, got {:?}",
            subscribe_response
        ),
    };
    assert_eq!(test_id, res_id);

    let received = ws_stream.next().await.unwrap()?;
    let event_response: Response = serde_json::from_str(received.to_text()?)?;
    assert_eq!(
        event_response,
        Response::Result {
            id: test_id.clone(),
            result: ResultEvent::Err { message: None }
        }
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
