use anyhow::Result;
use clap::Parser;
use indexer::{
    api::{self, Env, ws::Response, ws_client::WebSocketClient},
    bitcoin_client::Client,
    config::Config,
    database::{
        queries::{insert_block, insert_contract_result, insert_transaction},
        types::{BlockRow, ContractResultId, ContractResultRow, TransactionRow},
    },
    logging,
    reactor::results::{ResultEvent, ResultSubscriber},
    runtime::Runtime,
    test_utils::{new_mock_block_hash, new_test_db},
};
use tokio::sync::mpsc;
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

    handles.push(result_subscriber.run(cancel_token.clone(), event_rx));

    handles.push(
        api::run(Env {
            config: config.clone(),
            cancel_token: cancel_token.clone(),
            reader: reader.clone(),
            result_subscriber: result_subscriber.clone(), // Clone for shared use
            bitcoin: bitcoin.clone(),
            runtime: Runtime::new_read_only(&reader).await?,
        })
        .await?,
    );

    let mut ws_client = WebSocketClient::new().await?;

    ws_client.ping().await?;

    let foo_id = ContractResultId::builder().txid("foo".to_string()).build();
    ws_client.subscribe(&foo_id).await?;

    let bar_id = ContractResultId::builder().txid("bar".to_string()).build();
    ws_client.subscribe(&bar_id).await?;

    let event1 = ResultEvent::Ok {
        value: "1".to_string(),
    };
    let event2 = ResultEvent::Err {
        message: "failure".to_string(),
    };

    event_tx.send((foo_id.clone(), event1.clone())).await?;
    event_tx.send((bar_id.clone(), event2.clone())).await?;

    assert_eq!(
        ws_client.next().await?,
        Response::Result {
            id: foo_id.clone(),
            result: event1.clone()
        }
    );

    assert_eq!(
        ws_client.next().await?,
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
    ws_client.subscribe(&test_id).await?;

    assert_eq!(
        ws_client.next().await?,
        Response::Result {
            id: test_id.clone(),
            result: ResultEvent::Err {
                message: "Procedure failed. Error messages are ephemeral.".to_string()
            }
        }
    );

    ws_client.close().await?;

    cancel_token.cancel();
    for handle in handles {
        handle.await?;
    }

    Ok(())
}
