use anyhow::Result;
use clap::Parser;
use indexer::{
    api::{self, Env, ws::Response, ws_client::WebSocketClient},
    bitcoin_client::Client,
    config::Config,
    database::{
        queries::{insert_block, insert_contract_result, insert_transaction},
        types::{BlockRow, ContractResultRow, OpResultId, TransactionRow},
    },
    logging,
    reactor::results::{ResultEvent, ResultEventWrapper, ResultSubscriber},
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

    let foo_id = OpResultId::builder().txid("foo".to_string()).build();
    let foo_subscription_id = ws_client.subscribe(&foo_id).await?;

    let bar_id = OpResultId::builder().txid("bar".to_string()).build();
    let bar_subscription_id = ws_client.subscribe(&bar_id).await?;

    let event1 = ResultEvent::Ok {
        value: "1".to_string(),
    };
    let event2 = ResultEvent::Err {
        message: "failure".to_string(),
    };

    event_tx
        .send(
            ResultEventWrapper::builder()
                .op_result_id(foo_id.clone())
                .event(event1.clone())
                .build(),
        )
        .await?;
    event_tx
        .send(
            ResultEventWrapper::builder()
                .op_result_id(bar_id.clone())
                .event(event2.clone())
                .build(),
        )
        .await?;

    assert_eq!(
        ws_client.next().await?,
        Response::Result {
            id: foo_subscription_id,
            result: event1.clone()
        }
    );

    assert_eq!(
        ws_client.next().await?,
        Response::Result {
            id: bar_subscription_id,
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
    insert_transaction(
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
        ContractResultRow::builder().height(1).tx_index(1).build(),
    )
    .await?;

    let test_id = OpResultId::builder().txid("test".to_string()).build();
    let test_subscription_id = ws_client.subscribe(&test_id).await?;

    assert_eq!(
        ws_client.next().await?,
        Response::Result {
            id: test_subscription_id,
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
