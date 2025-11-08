use anyhow::Result;
use indexer::{
    api::{self, Env, ws::Response, ws_client::WebSocketClient},
    bitcoin_client::Client,
    config::Config,
    database::{
        queries::{insert_block, insert_contract, insert_contract_result, insert_transaction},
        types::{BlockRow, ContractResultRow, ContractRow, OpResultId, TransactionRow},
    },
    logging,
    reactor::results::{ResultEvent, ResultEventMetadata, ResultSubscriber},
    runtime::Runtime,
    test_utils::{new_mock_block_hash, new_test_db},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_websocket_server() -> Result<()> {
    logging::setup();
    let cancel_token = CancellationToken::new();
    let (reader, _writer, _temp_dir) = new_test_db().await?;
    let bitcoin = Client::new("".to_string(), "".to_string(), "".to_string())?;
    let (event_tx, event_rx) = mpsc::channel(10); // Channel to send test events
    let result_subscriber = ResultSubscriber::default();
    let mut handles = vec![];

    handles.push(result_subscriber.run(cancel_token.clone(), event_rx));

    handles.push(
        api::run(Env {
            config: Config::new_na(),
            cancel_token: cancel_token.clone(),
            reader: reader.clone(),
            result_subscriber: result_subscriber.clone(), // Clone for shared use
            bitcoin,
            runtime: Runtime::new_read_only(&reader).await?,
        })
        .await?,
    );

    let mut ws_client = WebSocketClient::new(9333).await?;

    ws_client.ping().await?;

    let foo_id = OpResultId::builder().txid("foo".to_string()).build();
    let foo_subscription_id = ws_client.subscribe(&foo_id).await?;

    let bar_id = OpResultId::builder().txid("bar".to_string()).build();
    let bar_subscription_id = ws_client.subscribe(&bar_id).await?;

    let event1 = ResultEvent::Ok {
        metadata: ResultEventMetadata::builder()
            .op_result_id(foo_id.clone())
            .build(),
        value: "1".to_string(),
    };
    let event2 = ResultEvent::Err {
        metadata: ResultEventMetadata::builder()
            .op_result_id(bar_id.clone())
            .build(),
        message: "failure".to_string(),
    };

    event_tx.send(event1.clone()).await?;
    event_tx.send(event2.clone()).await?;

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
    for i in [0, 1] {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(i)
                .hash(new_mock_block_hash(i as u32))
                .build(),
        )
        .await?;
    }
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .tx_index(1)
            .txid("test".to_string())
            .build(),
    )
    .await?;
    let contract_id = insert_contract(
        &conn,
        ContractRow::builder()
            .bytes(vec![])
            .height(0)
            .tx_index(0)
            .name("".to_string())
            .build(),
    )
    .await?;
    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_id)
            .height(1)
            .tx_index(1)
            .gas(0)
            .build(),
    )
    .await?;

    let test_id = OpResultId::builder().txid("test".to_string()).build();
    let test_subscription_id = ws_client.subscribe(&test_id).await?;

    assert_eq!(
        ws_client.next().await?,
        Response::Result {
            id: test_subscription_id,
            result: ResultEvent::Err {
                metadata: ResultEventMetadata::builder().op_result_id(test_id).build(),
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
