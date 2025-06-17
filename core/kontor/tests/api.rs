use anyhow::Result;
use axum::{Router, http::StatusCode, routing::get};
use axum_test::{TestResponse, TestServer};
use clap::Parser;
use kontor::{
    api::{
        Env,
        handlers::{get_block, get_block_latest, get_transaction, get_transactions},
    },
    bitcoin_client::Client,
    config::Config,
    database::{
        queries::{insert_block, insert_transaction},
        types::{BlockRow, TransactionCursor, TransactionListResponse, TransactionRow},
    },
    reactor::events::EventSubscriber,
    utils::new_test_db,
};
use libsql::params;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Serialize, Deserialize)]
struct BlockResponse {
    result: BlockRow,
}

#[derive(Debug, Serialize, Deserialize)]
struct TransactionListResponseWrapper {
    result: TransactionListResponse,
}

#[derive(Debug, Serialize, Deserialize)]
struct TransactionResponse {
    result: TransactionRow,
}

async fn create_test_app() -> Result<Router> {
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let bitcoin_client = Client::new_from_config(&config)?;

    let conn = writer.connection();

    // Insert blocks
    let block1 = BlockRow {
        height: 800000,
        hash: "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?,
    };
    let block2 = BlockRow {
        height: 800001,
        hash: "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?,
    };
    let block3 = BlockRow {
        height: 800002,
        hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".parse()?,
    };

    insert_block(&conn, block1).await?;
    insert_block(&conn, block2).await?;
    insert_block(&conn, block3).await?;

    let reader_conn = reader.connection().await?;
    let mut reader_verify_rows = reader_conn
        .query("SELECT COUNT(*) FROM blocks", params![])
        .await?;
    if let Some(row) = reader_verify_rows.next().await? {
        let count: i64 = row.get(0)?;
        assert_eq!(count, 3);
    }

    // Insert transactions
    let tx1 = TransactionRow::builder()
        .height(800000)
        .txid(
            "tx1_800000_0_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
        )
        .tx_index(0)
        .build();
    let tx2 = TransactionRow::builder()
        .height(800000)
        .txid(
            "tx2_800000_1_123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
                .to_string(),
        )
        .tx_index(1)
        .build();
    let tx3 = TransactionRow::builder()
        .height(800001)
        .txid(
            "tx3_800001_0_fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
                .to_string(),
        )
        .tx_index(0)
        .build();

    insert_transaction(&conn, tx1).await?;
    insert_transaction(&conn, tx2).await?;
    insert_transaction(&conn, tx3).await?;

    let env = Env {
        bitcoin: bitcoin_client,
        reader,
        config,
        cancel_token: CancellationToken::new(),
        event_subscriber: EventSubscriber::new(),
    };

    Ok(Router::new()
        .route("/api/blocks/{identifier}", get(get_block))
        .route("/api/blocks/latest", get(get_block_latest))
        .route("/api/blocks/{height}/transactions", get(get_transactions))
        .route("/api/transactions", get(get_transactions))
        .route("/api/transactions/{txid}", get(get_transaction))
        .with_state(env))
}

// Block API Tests
#[tokio::test]
async fn test_get_block_by_height() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/blocks/800000").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: BlockResponse = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.height, 800000);
    assert_eq!(
        result.result.hash.to_string(),
        "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04"
    );

    Ok(())
}

#[tokio::test]
async fn test_get_block_by_hash() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get("/api/blocks/000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: BlockResponse = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.height, 800001);
    assert_eq!(
        result.result.hash.to_string(),
        "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05"
    );

    Ok(())
}

#[tokio::test]
async fn test_get_block_not_found() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/blocks/999999").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    let error_body = response.text();
    assert!(error_body.contains("block at height or hash: 999999"));

    Ok(())
}

#[tokio::test]
async fn test_get_block_invalid_hash() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/blocks/invalidhash123").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    Ok(())
}

#[tokio::test]
async fn test_get_block_latest() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/blocks/latest").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: BlockResponse = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.height, 800002); // Highest block
    assert_eq!(
        result.result.hash.to_string(),
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    );

    Ok(())
}

// Transaction API Tests
#[tokio::test]
async fn test_get_transactions_all() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/transactions").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // This is correct - deserialize to the wrapper type first
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;

    assert_eq!(result.result.transactions.len(), 3);
    assert_eq!(result.result.pagination.total_count, 3);
    assert!(!result.result.pagination.has_more);

    // Verify ordering (DESC by height, tx_index)
    assert_eq!(result.result.transactions[0].height, 800001);
    assert_eq!(result.result.transactions[1].height, 800000);
    assert_eq!(result.result.transactions[2].height, 800000);

    Ok(())
}

#[tokio::test]
async fn test_get_transactions_with_limit() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/transactions?limit=3").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.transactions.len(), 3);
    assert_eq!(result.result.pagination.total_count, 3);
    assert!(!result.result.pagination.has_more);
    assert!(result.result.pagination.next_offset.is_none());
    assert!(result.result.pagination.next_cursor.is_none());

    Ok(())
}

#[tokio::test]
async fn test_get_transactions_with_offset() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/transactions?limit=2&offset=1").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.transactions.len(), 2);
    assert_eq!(result.result.pagination.total_count, 3);
    assert!(!result.result.pagination.has_more);

    Ok(())
}

#[tokio::test]
async fn test_get_transactions_with_cursor() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    // First get transactions with limit to get cursor
    let response: TestResponse = server.get("/api/transactions?limit=1").await;
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(result.result.transactions[0].height, 800001);
    assert_eq!(result.result.transactions[0].tx_index, 0);
    assert_eq!(result.result.transactions.len(), 1);
    assert_eq!(result.result.pagination.total_count, 3);
    assert!(result.result.pagination.has_more);
    assert!(result.result.pagination.next_offset.is_some());
    assert!(result.result.pagination.next_cursor.is_some());

    let cursor = result.result.pagination.next_cursor.unwrap();

    let decoded_cursor = TransactionCursor::decode(&cursor)?;

    assert_eq!(decoded_cursor.height, 800000);
    assert_eq!(decoded_cursor.tx_index, 1);

    // Use cursor for next page
    let response: TestResponse = server
        .get(&format!("/api/transactions?cursor={}", cursor))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;

    assert_eq!(result.result.transactions.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_get_transactions_cursor_and_offset_error() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/transactions?cursor=test&offset=10").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    let error_body = response.text();
    assert!(error_body.contains("Cannot specify both cursor and offset parameters"));

    Ok(())
}

#[tokio::test]
async fn test_get_transactions_at_height() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/blocks/800000/transactions").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.transactions.len(), 2);
    assert_eq!(result.result.pagination.total_count, 2);

    // All transactions should be at height 800000
    for tx in &result.result.transactions {
        assert_eq!(tx.height, 800000);
    }

    Ok(())
}

#[tokio::test]
async fn test_get_transactions_at_height_empty() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/blocks/999999/transactions").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.transactions.len(), 0);
    assert_eq!(result.result.pagination.total_count, 0);

    Ok(())
}

#[tokio::test]
async fn test_get_transaction_by_txid() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get("/api/transactions/tx1_800000_0_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: TransactionResponse = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(
        result.result.txid,
        "tx1_800000_0_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    );
    assert_eq!(result.result.height, 800000);
    assert_eq!(result.result.tx_index, 0);

    Ok(())
}

#[tokio::test]
async fn test_get_transaction_not_found() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/transactions/nonexistent_txid").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    let error_body = response.text();
    assert!(error_body.contains("transaction: nonexistent_txid"));

    Ok(())
}

#[tokio::test]
async fn test_get_transactions_limit_bounds() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    // Test minimum limit
    let response: TestResponse = server.get("/api/transactions?limit=0").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.transactions.len(), 1); // Clamped to 1

    // Test maximum limit
    let response: TestResponse = server.get("/api/transactions?limit=2000").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.transactions.len(), 3); // All available transactions

    Ok(())
}

#[tokio::test]
async fn test_get_transactions_invalid_cursor() -> Result<()> {
    let app = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/transactions?cursor=invalid_cursor").await;
    assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    let error_body = response.text();
    assert!(error_body.contains("Invalid cursor format"));

    Ok(())
}
