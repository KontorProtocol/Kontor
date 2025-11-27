use std::sync::Arc;

use anyhow::Result;
use axum::{Router, routing::get};
use axum_test::{TestResponse, TestServer};
use indexer::{
    api::{
        Env,
        handlers::{get_block, get_block_latest, get_transaction, get_transactions},
    },
    bitcoin_client::Client,
    config::Config,
    database::{
        Reader, Writer,
        queries::{
            insert_contract, insert_contract_state, insert_processed_block, insert_transaction,
        },
        types::{BlockRow, ContractRow, ContractStateRow, PaginatedResponse, TransactionRow},
    },
    event::EventSubscriber,
    runtime::Runtime,
    test_utils::new_test_db,
};
use libsql::params;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Serialize, Deserialize)]
struct TransactionListResponseWrapper {
    result: PaginatedResponse<TransactionRow>,
}

async fn create_test_app(reader: Reader, writer: Writer) -> Result<Router> {
    let conn = writer.connection();
    // Insert blocks for heights 800000-800005
    for height in 800000..=800005 {
        let block = BlockRow::builder()
            .height(height)
            .hash(format!("{:064x}", height).parse()?)
            .build();
        insert_processed_block(&conn, block).await?;
    }

    insert_contract(
        &conn,
        ContractRow::builder()
            .name("token".to_string())
            .height(800000)
            .tx_index(1)
            .bytes(vec![])
            .build(),
    )
    .await?;

    let mut reader_verify_rows = conn.query("SELECT COUNT(*) FROM blocks", params![]).await?;
    if let Some(row) = reader_verify_rows.next().await? {
        let count: i64 = row.get(0)?;
        assert_eq!(count, 6);
    }

    // Height 800000: 5 transactions (indices 0-4)
    for tx_index in 0..5 {
        let tx = TransactionRow::builder()
            .height(800000)
            .txid(format!("tx_800000_{}_hash{:056x}", tx_index, tx_index))
            .tx_index(tx_index)
            .build();
        insert_transaction(&conn, tx).await?;
    }

    insert_contract_state(
        &conn,
        ContractStateRow::builder()
            .contract_id(1)
            .height(800000)
            .tx_index(1)
            .path("foo".to_string())
            .build(),
    )
    .await?;

    // Height 800001: 3 transactions (indices 0-2)
    for tx_index in 0..3 {
        let tx = TransactionRow::builder()
            .height(800001)
            .txid(format!("tx_800001_{}_hash{:056x}", tx_index, tx_index))
            .tx_index(tx_index)
            .build();
        insert_transaction(&conn, tx).await?;
    }

    insert_contract_state(
        &conn,
        ContractStateRow::builder()
            .contract_id(1)
            .height(800001)
            .tx_index(2)
            .path("bar".to_string())
            .build(),
    )
    .await?;

    // Height 800002: 7 transactions (indices 0-6)
    for tx_index in 0..7 {
        let tx = TransactionRow::builder()
            .height(800002)
            .txid(format!("tx_800002_{}_hash{:056x}", tx_index, tx_index))
            .tx_index(tx_index)
            .build();
        insert_transaction(&conn, tx).await?;
    }

    insert_contract_state(
        &conn,
        ContractStateRow::builder()
            .contract_id(1)
            .height(800002)
            .tx_index(3)
            .path("biz".to_string())
            .build(),
    )
    .await?;

    // Height 800003: 1 transaction (index 0)
    let tx = TransactionRow::builder()
        .height(800003)
        .txid("tx_800003_0_hash0000000000000000000000000000000000000000000000000000000".to_string())
        .tx_index(0)
        .build();
    insert_transaction(&conn, tx).await?;

    // Height 800004: 4 transactions (indices 0-3)
    for tx_index in 0..4 {
        let tx = TransactionRow::builder()
            .height(800004)
            .txid(format!("tx_800004_{}_hash{:056x}", tx_index, tx_index))
            .tx_index(tx_index)
            .build();
        insert_transaction(&conn, tx).await?;
    }

    // Height 800005: 2 transactions (indices 0-1)
    for tx_index in 0..2 {
        let tx = TransactionRow::builder()
            .height(800005)
            .txid(format!("tx_800005_{}_hash{:056x}", tx_index, tx_index))
            .tx_index(tx_index)
            .build();
        insert_transaction(&conn, tx).await?;
    }

    let env = Env {
        bitcoin: Client::new("".to_string(), "".to_string(), "".to_string())?,
        config: Config::new_na(),
        cancel_token: CancellationToken::new(),
        available: Arc::new(RwLock::new(true)),
        event_subscriber: EventSubscriber::new(),
        runtime: Arc::new(Mutex::new(Runtime::new_read_only(&reader).await?)),
        reader,
    };

    Ok(Router::new()
        .route("/api/blocks/{identifier}", get(get_block))
        .route("/api/blocks/latest", get(get_block_latest))
        .route("/api/transactions", get(get_transactions))
        .route("/api/transactions/{txid}", get(get_transaction))
        .with_state(env))
}

async fn collect_all_transactions_with_cursor(
    server: &TestServer,
    endpoint: &str,
    limit: u32,
    height: Option<u32>,
) -> Result<Vec<TransactionRow>> {
    let mut all_transactions = Vec::new();
    let mut cursor: Option<i64> = None;
    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 50; // Safety limit

    loop {
        iterations += 1;
        if iterations > MAX_ITERATIONS {
            panic!("Too many iterations, possible infinite loop");
        }

        let mut url = format!("{}?limit={}", endpoint, limit);
        if let Some(c) = cursor.as_ref() {
            url += &format!("&cursor={}", c);
        }
        if let Some(h) = height {
            url += &format!("&height={}", h);
        }

        let response: TestResponse = server.get(&url).await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;

        all_transactions.extend(result.result.results);

        if !result.result.pagination.has_more {
            break;
        }

        cursor = result.result.pagination.next_cursor;
        assert!(
            cursor.is_some(),
            "has_more=true but no next_cursor provided"
        );
    }

    Ok(all_transactions)
}

async fn collect_all_transactions_with_offset(
    server: &TestServer,
    endpoint: &str,
    limit: u32,
    height: Option<u32>,
) -> Result<Vec<TransactionRow>> {
    let mut all_transactions = Vec::new();
    let mut offset = 0;
    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 50;

    loop {
        iterations += 1;
        if iterations > MAX_ITERATIONS {
            panic!("Too many iterations, possible infinite loop");
        }

        let mut url = format!("{}?limit={}&offset={}", endpoint, limit, offset);
        if let Some(h) = height {
            url += &format!("&height={}", h);
        }
        let response: TestResponse = server.get(&url).await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;

        all_transactions.extend(result.result.results);

        if !result.result.pagination.has_more {
            break;
        }

        offset = result.result.pagination.next_offset.unwrap_or(0);
    }

    Ok(all_transactions)
}

#[tokio::test]
async fn test_cursor_pagination_no_gaps_all_transactions() -> Result<()> {
    let (reader, writer, _temp_dir) = new_test_db().await?;
    let app = create_test_app(reader, writer).await?;
    let server = TestServer::new(app)?;

    // Test with different page sizes
    for limit in [1, 2, 3, 5, 7, 10] {
        let cursor_transactions =
            collect_all_transactions_with_cursor(&server, "/api/transactions", limit, None).await?;
        let offset_transactions =
            collect_all_transactions_with_offset(&server, "/api/transactions", limit, None).await?;

        // Both methods should return the same transactions in the same order
        assert_eq!(
            cursor_transactions.len(),
            offset_transactions.len(),
            "Cursor and offset pagination returned different counts for limit={}",
            limit
        );

        for (i, (cursor_tx, offset_tx)) in cursor_transactions
            .iter()
            .zip(offset_transactions.iter())
            .enumerate()
        {
            assert_eq!(
                cursor_tx.txid, offset_tx.txid,
                "Transaction mismatch at index {} for limit={}",
                i, limit
            );
            assert_eq!(
                cursor_tx.height, offset_tx.height,
                "Height mismatch at index {} for limit={}",
                i, limit
            );
            assert_eq!(
                cursor_tx.tx_index, offset_tx.tx_index,
                "tx_index mismatch at index {} for limit={}",
                i, limit
            );
        }

        // Verify total count (5+3+7+1+4+2 = 22 transactions)
        assert_eq!(
            cursor_transactions.len(),
            22,
            "Expected 22 total transactions for limit={}",
            limit
        );

        // Verify ordering (DESC by height, tx_index)
        for i in 1..cursor_transactions.len() {
            let prev = &cursor_transactions[i - 1];
            let curr = &cursor_transactions[i];

            assert!(
                prev.height > curr.height
                    || (prev.height == curr.height && prev.tx_index > curr.tx_index),
                "Incorrect ordering at index {} for limit={}: ({}, {}) should come before ({}, {})",
                i,
                limit,
                prev.height,
                prev.tx_index,
                curr.height,
                curr.tx_index
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_cursor_pagination_no_gaps_single_height() -> Result<()> {
    let (reader, writer, _temp_dir) = new_test_db().await?;
    let app = create_test_app(reader, writer).await?;
    let server = TestServer::new(app)?;

    // Test pagination for height 800000 (5 transactions)
    for limit in [1, 2, 3, 4, 5, 6] {
        let cursor_transactions =
            collect_all_transactions_with_cursor(&server, "/api/transactions", limit, Some(800000))
                .await?;
        let offset_transactions =
            collect_all_transactions_with_offset(&server, "/api/transactions", limit, Some(800000))
                .await?;

        // Both methods should return the same transactions
        assert_eq!(
            cursor_transactions.len(),
            offset_transactions.len(),
            "Cursor and offset pagination returned different counts for height 800000, limit={}",
            limit
        );

        for (i, (cursor_tx, offset_tx)) in cursor_transactions
            .iter()
            .zip(offset_transactions.iter())
            .enumerate()
        {
            assert_eq!(
                cursor_tx.txid, offset_tx.txid,
                "Transaction mismatch at index {} for height 800000, limit={}",
                i, limit
            );
        }

        // Verify all transactions are at height 800000
        for tx in &cursor_transactions {
            assert_eq!(
                tx.height, 800000,
                "Transaction not at expected height 800000"
            );
        }

        // Verify count (5 transactions at height 800000)
        assert_eq!(
            cursor_transactions.len(),
            5,
            "Expected 5 transactions at height 800000 for limit={}",
            limit
        );

        // Verify ordering (DESC by tx_index: 4, 3, 2, 1, 0)
        let expected_indices = [4, 3, 2, 1, 0];
        for (i, tx) in cursor_transactions.iter().enumerate() {
            assert_eq!(
                tx.tx_index, expected_indices[i],
                "Incorrect tx_index at position {} for limit={}: expected {}, got {}",
                i, limit, expected_indices[i], tx.tx_index
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_cursor_pagination_no_gaps_height_with_many_transactions() -> Result<()> {
    let (reader, writer, _temp_dir) = new_test_db().await?;
    let app = create_test_app(reader, writer).await?;
    let server = TestServer::new(app)?;

    // Test pagination for height 800002 (7 transactions)
    for limit in [1, 2, 3, 4, 5, 6, 7, 8] {
        let cursor_transactions =
            collect_all_transactions_with_cursor(&server, "/api/transactions", limit, Some(800002))
                .await?;
        let offset_transactions =
            collect_all_transactions_with_offset(&server, "/api/transactions", limit, Some(800002))
                .await?;

        // Both methods should return the same transactions
        assert_eq!(
            cursor_transactions.len(),
            offset_transactions.len(),
            "Cursor and offset pagination returned different counts for height 800002, limit={}",
            limit
        );

        // Verify count (7 transactions at height 800002)
        assert_eq!(
            cursor_transactions.len(),
            7,
            "Expected 7 transactions at height 800002 for limit={}",
            limit
        );

        // Verify ordering (DESC by tx_index: 6, 5, 4, 3, 2, 1, 0)
        let expected_indices = [6, 5, 4, 3, 2, 1, 0];
        for (i, tx) in cursor_transactions.iter().enumerate() {
            assert_eq!(
                tx.tx_index, expected_indices[i],
                "Incorrect tx_index at position {} for limit={}: expected {}, got {}",
                i, limit, expected_indices[i], tx.tx_index
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_cursor_pagination_edge_cases() -> Result<()> {
    let (reader, writer, _temp_dir) = new_test_db().await?;
    let app = create_test_app(reader, writer).await?;
    let server = TestServer::new(app)?;

    // Test with limit=1 to ensure every transaction is returned exactly once
    let transactions =
        collect_all_transactions_with_cursor(&server, "/api/transactions", 1, None).await?;

    // Create a set of unique transaction IDs to check for duplicates
    let mut seen_txids = std::collections::HashSet::new();
    for tx in &transactions {
        assert!(
            seen_txids.insert(&tx.txid),
            "Duplicate transaction found: {}",
            tx.txid
        );
    }

    // Test height with single transaction (800003)
    let single_tx =
        collect_all_transactions_with_cursor(&server, "/api/transactions", 1, Some(800003)).await?;
    assert_eq!(
        single_tx.len(),
        1,
        "Expected exactly 1 transaction at height 800003"
    );
    assert_eq!(single_tx[0].height, 800003);
    assert_eq!(single_tx[0].tx_index, 0);

    // Test empty height (800006 - no transactions)
    let empty_result =
        collect_all_transactions_with_cursor(&server, "/api/transactions", 10, Some(800006))
            .await?;
    assert_eq!(
        empty_result.len(),
        0,
        "Expected no transactions at height 800006"
    );

    Ok(())
}

#[tokio::test]
async fn test_cursor_pagination_boundary_conditions() -> Result<()> {
    let (reader, writer, _temp_dir) = new_test_db().await?;
    let app = create_test_app(reader, writer).await?;
    let server = TestServer::new(app)?;

    // Test that cursor pagination works correctly when page size equals total count
    let height_800001_all =
        collect_all_transactions_with_cursor(&server, "/api/transactions", 3, Some(800001)).await?;
    assert_eq!(
        height_800001_all.len(),
        3,
        "Expected 3 transactions at height 800001"
    );

    // Test that cursor pagination works correctly when page size exceeds total count
    let height_800001_large =
        collect_all_transactions_with_cursor(&server, "/api/transactions", 10, Some(800001))
            .await?;
    assert_eq!(
        height_800001_large.len(),
        3,
        "Expected 3 transactions at height 800001 with large limit"
    );

    // Verify both results are identical
    for (i, (tx1, tx2)) in height_800001_all
        .iter()
        .zip(height_800001_large.iter())
        .enumerate()
    {
        assert_eq!(tx1.txid, tx2.txid, "Transaction mismatch at index {}", i);
    }

    Ok(())
}

#[tokio::test]
async fn test_cursor_consistency_across_different_limits() -> Result<()> {
    let (reader, writer, _temp_dir) = new_test_db().await?;
    let app = create_test_app(reader, writer).await?;
    let server = TestServer::new(app)?;

    // Collect all transactions with different page sizes
    let results_limit_1 =
        collect_all_transactions_with_cursor(&server, "/api/transactions", 1, None).await?;
    let results_limit_3 =
        collect_all_transactions_with_cursor(&server, "/api/transactions", 3, None).await?;
    let results_limit_7 =
        collect_all_transactions_with_cursor(&server, "/api/transactions", 7, None).await?;
    let results_limit_22 =
        collect_all_transactions_with_cursor(&server, "/api/transactions", 22, None).await?;

    // All should return the same transactions in the same order
    let all_results = [
        &results_limit_1,
        &results_limit_3,
        &results_limit_7,
        &results_limit_22,
    ];

    for (i, results) in all_results.iter().enumerate() {
        assert_eq!(results.len(), 22, "Result set {} has wrong length", i);

        for (j, (tx1, tx2)) in results_limit_1.iter().zip(results.iter()).enumerate() {
            assert_eq!(
                tx1.txid, tx2.txid,
                "Transaction mismatch at index {} in result set {}",
                j, i
            );
            assert_eq!(
                tx1.height, tx2.height,
                "Height mismatch at index {} in result set {}",
                j, i
            );
            assert_eq!(
                tx1.tx_index, tx2.tx_index,
                "tx_index mismatch at index {} in result set {}",
                j, i
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_cursor_pagination_maintains_total_count() -> Result<()> {
    let (reader, writer, _temp_dir) = new_test_db().await?;
    let app = create_test_app(reader, writer).await?;
    let server = TestServer::new(app)?;

    // Test that total_count decreases as we paginate (showing remaining items)
    let mut cursor: Option<i64> = None;
    let mut page_count = 0;
    let limit = 3;
    let mut previous_total_count = None;

    loop {
        page_count += 1;
        let url = if let Some(ref c) = cursor {
            format!("/api/transactions?limit={}&cursor={}", limit, c)
        } else {
            format!("/api/transactions?limit={}", limit)
        };

        let response: TestResponse = server.get(&url).await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;

        let current_total_count = result.result.pagination.total_count;

        // First page should have the full count
        if page_count == 1 {
            assert_eq!(
                current_total_count, 22,
                "First page should show total count of 22"
            );
        } else {
            // Subsequent pages should have decreasing total_count (showing remaining items)
            if let Some(prev_count) = previous_total_count {
                assert!(
                    current_total_count < prev_count,
                    "total_count should decrease as we paginate: {} -> {}",
                    prev_count,
                    current_total_count
                );
            }
        }

        previous_total_count = Some(current_total_count);

        if !result.result.pagination.has_more {
            break;
        }

        cursor = result.result.pagination.next_cursor;
    }

    assert!(page_count > 1, "Should have required multiple pages");

    Ok(())
}

#[tokio::test]
async fn test_cursor_pagination_contract_address() -> Result<()> {
    let (reader, writer, _temp_dir) = new_test_db().await?;
    let app = create_test_app(reader, writer).await?;
    let server = TestServer::new(app)?;

    let url = "/api/transactions?limit=1&contract=token_800000_1";
    let response: TestResponse = server.get(url).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    let transactions = result.result.results;
    let meta = result.result.pagination;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800002);
    assert_eq!(transactions[0].tx_index, 3);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));
    assert_eq!(meta.total_count, 3);

    let url = format!(
        "/api/transactions?limit=1&contract=token_800000_1&cursor={}",
        meta.next_cursor.unwrap()
    );
    let response: TestResponse = server.get(&url).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    let transactions = result.result.results;
    let meta = result.result.pagination;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800001);
    assert_eq!(transactions[0].tx_index, 2);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));

    let url = format!(
        "/api/transactions?limit=1&contract=token_800000_1&cursor={}",
        meta.next_cursor.unwrap()
    );
    let response: TestResponse = server.get(&url).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    let transactions = result.result.results;
    let meta = result.result.pagination;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800000);
    assert_eq!(transactions[0].tx_index, 1);
    assert!(!meta.has_more);
    assert!(meta.next_cursor.is_none());

    Ok(())
}

#[tokio::test]
async fn test_cursor_pagination_contract_address_asc() -> Result<()> {
    let (reader, writer, _temp_dir) = new_test_db().await?;
    let app = create_test_app(reader, writer).await?;
    let server = TestServer::new(app)?;

    let url = "/api/transactions?limit=1&contract=token_800000_1&order=asc";
    let response: TestResponse = server.get(url).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    let transactions = result.result.results;
    let meta = result.result.pagination;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800000);
    assert_eq!(transactions[0].tx_index, 1);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));
    assert_eq!(meta.total_count, 3);

    let url = format!(
        "/api/transactions?limit=1&contract=token_800000_1&cursor={}&order=asc",
        meta.next_cursor.unwrap()
    );
    let response: TestResponse = server.get(&url).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    let transactions = result.result.results;
    let meta = result.result.pagination;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800001);
    assert_eq!(transactions[0].tx_index, 2);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));

    let url = format!(
        "/api/transactions?limit=1&contract=token_800000_1&cursor={}&order=asc",
        meta.next_cursor.unwrap()
    );
    let response: TestResponse = server.get(&url).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let result: TransactionListResponseWrapper = serde_json::from_slice(response.as_bytes())?;
    let transactions = result.result.results;
    let meta = result.result.pagination;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800002);
    assert_eq!(transactions[0].tx_index, 3);
    assert!(!meta.has_more);
    assert!(meta.next_cursor.is_none());

    Ok(())
}
