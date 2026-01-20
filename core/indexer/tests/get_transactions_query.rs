use anyhow::Result;
use indexer::{
    database::{
        queries::{
            get_transactions_paginated, insert_contract, insert_contract_state,
            insert_processed_block, insert_transaction,
        },
        types::{ContractRow, ContractStateRow, OrderDirection, TransactionQuery},
    },
    test_utils::new_test_db,
};
use indexer_types::{BlockRow, TransactionRow};
use testlib::ContractAddress;

async fn setup_test_data(conn: &libsql::Connection) -> Result<()> {
    // Insert blocks
    for height in [800000, 800001, 800002] {
        let hash = format!(
            "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba{:02}",
            height % 100
        )
        .parse()?;
        let block = BlockRow::builder().height(height).hash(hash).build();
        insert_processed_block(conn, block).await?;
    }

    insert_contract(
        conn,
        ContractRow::builder()
            .name("token".to_string())
            .height(800000)
            .tx_index(1)
            .bytes(vec![])
            .build(),
    )
    .await?;

    // Insert transactions across multiple heights
    // Height 800000: 5 transactions (tx_index 0-4)
    for i in 0..5 {
        let tx = TransactionRow::builder()
            .height(800000)
            .txid(format!(
                "tx800000_{:02}_abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
                i
            ))
            .tx_index(i)
            .build();
        insert_transaction(conn, tx).await?;
    }

    insert_contract_state(
        conn,
        ContractStateRow::builder()
            .contract_id(1)
            .height(800000)
            .tx_index(0)
            .path("foo".to_string())
            .build(),
    )
    .await?;

    // Height 800001: 3 transactions (tx_index 0-2)
    for i in 0..3 {
        let tx = TransactionRow::builder()
            .height(800001)
            .txid(format!(
                "tx800001_{:02}_fedcba0987654321fedcba0987654321fedcba0987654321fedcba098765",
                i
            ))
            .tx_index(i)
            .build();
        insert_transaction(conn, tx).await?;
    }

    // tests DISTINCT functionality
    insert_contract_state(
        conn,
        ContractStateRow::builder()
            .contract_id(1)
            .height(800001)
            .tx_index(1)
            .path("bar".to_string())
            .build(),
    )
    .await?;
    insert_contract_state(
        conn,
        ContractStateRow::builder()
            .contract_id(1)
            .height(800001)
            .tx_index(1)
            .path("biz".to_string())
            .build(),
    )
    .await?;

    // Height 800002: 2 transactions (tx_index 0-1)
    for i in 0..2 {
        let tx = TransactionRow::builder()
            .height(800002)
            .txid(format!(
                "tx800002_{:02}_123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
                i
            ))
            .tx_index(i)
            .build();
        insert_transaction(conn, tx).await?;
    }

    insert_contract_state(
        conn,
        ContractStateRow::builder()
            .contract_id(1)
            .height(800002)
            .tx_index(0)
            .path("baz".to_string())
            .build(),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_transaction_query_contract_address() -> Result<()> {
    let x = serde_json::from_str::<TransactionQuery>(r#"{"contract": "token_1_0"}"#).unwrap();
    assert_eq!(
        x,
        TransactionQuery::builder()
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 1,
                tx_index: 0
            })
            .build()
    );
    Ok(())
}

#[tokio::test]
async fn test_basic_pagination_no_filters() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Test first page with limit 3
    let (transactions, meta) =
        get_transactions_paginated(&conn, TransactionQuery::builder().limit(3).build()).await?;

    assert_eq!(transactions.len(), 3);
    assert!(meta.has_more);
    assert_eq!(meta.total_count, 10); // 5 + 3 + 2 = 10 total
    assert!(meta.next_offset.is_some());
    assert_eq!(meta.next_offset, Some(3));
    assert!(meta.next_cursor.is_some());
    let cursor = meta.next_cursor.unwrap();
    assert_eq!(cursor, 8);

    // Verify ordering (DESC by height, then DESC by tx_index)
    assert_eq!(transactions[0].height, 800002);
    assert_eq!(transactions[0].tx_index, 1);
    assert_eq!(transactions[1].height, 800002);
    assert_eq!(transactions[1].tx_index, 0);
    assert_eq!(transactions[2].height, 800001);
    assert_eq!(transactions[2].tx_index, 2);

    Ok(())
}

#[tokio::test]
async fn test_offset_pagination() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    // First page
    let (page1, meta1) =
        get_transactions_paginated(&conn, TransactionQuery::builder().limit(3).build()).await?;
    assert_eq!(page1.len(), 3);
    assert_eq!(meta1.next_offset, Some(3));
    assert!(meta1.has_more);
    assert!(meta1.next_cursor.is_some());

    // Second page using offset
    let (page2, meta2) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().offset(3).limit(3).build(),
    )
    .await?;
    assert_eq!(page2.len(), 3);
    assert_eq!(meta2.next_offset, Some(6));
    assert!(meta2.has_more);
    assert!(meta2.next_cursor.is_none()); // offset pagination

    // Third page
    let (page3, meta3) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().offset(6).limit(3).build(),
    )
    .await?;
    assert_eq!(page3.len(), 3);
    assert_eq!(meta3.next_offset, Some(9));
    assert!(meta3.has_more);

    // Fourth page (last page)
    let (page4, meta4) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().offset(9).limit(3).build(),
    )
    .await?;
    assert_eq!(page4.len(), 1); // Only 1 transaction left
    assert_eq!(meta4.next_offset, Some(10)); // For polling - points past last item
    assert!(!meta4.has_more);

    // Verify no overlap between pages
    let all_txids: Vec<String> = [&page1, &page2, &page3, &page4]
        .iter()
        .flat_map(|page| page.iter().map(|tx| tx.txid.clone()))
        .collect();
    let unique_txids: std::collections::HashSet<String> = all_txids.iter().cloned().collect();
    assert_eq!(all_txids.len(), unique_txids.len()); // No duplicates

    Ok(())
}

#[tokio::test]
async fn test_cursor_pagination() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // First page with cursor pagination
    let (page1, meta1) =
        get_transactions_paginated(&conn, TransactionQuery::builder().limit(3).build()).await?;

    assert_eq!(page1.len(), 3);
    assert!(meta1.has_more);
    assert!(meta1.next_cursor.is_some());
    assert!(meta1.next_offset.is_some());

    let cursor = meta1.next_cursor.unwrap();
    assert_eq!(cursor, 8);

    let (page2, meta2) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta1.next_cursor)
            .limit(3)
            .build(),
    )
    .await?;

    assert_eq!(page2.len(), 3);
    assert!(meta2.has_more);
    assert!(meta2.next_cursor.is_some());
    assert!(meta2.next_offset.is_none());

    let cursor = meta2.next_cursor.unwrap();
    assert_eq!(cursor, 5);

    let (page3, meta3) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta2.next_cursor)
            .limit(3)
            .build(),
    )
    .await?;

    assert_eq!(page3.len(), 3);
    assert!(meta3.has_more);
    assert!(meta3.next_cursor.is_some());

    let cursor = meta3.next_cursor.unwrap();
    assert_eq!(cursor, 2);

    let (page4, meta4) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta3.next_cursor)
            .limit(3)
            .build(),
    )
    .await?;

    assert_eq!(page4.len(), 1);
    assert!(!meta4.has_more);
    assert_eq!(meta4.next_cursor, Some(page4[0].id));

    // Verify no overlap
    let all_txids: Vec<String> = [&page1, &page2, &page3]
        .iter()
        .flat_map(|page| page.iter().map(|tx| tx.txid.clone()))
        .collect();
    let unique_txids: std::collections::HashSet<String> = all_txids.iter().cloned().collect();
    assert_eq!(all_txids.len(), unique_txids.len());

    Ok(())
}

#[tokio::test]
async fn test_height_filter() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    // Filter by height 800001 (should have 3 transactions)
    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().height(800001).limit(10).build(),
    )
    .await?;

    assert_eq!(transactions.len(), 3);
    assert_eq!(meta.total_count, 3);
    assert!(!meta.has_more);
    assert_eq!(meta.next_offset, Some(3));

    // Verify all transactions are from height 800001
    for tx in &transactions {
        assert_eq!(tx.height, 800001);
    }

    // Verify ordering within height (DESC by tx_index)
    assert_eq!(transactions[0].tx_index, 2);
    assert_eq!(transactions[1].tx_index, 1);
    assert_eq!(transactions[2].tx_index, 0);

    Ok(())
}

#[tokio::test]
async fn test_height_filter_with_pagination() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Filter by height 800000 with limit 2 (should have 5 total, return 2)
    let (page1, meta1) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().height(800000).limit(2).build(),
    )
    .await?;

    assert_eq!(page1.len(), 2);
    assert_eq!(meta1.total_count, 5);
    assert!(meta1.has_more);
    assert_eq!(meta1.next_offset, Some(2));

    // Get second page
    let (page2, meta2) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .height(800000)
            .offset(2)
            .limit(2)
            .build(),
    )
    .await?;

    assert_eq!(page2.len(), 2);
    assert!(meta2.has_more);
    assert_eq!(meta2.next_offset, Some(4));

    // Get final page
    let (page3, meta3) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .height(800000)
            .offset(4)
            .limit(2)
            .build(),
    )
    .await?;

    assert_eq!(page3.len(), 1); // Last transaction
    assert!(!meta3.has_more);
    assert_eq!(meta3.next_offset, Some(5));

    Ok(())
}

#[tokio::test]
async fn test_cursor_and_offset_conflict() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // When both cursor and offset are provided, cursor takes precedence
    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .cursor(9)
            .offset(5)
            .limit(3)
            .build(),
    )
    .await?;

    // Should use cursor pagination (ignore offset)
    assert!(meta.next_cursor.is_none());
    assert!(meta.next_offset.is_none());

    // Should return transactions with (height, tx_index) < (800001, 1)
    for tx in &transactions {
        assert!(tx.height == 800001);
    }

    Ok(())
}

#[tokio::test]
async fn test_empty_result_set() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Query for non-existent height
    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().height(999999).limit(10).build(),
    )
    .await?;

    assert_eq!(transactions.len(), 0);
    assert_eq!(meta.total_count, 0);
    assert!(!meta.has_more);
    assert_eq!(meta.next_offset, Some(0));
    assert!(meta.next_cursor.is_none());

    Ok(())
}

#[tokio::test]
async fn test_large_limit() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Request more than available
    let (transactions, meta) =
        get_transactions_paginated(&conn, TransactionQuery::builder().limit(100).build()).await?;

    assert_eq!(transactions.len(), 10); // All available transactions
    assert!(!meta.has_more);
    assert_eq!(meta.next_offset, Some(10));
    assert_eq!(meta.total_count, 10);

    Ok(())
}

#[tokio::test]
async fn test_zero_limit() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    let (transactions, meta) =
        get_transactions_paginated(&conn, TransactionQuery::builder().limit(0).build()).await?;

    assert_eq!(transactions.len(), 0);
    assert!(meta.has_more); // There are transactions available
    assert_eq!(meta.next_offset, Some(0)); // Next offset should be 0
    assert_eq!(meta.total_count, 10);

    Ok(())
}

#[tokio::test]
async fn test_cursor_boundary_conditions() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Cursor pointing to the very first transaction
    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().cursor(10).limit(10).build(),
    )
    .await?;

    assert_eq!(transactions.len(), 9);
    assert!(!meta.has_more);

    // Cursor pointing beyond all transactions
    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().cursor(11).limit(10).build(),
    )
    .await?;

    assert_eq!(transactions.len(), 10);
    assert!(!meta.has_more);

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().cursor(0).limit(10).build(),
    )
    .await?;

    assert_eq!(transactions.len(), 0);
    assert!(!meta.has_more);

    Ok(())
}

#[tokio::test]
async fn test_cursor_contract_address_querying() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800002);
    assert_eq!(transactions[0].tx_index, 0);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));
    assert_eq!(meta.total_count, 3);

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800001);
    assert_eq!(transactions[0].tx_index, 1);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800000);
    assert_eq!(transactions[0].tx_index, 0);
    assert!(!meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));

    Ok(())
}

#[tokio::test]
async fn test_cursor_contract_address_querying_asc() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .order(OrderDirection::Asc)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800000);
    assert_eq!(transactions[0].tx_index, 0);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));
    assert_eq!(meta.total_count, 3);

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .order(OrderDirection::Asc)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800001);
    assert_eq!(transactions[0].tx_index, 1);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .order(OrderDirection::Asc)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800002);
    assert_eq!(transactions[0].tx_index, 0);
    assert!(!meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));

    Ok(())
}
