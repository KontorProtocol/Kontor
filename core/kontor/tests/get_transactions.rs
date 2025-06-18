use anyhow::Result;
use base64::Engine;
use clap::Parser;
use kontor::{
    config::Config,
    database::{
        queries::{get_transactions_paginated, insert_block, insert_transaction},
        types::{BlockRow, TransactionCursor, TransactionRow},
    },
    utils::new_test_db,
};

async fn setup_test_data(conn: &libsql::Connection) -> Result<()> {
    // Insert blocks
    for height in [800000, 800001, 800002] {
        let hash = format!(
            "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba{:02}",
            height % 100
        )
        .parse()?;
        let block = BlockRow { height, hash };
        insert_block(conn, block).await?;
    }

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

    Ok(())
}

#[tokio::test]
async fn test_basic_pagination_no_filters() -> Result<()> {
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    let tx = reader.connection().await?.transaction().await?;

    // Test first page with limit 3
    let (transactions, meta) = get_transactions_paginated(
        &tx, None, // no height filter
        None, // no cursor
        None, // no offset
        3,    // limit
    )
    .await?;

    assert_eq!(transactions.len(), 3);
    assert!(meta.has_more);
    assert_eq!(meta.total_count, 10); // 5 + 3 + 2 = 10 total
    assert!(meta.next_offset.is_some());
    assert_eq!(meta.next_offset, Some(3));
    assert!(meta.next_cursor.is_some());
    let cursor = meta.next_cursor.clone().unwrap();
    let decoded_cursor = TransactionCursor::decode(&cursor)?;
    assert_eq!(decoded_cursor.height, 800001);
    assert_eq!(decoded_cursor.tx_index, 2);

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
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    let tx = reader.connection().await?.transaction().await?;

    // First page
    let (page1, meta1) = get_transactions_paginated(&tx, None, None, None, 3).await?;
    assert_eq!(page1.len(), 3);
    assert_eq!(meta1.next_offset, Some(3));
    assert!(meta1.has_more);
    assert!(meta1.next_cursor.is_some());

    // Second page using offset
    let (page2, meta2) = get_transactions_paginated(&tx, None, None, Some(3), 3).await?;
    assert_eq!(page2.len(), 3);
    assert_eq!(meta2.next_offset, Some(6));
    assert!(meta2.has_more);
    assert!(meta2.next_cursor.is_none()); // offset pagination

    // Third page
    let (page3, meta3) = get_transactions_paginated(&tx, None, None, Some(6), 3).await?;
    assert_eq!(page3.len(), 3);
    assert_eq!(meta3.next_offset, Some(9));
    assert!(meta3.has_more);

    // Fourth page (last page)
    let (page4, meta4) = get_transactions_paginated(&tx, None, None, Some(9), 3).await?;
    assert_eq!(page4.len(), 1); // Only 1 transaction left
    assert_eq!(meta4.next_offset, None); // No more pages
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
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // First page with cursor pagination
    let tx1 = reader.connection().await?.transaction().await?;
    let (page1, meta1) = get_transactions_paginated(&tx1, None, None, None, 3).await?;
    tx1.commit().await?; // Commit the transaction

    assert_eq!(page1.len(), 3);
    assert!(meta1.has_more);
    assert!(meta1.next_cursor.is_some());
    assert!(meta1.next_offset.is_some());

    let cursor = meta1.next_cursor.clone().unwrap();
    let decoded_cursor = TransactionCursor::decode(&cursor)?;
    assert_eq!(decoded_cursor.height, 800001);
    assert_eq!(decoded_cursor.tx_index, 2);

    // Create NEW connection for second transaction
    let tx2 = reader.connection().await?.transaction().await?;
    let (page2, meta2) = get_transactions_paginated(&tx2, None, meta1.next_cursor, None, 3).await?;
    tx2.commit().await?; // Commit the transaction

    assert_eq!(page2.len(), 3);
    assert!(meta2.has_more);
    assert!(meta2.next_cursor.is_some());
    assert!(meta2.next_offset.is_none());

    let cursor = meta2.next_cursor.clone().unwrap();
    let decoded_cursor = TransactionCursor::decode(&cursor)?;
    assert_eq!(decoded_cursor.height, 800000);
    assert_eq!(decoded_cursor.tx_index, 4);

    // Create NEW connection for third transaction
    let tx3 = reader.connection().await?.transaction().await?;
    let (page3, meta3) = get_transactions_paginated(&tx3, None, meta2.next_cursor, None, 3).await?;
    tx3.commit().await?; // Commit the transaction

    assert_eq!(page3.len(), 3);
    assert!(meta3.has_more);
    assert!(meta3.next_cursor.is_some());

    let cursor = meta3.next_cursor.clone().unwrap();
    let decoded_cursor = TransactionCursor::decode(&cursor)?;
    assert_eq!(decoded_cursor.height, 800000);
    assert_eq!(decoded_cursor.tx_index, 1);

    let tx4 = reader.connection().await?.transaction().await?;
    let (page4, meta4) = get_transactions_paginated(&tx4, None, meta3.next_cursor, None, 3).await?;
    tx4.commit().await?; // Commit the transaction

    assert_eq!(page4.len(), 1);
    assert!(!meta4.has_more);
    assert!(meta4.next_cursor.is_none());

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
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    let tx = reader.connection().await?.transaction().await?;
    // Filter by height 800001 (should have 3 transactions)
    let (transactions, meta) =
        get_transactions_paginated(&tx, Some(800001), None, None, 10).await?;

    assert_eq!(transactions.len(), 3);
    assert_eq!(meta.total_count, 3);
    assert!(!meta.has_more);
    assert!(meta.next_offset.is_none());

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
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    let tx = reader.connection().await?.transaction().await?;

    // Filter by height 800000 with limit 2 (should have 5 total, return 2)
    let (page1, meta1) = get_transactions_paginated(&tx, Some(800000), None, None, 2).await?;

    assert_eq!(page1.len(), 2);
    assert_eq!(meta1.total_count, 5);
    assert!(meta1.has_more);
    assert_eq!(meta1.next_offset, Some(2));

    // Get second page
    let (page2, meta2) = get_transactions_paginated(&tx, Some(800000), None, Some(2), 2).await?;

    assert_eq!(page2.len(), 2);
    assert!(meta2.has_more);
    assert_eq!(meta2.next_offset, Some(4));

    // Get final page
    let (page3, meta3) = get_transactions_paginated(&tx, Some(800000), None, Some(4), 2).await?;

    assert_eq!(page3.len(), 1); // Last transaction
    assert!(!meta3.has_more);
    assert!(meta3.next_offset.is_none());

    Ok(())
}

#[tokio::test]
async fn test_cursor_and_offset_conflict() -> Result<()> {
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    let tx = reader.connection().await?.transaction().await?;

    // This should be handled at the handler level, but let's test the query behavior
    let cursor = TransactionCursor {
        height: 800001,
        tx_index: 1,
    }
    .encode();

    // When both cursor and offset are provided, cursor takes precedence
    let (transactions, meta) =
        get_transactions_paginated(&tx, None, Some(cursor), Some(5), 3).await?;

    // Should use cursor pagination (ignore offset)
    assert!(meta.next_cursor.is_none());
    assert!(meta.next_offset.is_none());

    // Should return transactions with (height, tx_index) < (800001, 1)
    for tx in &transactions {
        assert!(tx.height < 800001 || (tx.height == 800001 && tx.tx_index < 1));
    }

    Ok(())
}

#[tokio::test]
async fn test_empty_result_set() -> Result<()> {
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    let tx = reader.connection().await?.transaction().await?;

    // Query for non-existent height
    let (transactions, meta) =
        get_transactions_paginated(&tx, Some(999999), None, None, 10).await?;

    assert_eq!(transactions.len(), 0);
    assert_eq!(meta.total_count, 0);
    assert!(!meta.has_more);
    assert!(meta.next_offset.is_none());
    assert!(meta.next_cursor.is_none());

    Ok(())
}

#[tokio::test]
async fn test_cursor_encoding_decoding() -> Result<()> {
    let original = TransactionCursor {
        height: 800001,
        tx_index: 42,
    };

    let encoded = original.encode();
    let decoded = TransactionCursor::decode(&encoded)?;

    assert_eq!(original.height, decoded.height);
    assert_eq!(original.tx_index, decoded.tx_index);

    Ok(())
}

#[tokio::test]
async fn test_invalid_cursor() -> Result<()> {
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Test with invalid base64
    let tx = reader.connection().await?.transaction().await?;
    let result =
        get_transactions_paginated(&tx, None, Some("invalid_cursor".to_string()), None, 3).await;
    assert!(result.is_err());
    tx.rollback().await?; // Rollback since we expect an error

    // Test with valid base64 but invalid format
    let invalid_cursor =
        base64::engine::general_purpose::STANDARD.encode("invalid:format:too:many:parts");
    let tx = reader.connection().await?.transaction().await?; // NEW connection
    let result = get_transactions_paginated(&tx, None, Some(invalid_cursor), None, 3).await;
    assert!(result.is_err());
    tx.rollback().await?; // Rollback since we expect an error

    Ok(())
}

#[tokio::test]
async fn test_large_limit() -> Result<()> {
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    let tx = reader.connection().await?.transaction().await?;

    // Request more than available
    let (transactions, meta) = get_transactions_paginated(&tx, None, None, None, 100).await?;

    assert_eq!(transactions.len(), 10); // All available transactions
    assert!(!meta.has_more);
    assert!(meta.next_offset.is_none());
    assert_eq!(meta.total_count, 10);

    Ok(())
}

#[tokio::test]
async fn test_zero_limit() -> Result<()> {
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    let tx = reader.connection().await?.transaction().await?;

    let (transactions, meta) = get_transactions_paginated(&tx, None, None, None, 0).await?;

    assert_eq!(transactions.len(), 0);
    assert!(meta.has_more); // There are transactions available
    assert_eq!(meta.next_offset, Some(0)); // Next offset should be 0
    assert_eq!(meta.total_count, 10);

    Ok(())
}

#[tokio::test]
async fn test_cursor_boundary_conditions() -> Result<()> {
    let config = Config::try_parse()?;
    let (reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Cursor pointing to the very first transaction
    let cursor = TransactionCursor {
        height: 800002,
        tx_index: 1,
    }
    .encode();

    let tx = reader.connection().await?.transaction().await?;
    let (transactions, meta) =
        get_transactions_paginated(&tx, None, Some(cursor), None, 10).await?;
    tx.commit().await?;

    assert_eq!(transactions.len(), 9);
    assert!(!meta.has_more);

    // Cursor pointing beyond all transactions
    let cursor = TransactionCursor {
        height: 900000,
        tx_index: 0,
    }
    .encode();

    let tx = reader.connection().await?.transaction().await?; // NEW connection
    let (transactions, meta) =
        get_transactions_paginated(&tx, None, Some(cursor), None, 10).await?;
    tx.commit().await?;

    assert_eq!(transactions.len(), 10);
    assert!(!meta.has_more);

    // Cursor pointing before all transactions
    let cursor = TransactionCursor {
        height: 700000,
        tx_index: 0,
    }
    .encode();

    let tx = reader.connection().await?.transaction().await?; // NEW connection
    let (transactions, meta) =
        get_transactions_paginated(&tx, None, Some(cursor), None, 10).await?;
    tx.commit().await?;

    assert_eq!(transactions.len(), 0);
    assert!(!meta.has_more);

    Ok(())
}
