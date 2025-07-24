use anyhow::Result;
use clap::Parser;
use indexer::{
    bitcoin_client::Client,
    config::Config,
    database::{
        queries::{
            delete_contract_state, exists_contract_state, get_contract_bytes,
            get_latest_contract_state, get_latest_contract_state_value, get_transaction_by_id,
            get_transaction_by_txid, get_transactions_at_height, insert_block, insert_contract,
            insert_contract_state, insert_transaction, select_block_at_height,
            select_block_by_height_or_hash, select_block_latest,
        },
        types::{BlockRow, ContractId, ContractRow, ContractStateRow, TransactionRow},
    },
    logging,
    test_utils::{new_mock_block_hash, new_test_db},
};
use libsql::params;

#[tokio::test]
async fn test_database() -> Result<()> {
    let config = Config::try_parse()?;
    let client = Client::new_from_config(&config)?;
    let height = 800000;
    let hash = client.get_block_hash(height).await?;
    let block = BlockRow { height, hash };

    let (reader, writer, _temp_dir) = new_test_db(&config).await?;

    insert_block(&writer.connection(), block).await?;
    let block_at_height = select_block_at_height(&*reader.connection().await?, height)
        .await?
        .unwrap();
    assert_eq!(block_at_height.height, height);
    assert_eq!(block_at_height.hash, hash);
    let last_block = select_block_latest(&*reader.connection().await?)
        .await?
        .unwrap();
    assert_eq!(last_block.height, height);
    assert_eq!(last_block.hash, hash);

    Ok(())
}

#[tokio::test]
async fn test_transaction() -> Result<()> {
    let config = Config::try_parse()?;
    let (_reader, writer, _temp_dir) = new_test_db(&config).await?;
    let tx = writer.connection().transaction().await?;
    let height = 800000;
    let client = Client::new_from_config(&config)?;
    let hash = client.get_block_hash(height).await?;
    let block = BlockRow { height, hash };
    insert_block(&tx, block).await?;
    assert!(select_block_latest(&tx).await?.is_some());
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
async fn test_crypto_extension() -> Result<()> {
    logging::setup();
    let config = Config::try_parse()?;
    let (_reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    let mut rows = conn
        .query("SELECT hex(crypto_sha256('abc'))", params![])
        .await?;
    let row = rows.next().await?.unwrap();
    let hash = row.get_str(0)?;
    assert_eq!(
        hash,
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    );
    Ok(())
}

#[tokio::test]
async fn test_contract_state_operations() -> Result<()> {
    let config = Config::try_parse()?;
    let (_reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();

    // First insert a block to satisfy foreign key constraints
    let height = 800000;
    let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
    let block = BlockRow { height, hash };
    insert_block(&conn, block).await?;

    // Insert a transaction for the contract state
    let tx = TransactionRow::builder()
        .height(height as i64)
        .txid("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string())
        .tx_index(0)
        .build();
    let tx_id = insert_transaction(&conn, tx).await?;

    // Test contract state insertion and retrieval
    let contract_id = "test_contract_123";
    let path = "test/path";
    let value = vec![1, 2, 3, 4];

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id.to_string())
        .tx_id(tx_id)
        .height(height as i64)
        .path(path.to_string())
        .value(value.clone())
        .build();

    // Insert contract state
    let id = insert_contract_state(&conn, contract_state).await?;
    assert!(id > 0, "Contract state insertion should return a valid ID");

    // check existence
    assert!(exists_contract_state(&conn, contract_id, "test/").await?);

    // Get latest contract state
    let retrieved_state = get_latest_contract_state(&conn, contract_id, path).await?;
    assert!(
        retrieved_state.is_some(),
        "Contract state should be retrieved"
    );

    // Get latest contract state value
    let retrieved_value = get_latest_contract_state_value(&conn, contract_id, path).await?;
    assert!(
        retrieved_value.is_some(),
        "Contract state value should be retrieved"
    );

    let retrieved_state = retrieved_state.unwrap();
    assert_eq!(retrieved_state.contract_id, contract_id);
    assert_eq!(retrieved_state.path, path);
    assert_eq!(retrieved_state.value, value);
    assert_eq!(retrieved_value.unwrap(), value);
    assert!(!retrieved_state.deleted);
    assert_eq!(retrieved_state.height, height as i64);
    assert_eq!(retrieved_state.tx_id, tx_id);

    // Test with a newer version of the same contract state
    let height2 = 800001;
    let hash2 = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?;
    let block2 = BlockRow {
        height: height2,
        hash: hash2,
    };
    insert_block(&conn, block2).await?;

    let txid2 = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    let tx2 = TransactionRow::builder()
        .height(height2 as i64)
        .txid(txid2.to_string())
        .tx_index(2)
        .build();
    let tx_id2 = insert_transaction(&conn, tx2).await?;

    let updated_value = vec![5, 6, 7, 8];
    let updated_contract_state = ContractStateRow::builder()
        .contract_id(contract_id.to_string())
        .tx_id(tx_id2)
        .height(height2 as i64)
        .path(path.to_string())
        .value(updated_value.clone())
        .build();
    insert_contract_state(&conn, updated_contract_state).await?;

    // Verify we get the latest version
    let latest_state = get_latest_contract_state(&conn, contract_id, path)
        .await?
        .unwrap();
    let latest_value = get_latest_contract_state_value(&conn, contract_id, path)
        .await?
        .unwrap();
    assert_eq!(latest_state.height, height2 as i64);
    assert_eq!(latest_state.value, updated_value);
    assert_eq!(latest_value, updated_value);

    // Delete the contract state
    delete_contract_state(&conn, height2 as i64, tx_id, contract_id, path).await?;

    // Verify the contract state is deleted
    let latest_state = get_latest_contract_state(&conn, contract_id, path).await?;
    assert!(latest_state.is_none());

    let count = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE contract_id = ? AND path = ?",
            vec![contract_id, path],
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get::<u64>(0)
        .unwrap();
    assert_eq!(count, 2);

    Ok(())
}

#[tokio::test]
async fn test_transaction_operations() -> Result<()> {
    let config = Config::try_parse()?;
    let (_reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();

    // Insert a block first
    let height = 800000;
    let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
    let block = BlockRow { height, hash };
    insert_block(&conn, block).await?;

    let tx1 = TransactionRow::builder()
        .height(height as i64)
        .txid("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string())
        .tx_index(0)
        .build();
    let tx2 = TransactionRow::builder()
        .height(height as i64)
        .txid("123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0".to_string())
        .tx_index(1)
        .build();
    let tx3 = TransactionRow::builder()
        .height(height as i64)
        .txid("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string())
        .tx_index(2)
        .build();

    // Insert multiple transactions at the same height

    let tx_id1 = insert_transaction(&conn, tx1).await?;
    let tx_id2 = insert_transaction(&conn, tx2.clone()).await?;
    let tx_id3 = insert_transaction(&conn, tx3.clone()).await?;

    // Test get_transaction_by_id
    let tx1 = get_transaction_by_id(&conn, tx_id1).await?.unwrap();
    assert_eq!(tx1.id, Some(tx_id1));
    assert_eq!(tx1.txid, tx1.txid);
    assert_eq!(tx1.height, height as i64);

    // Test get_transaction_by_txid
    let tx2 = get_transaction_by_txid(&conn, tx2.txid.as_str())
        .await?
        .unwrap();
    assert_eq!(tx2.id, Some(tx_id2));
    assert_eq!(tx2.txid, tx2.txid);
    assert_eq!(tx2.height, height as i64);

    // Test get_transactions_at_height
    let txs_at_height = get_transactions_at_height(&conn, height as i64).await?;
    assert_eq!(txs_at_height.len(), 3);

    // Verify all transactions are included - now using TransactionRow objects
    let tx_ids: Vec<i64> = txs_at_height.iter().filter_map(|tx| tx.id).collect();

    let tx_ids_set: std::collections::HashSet<i64> = tx_ids.into_iter().collect();
    assert!(tx_ids_set.contains(&tx_id1));
    assert!(tx_ids_set.contains(&tx_id2));
    assert!(tx_ids_set.contains(&tx_id3));

    // Verify txids are also present
    let txids: Vec<&str> = txs_at_height.iter().map(|tx| tx.txid.as_str()).collect();

    let txids_set: std::collections::HashSet<&str> = txids.into_iter().collect();
    assert!(txids_set.contains(tx1.txid.as_str()));
    assert!(txids_set.contains(tx2.txid.as_str()));
    assert!(txids_set.contains(tx3.txid.as_str()));

    // Insert transactions at a different height
    let height2 = 800001;
    let hash2 = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?;
    let block2 = BlockRow {
        height: height2,
        hash: hash2,
    };
    insert_block(&conn, block2).await?;

    let tx4 = TransactionRow::builder()
        .height(height2 as i64)
        .txid("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string())
        .tx_index(0)
        .build();

    let tx_id4 = insert_transaction(&conn, tx4).await?;

    // Verify get_transactions_at_height returns only transactions at the specified height
    let txs_at_height1 = get_transactions_at_height(&conn, height as i64).await?;
    assert_eq!(txs_at_height1.len(), 3);

    let txs_at_height2 = get_transactions_at_height(&conn, height2 as i64).await?;
    assert_eq!(txs_at_height2.len(), 1);

    // Check the transaction details
    let tx4 = &txs_at_height2[0];
    assert_eq!(tx4.id, Some(tx_id4));
    assert_eq!(tx4.txid, tx4.txid);
    assert_eq!(tx4.height, height2 as i64);

    Ok(())
}

#[tokio::test]
async fn test_select_block_by_height_or_hash() -> Result<()> {
    let config = Config::try_parse()?;
    let (_reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();

    // Insert test blocks
    let block1 = BlockRow {
        height: 800000,
        hash: "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?,
    };
    let block2 = BlockRow {
        height: 800001,
        hash: "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?,
    };
    let block3 = BlockRow {
        height: 123456,
        hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".parse()?,
    };

    insert_block(&conn, block1.clone()).await?;
    insert_block(&conn, block2.clone()).await?;
    insert_block(&conn, block3.clone()).await?;

    // Test 1: Find by height (as string)
    let result = select_block_by_height_or_hash(&conn, "800000").await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 800000);
    assert_eq!(found_block.hash, block1.hash);

    // Test 2: Find by hash
    let result = select_block_by_height_or_hash(
        &conn,
        "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05",
    )
    .await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 800001);
    assert_eq!(found_block.hash, block2.hash);

    // Test 3: Find by different height
    let result = select_block_by_height_or_hash(&conn, "123456").await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 123456);
    assert_eq!(found_block.hash, block3.hash);

    // Test 4: Find by different hash
    let result = select_block_by_height_or_hash(
        &conn,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    )
    .await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 123456);
    assert_eq!(found_block.hash, block3.hash);

    // Test 5: Non-existent height
    let result = select_block_by_height_or_hash(&conn, "999999").await?;
    assert!(result.is_none());

    // Test 6: Non-existent hash
    let result = select_block_by_height_or_hash(&conn, "nonexistenthash123456789").await?;
    assert!(result.is_none());

    // Test 7: Invalid height format (non-numeric string that's not a hash)
    let result = select_block_by_height_or_hash(&conn, "invalid_height").await?;
    assert!(result.is_none());

    // Test 8: Empty string
    let result = select_block_by_height_or_hash(&conn, "").await?;
    assert!(result.is_none());

    // Test 9: Height 0 (edge case)
    let block_zero = BlockRow {
        height: 0,
        hash: "0000000000000000000000000000000000000000000000000000000000000000".parse()?,
    };
    insert_block(&conn, block_zero.clone()).await?;

    let result = select_block_by_height_or_hash(&conn, "0").await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 0);
    assert_eq!(found_block.hash, block_zero.hash);

    // Test 10: Very large height
    let large_height = u64::MAX;
    let result = select_block_by_height_or_hash(&conn, &large_height.to_string()).await?;
    assert!(result.is_none());

    // Test 11: Partial hash match (should not match)
    let result = select_block_by_height_or_hash(&conn, "000000000000000000015d76").await?;
    assert!(result.is_none());

    Ok(())
}

#[tokio::test]
async fn test_contracts() -> Result<()> {
    let config = Config::try_parse()?;
    let (_reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow::builder()
            .hash(new_mock_block_hash(0))
            .height(0)
            .build(),
    )
    .await?;
    let row = ContractRow::builder()
        .bytes("value".as_bytes().to_vec())
        .height(0)
        .tx_index(1)
        .name("test".to_string())
        .build();
    insert_contract(&conn, row.clone()).await?;
    let option_bytes = get_contract_bytes(
        &conn,
        ContractId::builder()
            .height(0)
            .tx_index(1)
            .name("test".to_string())
            .build(),
    )
    .await?;
    assert_eq!(option_bytes.unwrap(), row.bytes);
    Ok(())
}
