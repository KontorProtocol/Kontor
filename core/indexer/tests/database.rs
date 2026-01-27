use std::collections::HashSet;

use anyhow::Result;
use futures_util::{StreamExt, TryStreamExt};
use indexer::{
    database::{
        queries::{
            contract_has_state, delete_contract_state, delete_matching_paths,
            exists_contract_state, get_contract_bytes_by_address, get_contract_bytes_by_id,
            get_contract_id_from_address, get_contract_result, get_contracts,
            get_latest_contract_state, get_latest_contract_state_value, get_op_result,
            get_transaction_by_txid, get_transactions_at_height, insert_block, insert_contract,
            insert_contract_result, insert_contract_state, insert_file_metadata,
            insert_processed_block, insert_transaction, matching_path,
            path_prefix_filter_contract_state, rollback_to_height, select_all_file_metadata,
            select_block_at_height, select_block_latest, select_processed_block_by_height_or_hash,
        },
        types::{ContractResultRow, ContractRow, ContractStateRow, FileMetadataRow, OpResultId},
    },
    runtime::ContractAddress,
    test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db},
};
use indexer_types::{BlockRow, ContractListRow, TransactionRow};
use libsql::{Connection, params};

#[tokio::test]
async fn test_database() -> Result<()> {
    let height: i64 = 800000;
    let hash = new_mock_block_hash(height as u32);
    let block = BlockRow::builder().height(height).hash(hash).build();

    let (reader, writer, _temp_dir) = new_test_db().await?;

    insert_processed_block(&writer.connection(), block).await?;
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
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let tx = writer.connection().transaction().await?;
    let height = 800000;
    let hash = new_mock_block_hash(height as u32);
    let block = BlockRow::builder().height(height).hash(hash).build();
    insert_processed_block(&tx, block).await?;
    assert!(select_block_latest(&tx).await?.is_some());
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
async fn test_crypto_extension() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
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
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // First insert a block to satisfy foreign key constraints
    let height = 800000;
    let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
    let block = BlockRow::builder().height(height).hash(hash).build();
    insert_block(&conn, block).await?;

    // Insert a transaction for the contract state
    let tx = TransactionRow::builder()
        .height(height)
        .txid("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string())
        .tx_index(0)
        .build();
    insert_transaction(&conn, tx.clone()).await?;

    // Test contract state insertion and retrieval
    let contract_id = 123;
    let path = "test.path";
    let value = vec![1, 2, 3, 4];

    assert!(!contract_has_state(&conn, contract_id).await?);

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_index(tx.tx_index)
        .height(height)
        .path(path.to_string())
        .value(value.clone())
        .build();

    // Insert contract state
    let id = insert_contract_state(&conn, contract_state.clone()).await?;
    assert!(id > 0, "Contract state insertion should succeed");

    // check existence
    assert!(contract_has_state(&conn, contract_id).await?);
    assert!(exists_contract_state(&conn, contract_id, "test.").await?);

    assert_eq!(
        matching_path(&conn, contract_id, "test", r"^test.(path|foo|bar)(\..*|$)")
            .await?
            .unwrap(),
        path
    );

    // Get latest contract state
    let retrieved_state = get_latest_contract_state(&conn, contract_id, path).await?;
    assert!(
        retrieved_state.is_some(),
        "Contract state should be retrieved"
    );

    // Get latest contract state value
    let fuel = 1000;
    let retrieved_value = get_latest_contract_state_value(&conn, 1000, contract_id, path).await?;
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
    assert_eq!(retrieved_state.height, height);
    assert_eq!(retrieved_state.tx_index, contract_state.tx_index);

    // Test with a newer version of the same contract state
    let height2 = 800001;
    let hash2 = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?;
    let block2 = BlockRow::builder().height(height2).hash(hash2).build();
    insert_block(&conn, block2).await?;

    let txid2 = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    let tx2 = TransactionRow::builder()
        .height(height2)
        .txid(txid2.to_string())
        .tx_index(2)
        .build();
    insert_transaction(&conn, tx2.clone()).await?;

    let updated_value = vec![5, 6, 7, 8];
    let updated_contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_index(tx2.tx_index)
        .height(height2)
        .path(path.to_string())
        .value(updated_value.clone())
        .build();
    insert_contract_state(&conn, updated_contract_state).await?;

    // Verify we get the latest version
    let latest_state = get_latest_contract_state(&conn, contract_id, path)
        .await?
        .unwrap();
    let latest_value = get_latest_contract_state_value(&conn, fuel, contract_id, path)
        .await?
        .unwrap();
    assert_eq!(latest_state.height, height2);
    assert_eq!(latest_state.value, updated_value);
    assert_eq!(latest_value, updated_value);

    // Delete the contract state
    let deleted = delete_contract_state(&conn, height2, tx2.tx_index, contract_id, path).await?;
    assert!(deleted);

    let count = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE contract_id = :contract_id AND path = :path",
            ((":contract_id", contract_id), (":path", path)),
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get::<u64>(0)
        .unwrap();
    assert_eq!(count, 2);

    // Verify the contract state is deleted
    let latest_state = get_latest_contract_state(&conn, contract_id, path).await?;
    assert!(latest_state.is_none());

    Ok(())
}

#[tokio::test]
async fn test_transaction_operations() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // Insert a block first
    let height = 800000;
    let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
    let block = BlockRow::builder().height(height).hash(hash).build();
    insert_block(&conn, block).await?;

    let tx1 = TransactionRow::builder()
        .height(height)
        .txid("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string())
        .tx_index(0)
        .build();
    let tx2 = TransactionRow::builder()
        .height(height)
        .txid("123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0".to_string())
        .tx_index(1)
        .build();
    let tx3 = TransactionRow::builder()
        .height(height)
        .txid("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string())
        .tx_index(2)
        .build();

    // Insert multiple transactions at the same height

    insert_transaction(&conn, tx1.clone()).await?;
    insert_transaction(&conn, tx2.clone()).await?;
    insert_transaction(&conn, tx3.clone()).await?;

    // Test get_transaction_by_txid
    let result = get_transaction_by_txid(&conn, tx2.txid.as_str())
        .await?
        .unwrap();
    assert_eq!(tx2.txid, result.txid);
    assert_eq!(tx2.height, result.height);
    assert_eq!(tx2.tx_index, result.tx_index);

    // Test get_transactions_at_height
    let txs_at_height = get_transactions_at_height(&conn, height).await?;
    assert_eq!(txs_at_height.len(), 3);

    // Verify all transactions are included - now using TransactionRow objects
    let txids = txs_at_height
        .iter()
        .map(|tx| tx.txid.clone())
        .collect::<HashSet<_>>();

    assert!(txids.contains(&tx1.txid));
    assert!(txids.contains(&tx2.txid));
    assert!(txids.contains(&tx3.txid));

    // Insert transactions at a different height
    let height2 = 800001;
    let hash2 = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?;
    let block2 = BlockRow::builder().height(height2).hash(hash2).build();
    insert_block(&conn, block2).await?;

    let tx4 = TransactionRow::builder()
        .height(height2)
        .txid("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string())
        .tx_index(0)
        .build();

    insert_transaction(&conn, tx4).await?;

    // Verify get_transactions_at_height returns only transactions at the specified height
    let txs_at_height1 = get_transactions_at_height(&conn, height).await?;
    assert_eq!(txs_at_height1.len(), 3);

    let txs_at_height2 = get_transactions_at_height(&conn, height2).await?;
    assert_eq!(txs_at_height2.len(), 1);

    // Check the transaction details
    let tx4 = &txs_at_height2[0];
    assert_eq!(tx4.tx_index, tx4.tx_index);
    assert_eq!(tx4.txid, tx4.txid);
    assert_eq!(tx4.height, height2);

    Ok(())
}

#[tokio::test]
async fn test_select_processed_block_by_height_or_hash() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // Insert test blocks
    let block1 = BlockRow::builder()
        .height(800000)
        .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?)
        .build();
    let block2 = BlockRow::builder()
        .height(800001)
        .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?)
        .build();
    let block3 = BlockRow::builder()
        .height(123456)
        .hash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".parse()?)
        .build();

    insert_processed_block(&conn, block1.clone()).await?;
    insert_processed_block(&conn, block2.clone()).await?;
    insert_processed_block(&conn, block3.clone()).await?;

    // Test 1: Find by height (as string)
    let result = select_processed_block_by_height_or_hash(&conn, "800000").await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 800000);
    assert_eq!(found_block.hash, block1.hash);

    // Test 2: Find by hash
    let result = select_processed_block_by_height_or_hash(
        &conn,
        "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05",
    )
    .await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 800001);
    assert_eq!(found_block.hash, block2.hash);

    // Test 3: Find by different height
    let result = select_processed_block_by_height_or_hash(&conn, "123456").await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 123456);
    assert_eq!(found_block.hash, block3.hash);

    // Test 4: Find by different hash
    let result = select_processed_block_by_height_or_hash(
        &conn,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    )
    .await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 123456);
    assert_eq!(found_block.hash, block3.hash);

    // Test 5: Non-existent height
    let result = select_processed_block_by_height_or_hash(&conn, "999999").await?;
    assert!(result.is_none());

    // Test 6: Non-existent hash
    let result =
        select_processed_block_by_height_or_hash(&conn, "nonexistenthash123456789").await?;
    assert!(result.is_none());

    // Test 7: Invalid height format (non-numeric string that's not a hash)
    let result = select_processed_block_by_height_or_hash(&conn, "invalid_height").await?;
    assert!(result.is_none());

    // Test 8: Empty string
    let result = select_processed_block_by_height_or_hash(&conn, "").await?;
    assert!(result.is_none());

    // Test 9: Height 0 (edge case)
    let block_zero = BlockRow::builder()
        .height(0)
        .hash("0000000000000000000000000000000000000000000000000000000000000000".parse()?)
        .build();
    insert_processed_block(&conn, block_zero.clone()).await?;

    let result = select_processed_block_by_height_or_hash(&conn, "0").await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 0);
    assert_eq!(found_block.hash, block_zero.hash);

    // Test 10: Very large height
    let large_height = u64::MAX;
    let result = select_processed_block_by_height_or_hash(&conn, &large_height.to_string()).await?;
    assert!(result.is_none());

    // Test 11: Partial hash match (should not match)
    let result =
        select_processed_block_by_height_or_hash(&conn, "000000000000000000015d76").await?;
    assert!(result.is_none());

    Ok(())
}

#[tokio::test]
async fn test_contracts() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow::builder()
            .hash(new_mock_block_hash(0))
            .height(0)
            .build(),
    )
    .await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(0)
            .tx_index(1)
            .txid(new_mock_transaction(1).txid.to_string())
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
    let address = ContractAddress {
        height: 0,
        tx_index: 1,
        name: "test".to_string(),
    };
    let bytes = get_contract_bytes_by_address(&conn, &address)
        .await?
        .unwrap();
    assert_eq!(bytes, row.bytes);
    let id = get_contract_id_from_address(&conn, &address)
        .await?
        .unwrap();
    let bytes = get_contract_bytes_by_id(&conn, id).await?.unwrap();
    assert_eq!(bytes, row.bytes);
    let rows = get_contracts(&conn).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], ContractListRow { id, ..row.into() });
    Ok(())
}

#[tokio::test]
async fn test_contracts_gapless() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let insert = async |conn: &Connection, i: i64| {
        insert_block(
            conn,
            BlockRow::builder()
                .hash(new_mock_block_hash(i as u32))
                .height(i)
                .build(),
        )
        .await
        .unwrap();
        let row = ContractRow::builder()
            .bytes("value".as_bytes().to_vec())
            .height(i)
            .tx_index(1)
            .name("test".to_string())
            .build();
        insert_contract(conn, row.clone()).await.unwrap();
    };
    for i in 1i64..=5 {
        insert(&conn, i).await;
    }
    let query = "SELECT id FROM contracts ORDER BY height ASC";
    let get_ids = async |conn: &Connection| {
        conn.query(query, params![])
            .await
            .unwrap()
            .into_stream()
            .map(|row| row.unwrap().get::<i64>(0).unwrap())
            .collect::<Vec<_>>()
            .await
    };
    assert_eq!(get_ids(&conn).await, vec![1, 2, 3, 4, 5]);
    rollback_to_height(&conn, 3).await?;
    assert_eq!(get_ids(&conn).await, vec![1, 2, 3]);
    for i in 4i64..=5 {
        insert(&conn, i).await;
    }
    assert_eq!(get_ids(&conn).await, vec![1, 2, 3, 4, 5]);
    Ok(())
}

#[tokio::test]
async fn test_map_keys() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    let height = 800000;
    let block1 = BlockRow::builder()
        .height(height)
        .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?)
        .build();

    insert_block(&conn, block1.clone()).await?;

    let contract_id = 123;
    let path = "test.path";
    let value = vec![1, 2, 3, 4];
    let tx_index = 1;

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_index(tx_index)
        .height(height)
        .path(format!("{}.key0.foo", path))
        .value(value.clone())
        .build();

    insert_contract_state(&conn, contract_state).await?;

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_index(tx_index)
        .height(height)
        .path(format!("{}.key0.bar", path))
        .value(value.clone())
        .build();

    insert_contract_state(&conn, contract_state).await?;

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_index(tx_index + 1)
        .height(height)
        .path(format!("{}.key2", path))
        .value(value.clone())
        .build();
    insert_contract_state(&conn, contract_state).await?;

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_index(tx_index + 2)
        .height(height)
        .path(format!("{}.key1", path))
        .value(value.clone())
        .build();
    insert_contract_state(&conn, contract_state).await?;

    let stream =
        path_prefix_filter_contract_state(&conn, contract_id, "test.path".to_string()).await?;
    let paths = stream.try_collect::<Vec<String>>().await?;
    assert_eq!(paths.len(), 3);
    assert_eq!(paths[0], "key0");
    assert_eq!(paths[1], "key1");
    assert_eq!(paths[2], "key2");

    let result = delete_matching_paths(
        &conn,
        contract_id,
        height,
        &format!(r"^{}.({})(\..*|$)", "test.path", ["key0"].join("|")),
    )
    .await?;
    assert_eq!(result, 2);

    Ok(())
}

#[tokio::test]
async fn test_contract_result_operations() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // Insert a block first
    let height = 800000;
    let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
    let block = BlockRow::builder().height(height).hash(hash).build();
    insert_processed_block(&conn, block).await?;

    let contract_id = insert_contract(
        &conn,
        ContractRow::builder()
            .name("token".to_string())
            .height(height)
            .tx_index(1)
            .bytes(vec![])
            .build(),
    )
    .await?;

    let txid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let tx1 = TransactionRow::builder()
        .height(height)
        .txid(txid.to_string())
        .tx_index(0)
        .build();

    insert_transaction(&conn, tx1.clone()).await?;

    let result = ContractResultRow::builder()
        .id(1)
        .tx_index(tx1.tx_index)
        .input_index(0)
        .op_index(0)
        .height(height)
        .contract_id(contract_id)
        .value("".to_string())
        .gas(100)
        .build();

    insert_contract_result(&conn, result.clone()).await?;

    let row = get_contract_result(
        &conn,
        result.height,
        result.tx_index,
        result.input_index,
        result.op_index,
        result.result_index,
    )
    .await?;
    assert_eq!(Some(result.clone()), row);

    let row = get_op_result(&conn, &OpResultId::builder().txid(txid.to_string()).build()).await?;
    assert!(row.is_some());
    assert_eq!(result.id, row.unwrap().id);

    Ok(())
}

#[tokio::test]
async fn test_file_metadata_operations() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // Insert a block first to satisfy foreign key constraints
    let height = 800000;
    let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
    let block = BlockRow::builder().height(height).hash(hash).build();
    insert_block(&conn, block).await?;

    // Insert a transaction
    let txid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let tx = TransactionRow::builder()
        .height(height)
        .txid(txid.to_string())
        .tx_index(0)
        .build();
    insert_transaction(&conn, tx.clone()).await?;

    // Initially, no file metadata entries should exist
    let entries = select_all_file_metadata(&conn).await?;
    assert!(entries.is_empty());

    // Insert a file metadata entry
    let file_id = "file_abc123".to_string();
    let root = [1u8; 32]; // 32 bytes for FieldElement
    let padded_len = 1024u64;
    let original_size = 100u64;
    let filename = "file_abc123.dat".to_string();

    let object_id = "obj_abc123".to_string();
    let nonce = vec![3u8; 32];

    let entry1 = FileMetadataRow::builder()
        .file_id(file_id.clone())
        .object_id(object_id.clone())
        .nonce(nonce.clone())
        .root(root)
        .padded_len(padded_len)
        .original_size(original_size)
        .filename(filename.clone())
        .height(height)
        .build();

    let id1 = insert_file_metadata(&conn, &entry1).await?;
    assert!(id1 > 0, "Insert should return a valid ID");

    // Verify entry was inserted
    let entries = select_all_file_metadata(&conn).await?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, id1);
    assert_eq!(entries[0].file_id, file_id);
    assert_eq!(entries[0].object_id, object_id);
    assert_eq!(entries[0].nonce, nonce);
    assert_eq!(entries[0].root, root);
    assert_eq!(entries[0].padded_len, padded_len);
    assert_eq!(entries[0].original_size, original_size);
    assert_eq!(entries[0].filename, filename);
    assert_eq!(entries[0].height, height);

    // Insert another file metadata entry at a different height
    let height2 = 800001;
    let hash2 = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?;
    let block2 = BlockRow::builder().height(height2).hash(hash2).build();
    insert_block(&conn, block2).await?;

    let txid2 = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    let tx2 = TransactionRow::builder()
        .height(height2)
        .txid(txid2.to_string())
        .tx_index(0)
        .build();
    insert_transaction(&conn, tx2.clone()).await?;

    let file_id2 = "file_def456".to_string();
    let object_id2 = "obj_def456".to_string();
    let nonce2 = vec![4u8; 32];
    let root2 = [2u8; 32];
    let padded_len2 = 2048u64;
    let original_size2 = 200u64;
    let filename2 = "file_def456.dat".to_string();

    let entry2 = FileMetadataRow::builder()
        .file_id(file_id2.clone())
        .object_id(object_id2)
        .nonce(nonce2)
        .root(root2)
        .padded_len(padded_len2)
        .original_size(original_size2)
        .filename(filename2)
        .height(height2)
        .build();

    let id2 = insert_file_metadata(&conn, &entry2).await?;
    assert!(id2 > id1, "Second entry should have a higher ID");

    // Verify both entries exist and are ordered by ID
    let entries = select_all_file_metadata(&conn).await?;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].id, id1);
    assert_eq!(entries[0].file_id, file_id);
    assert_eq!(entries[1].id, id2);
    assert_eq!(entries[1].file_id, file_id2);

    // Test rollback deletes file metadata entries (ON DELETE CASCADE)
    rollback_to_height(&conn, height as u64).await?;

    let entries = select_all_file_metadata(&conn).await?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, id1);

    Ok(())
}
