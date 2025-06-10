use anyhow::Result;
use clap::Parser;
use kontor::{
    bitcoin_client::Client,
    config::Config,
    database::{
        queries::{
            get_latest_contract_state, get_transaction_by_id, get_transaction_by_txid,
            get_transactions_at_height, insert_block, insert_contract_state, insert_transaction,
            select_block_at_height, select_block_latest,
        },
        types::{BlockRow, ContractStateRow, TransactionRow},
    },
    logging,
    utils::new_test_db,
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
        .height(height)
        .txid("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string())
        .build();
    let tx_id = insert_transaction(&conn, tx).await?;

    // Test contract state insertion and retrieval
    let contract_id = "test_contract_123";
    let path = "test/path";
    let value = vec![1, 2, 3, 4];

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id.to_string())
        .tx_id(tx_id)
        .height(height)
        .path(path.to_string())
        .value(value.clone())
        .build();

    // Insert contract state
    let id = insert_contract_state(&conn, contract_state).await?;
    assert!(id > 0, "Contract state insertion should return a valid ID");

    // Get latest contract state
    let retrieved_state = get_latest_contract_state(&conn, contract_id, path).await?;
    assert!(
        retrieved_state.is_some(),
        "Contract state should be retrieved"
    );

    let retrieved_state = retrieved_state.unwrap();
    assert_eq!(retrieved_state.contract_id, contract_id);
    assert_eq!(retrieved_state.path, path);
    assert_eq!(retrieved_state.value, Some(value));
    assert!(!retrieved_state.deleted);
    assert_eq!(retrieved_state.height, height);
    assert_eq!(retrieved_state.tx_id, tx_id);

    // Test with a newer version of the same contract state
    let height2 = 800001;
    let block2 = BlockRow {
        height: height2,
        hash,
    };
    insert_block(&conn, block2).await?;

    let txid2 = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    let tx2 = TransactionRow::builder()
        .height(height2)
        .txid(txid2.to_string())
        .build();
    let tx_id2 = insert_transaction(&conn, tx2).await?;

    let updated_value = vec![5, 6, 7, 8];
    let updated_contract_state = ContractStateRow::builder()
        .contract_id(contract_id.to_string())
        .tx_id(tx_id2)
        .height(height2)
        .path(path.to_string())
        .value(updated_value.clone())
        .build();
    insert_contract_state(&conn, updated_contract_state).await?;

    // Verify we get the latest version
    let latest_state = get_latest_contract_state(&conn, contract_id, path)
        .await?
        .unwrap();
    assert_eq!(latest_state.height, height2);
    assert_eq!(latest_state.value, Some(updated_value));

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
        .height(height)
        .txid("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string())
        .build();
    let tx2 = TransactionRow::builder()
        .height(height)
        .txid("123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0".to_string())
        .build();
    let tx3 = TransactionRow::builder()
        .height(height)
        .txid("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string())
        .build();

    // Insert multiple transactions at the same height

    let tx_id1 = insert_transaction(&conn, tx1).await?;
    let tx_id2 = insert_transaction(&conn, tx2.clone()).await?;
    let tx_id3 = insert_transaction(&conn, tx3.clone()).await?;

    // Test get_transaction_by_id
    let tx1 = get_transaction_by_id(&conn, tx_id1).await?.unwrap();
    assert_eq!(tx1.id, Some(tx_id1));
    assert_eq!(tx1.txid, tx1.txid);
    assert_eq!(tx1.height, height);

    // Test get_transaction_by_txid
    let tx2 = get_transaction_by_txid(&conn, tx2.txid.as_str())
        .await?
        .unwrap();
    assert_eq!(tx2.id, Some(tx_id2));
    assert_eq!(tx2.txid, tx2.txid);
    assert_eq!(tx2.height, height);

    // Test get_transactions_at_height
    let txs_at_height = get_transactions_at_height(&conn, height).await?;
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
    let block2 = BlockRow {
        height: height2,
        hash,
    };
    insert_block(&conn, block2).await?;

    let tx4 = TransactionRow::builder()
        .height(height2)
        .txid("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string())
        .build();

    let tx_id4 = insert_transaction(&conn, tx4).await?;

    // Verify get_transactions_at_height returns only transactions at the specified height
    let txs_at_height1 = get_transactions_at_height(&conn, height).await?;
    assert_eq!(txs_at_height1.len(), 3);

    let txs_at_height2 = get_transactions_at_height(&conn, height2).await?;
    assert_eq!(txs_at_height2.len(), 1);

    // Check the transaction details
    let tx4 = &txs_at_height2[0];
    assert_eq!(tx4.id, Some(tx_id4));
    assert_eq!(tx4.txid, tx4.txid);
    assert_eq!(tx4.height, height2);

    Ok(())
}
