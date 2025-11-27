use anyhow::Result;
use bitcoin::hashes::Hash;
use indexer::{
    database::{
        queries::{
            get_checkpoint_by_height, get_checkpoint_latest, insert_block, insert_contract_state,
        },
        types::{BlockRow, ContractStateRow},
    },
    test_utils::new_test_db,
};
use libsql::params;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn test_checkpoint_trigger() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    for height in 1..=200 {
        let block = BlockRow::builder()
            .height(height)
            .hash(bitcoin::BlockHash::from_byte_array([height as u8; 32]))
            .build();
        insert_block(&conn, block).await?;
    }

    let contract_state1 = ContractStateRow::builder()
        .contract_id(1)
        .tx_index(1)
        .height(10)
        .path("/test/path1".to_string())
        .value(b"test value 1".to_vec())
        .build();
    insert_contract_state(&conn, contract_state1.clone()).await?;

    let checkpoint1 = get_checkpoint_by_height(&conn, 10).await?.unwrap();
    assert_eq!(checkpoint1.height, 10);
    let expected_hash1 = calculate_row_hash(&contract_state1)?;
    assert_eq!(
        checkpoint1.hash.to_lowercase(),
        expected_hash1.to_lowercase()
    );
    let checkpoint_count1 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count1, 1);

    let contract_state2 = ContractStateRow::builder()
        .contract_id(1)
        .tx_index(2)
        .height(20)
        .path("/test/path2".to_string())
        .build();
    insert_contract_state(&conn, contract_state2.clone()).await?;

    let checkpoint2 = get_checkpoint_by_height(&conn, 20).await?.unwrap();
    assert_eq!(checkpoint2.height, 20);
    let expected_hash2 = calculate_combined_hash(&contract_state2, &checkpoint1.hash)?;
    assert_eq!(
        checkpoint2.hash.to_lowercase(),
        expected_hash2.to_lowercase()
    );
    let checkpoint_count2 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count2, 2);

    let contract_state3 = ContractStateRow::builder()
        .contract_id(2)
        .tx_index(3)
        .height(60)
        .path("/test/path3".to_string())
        .value(b"test value 3".to_vec())
        .build();
    insert_contract_state(&conn, contract_state3.clone()).await?;

    let checkpoint3 = get_checkpoint_by_height(&conn, 60).await?.unwrap();
    assert_eq!(checkpoint3.height, 60);
    let expected_hash3 = calculate_combined_hash(&contract_state3, &checkpoint2.hash)?;
    assert_eq!(
        checkpoint3.hash.to_lowercase(),
        expected_hash3.to_lowercase()
    );
    let checkpoint_count3 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count3, 3);

    let contract_state4 = ContractStateRow::builder()
        .contract_id(2)
        .tx_index(4)
        .height(75)
        .path("/test/path4".to_string())
        .value(b"test value 4".to_vec())
        .build();
    insert_contract_state(&conn, contract_state4.clone()).await?;

    let checkpoint4 = get_checkpoint_by_height(&conn, 75).await?.unwrap();
    assert_eq!(checkpoint4.height, 75);
    let expected_hash4 = calculate_combined_hash(&contract_state4, &checkpoint3.hash)?;
    assert_eq!(
        checkpoint4.hash.to_lowercase(),
        expected_hash4.to_lowercase()
    );
    let checkpoint_count4 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count4, 4);

    let contract_state5 = ContractStateRow::builder()
        .contract_id(3)
        .tx_index(5)
        .height(120)
        .path("/test/path5".to_string())
        .value(b"test value 5".to_vec())
        .build();
    insert_contract_state(&conn, contract_state5.clone()).await?;

    let checkpoint5 = get_checkpoint_by_height(&conn, 120).await?.unwrap();
    assert_eq!(checkpoint5.height, 120);
    let expected_hash5 = calculate_combined_hash(&contract_state5, &checkpoint4.hash)?;
    assert_eq!(
        checkpoint5.hash.to_lowercase(),
        expected_hash5.to_lowercase()
    );
    let checkpoint_count5 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count5, 5);

    let contract_state6 = ContractStateRow::builder()
        .contract_id(4)
        .tx_index(6)
        .height(190)
        .path("/test/path6".to_string())
        .build();
    insert_contract_state(&conn, contract_state6.clone()).await?;

    let checkpoint6 = get_checkpoint_by_height(&conn, 190).await?.unwrap();
    assert_eq!(checkpoint6.height, 190);
    let expected_hash6 = calculate_combined_hash(&contract_state6, &checkpoint5.hash)?;
    assert_eq!(
        checkpoint6.hash.to_lowercase(),
        expected_hash6.to_lowercase()
    );
    let checkpoint_count6 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count6, 6);

    let contract_state7 = ContractStateRow::builder()
        .contract_id(4)
        .tx_index(7)
        .height(199)
        .path("/test/path7".to_string())
        .value(b"test value 7".to_vec())
        .build();
    insert_contract_state(&conn, contract_state7.clone()).await?;

    let checkpoint7 = get_checkpoint_by_height(&conn, 199).await?.unwrap();
    assert_eq!(checkpoint7.height, 199);
    let expected_hash7 = calculate_combined_hash(&contract_state7, &checkpoint6.hash)?;
    assert_eq!(
        checkpoint7.hash.to_lowercase(),
        expected_hash7.to_lowercase()
    );
    let checkpoint_count7 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count7, 7);

    let checkpoint_latest = get_checkpoint_latest(&conn).await?.unwrap();
    assert_eq!(checkpoint7, checkpoint_latest);

    // Test case 8: Insertion in the same height
    let contract_state8 = ContractStateRow::builder()
        .contract_id(4)
        .tx_index(8)
        .height(199)
        .path("/test/path7".to_string())
        .value(b"test value 7".to_vec())
        .build();
    insert_contract_state(&conn, contract_state8.clone()).await?;
    assert_eq!(count_checkpoints(&conn).await?, 7);
    let expected_hash8 = calculate_combined_hash(&contract_state8, &checkpoint7.hash)?;
    assert_eq!(
        expected_hash8.to_lowercase(),
        get_checkpoint_latest(&conn)
            .await?
            .unwrap()
            .hash
            .to_lowercase()
    );

    Ok(())
}

async fn count_checkpoints(conn: &libsql::Connection) -> Result<i64> {
    let stmt = conn.prepare("SELECT COUNT(*) FROM checkpoints").await?;
    let mut rows = stmt.query(params![]).await?;

    if let Some(row) = rows.next().await? {
        Ok(row.get(0)?)
    } else {
        Ok(0) // Return 0 if no rows (shouldn't happen for COUNT query)
    }
}

fn calculate_row_hash(state: &ContractStateRow) -> Result<String> {
    let value_part = hex::encode(&state.value).to_uppercase();

    let input = format!(
        "{}{}{}{}",
        state.contract_id,
        state.path,
        value_part,
        if state.deleted { "1" } else { "0" }
    );

    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();

    Ok(hex::encode(result).to_uppercase())
}

// Calculate combined hash using Rust
fn calculate_combined_hash(state: &ContractStateRow, prev_hash: &str) -> Result<String> {
    // First calculate the row hash
    let row_hash = calculate_row_hash(state)?;

    // Then combine with previous hash
    let combined = format!("{}{}", row_hash, prev_hash);

    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    let result = hasher.finalize();

    // Convert to uppercase hex to match SQLite's hex() function
    Ok(hex::encode(result).to_uppercase())
}
