use anyhow::Result;
use bitcoin::hashes::Hash;
use clap::Parser;
use kontor::{
    config::Config,
    database::{
        queries::insert_block,
        types::{BlockRow, CheckpointRow, ContractStateRow},
    },
    utils::new_test_db,
};
use libsql::params;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn test_checkpoint_trigger() -> Result<()> {
    let config = Config::try_parse()?;
    let (_reader, writer, _temp_dir) = new_test_db(&config).await?;
    let conn = writer.connection();

    for height in 1..=200 {
        let block = BlockRow {
            height,
            hash: bitcoin::BlockHash::from_byte_array([height as u8; 32]),
        };
        insert_block(&conn, block).await?;
    }

    // Test case 1: First insertion creates a checkpoint with ID 1
    let contract_state1 = ContractStateRow {
        id: None,
        contract_id: "contract1".to_string(),
        tx_id: 1,
        height: 10,
        path: "/test/path1".to_string(),
        value: Some(b"test value 1".to_vec()),
        deleted: false,
    };
    insert_contract_state(&conn, contract_state1.clone()).await?;

    // Verify the first checkpoint
    let checkpoint1 = get_checkpoint_by_id(&conn, 1).await?;
    assert_eq!(checkpoint1.height, 10);
    let expected_hash1 = calculate_row_hash(&contract_state1)?;
    assert_eq!(
        checkpoint1.hash.to_lowercase(),
        expected_hash1.to_lowercase()
    );
    let checkpoint_count1 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count1, 1);

    // Test case 2: Second insertion within same interval updates the checkpoint
    let contract_state2 = ContractStateRow {
        id: None,
        contract_id: "contract1".to_string(),
        tx_id: 2,
        height: 20, // Still within the first 50-block interval
        path: "/test/path2".to_string(),
        value: None,
        deleted: false,
    };
    insert_contract_state(&conn, contract_state2.clone()).await?;

    // Verify the checkpoint was updated
    let checkpoint2 = get_checkpoint_by_id(&conn, 1).await?;
    assert_eq!(checkpoint2.height, 20);
    let expected_hash2 = calculate_combined_hash(&contract_state2, &checkpoint1.hash)?;
    assert_eq!(
        checkpoint2.hash.to_lowercase(),
        expected_hash2.to_lowercase()
    );
    let checkpoint_count2 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count2, 1);

    // Test case 3: Insertion in a new interval creates a new checkpoint
    let contract_state3 = ContractStateRow {
        id: None,
        contract_id: "contract2".to_string(),
        tx_id: 3,
        height: 60, // In the second 50-block interval
        path: "/test/path3".to_string(),
        value: Some(b"test value 3".to_vec()),
        deleted: false,
    };
    insert_contract_state(&conn, contract_state3.clone()).await?;

    // Verify a new checkpoint was created
    let checkpoint3 = get_checkpoint_by_id(&conn, 2).await?;
    assert_eq!(checkpoint3.height, 60);
    let expected_hash3 = calculate_combined_hash(&contract_state3, &checkpoint2.hash)?;
    assert_eq!(
        checkpoint3.hash.to_lowercase(),
        expected_hash3.to_lowercase()
    );
    let checkpoint_count3 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count3, 2);

    // Test case 4: Another insertion in the same new interval updates that checkpoint
    let contract_state4 = ContractStateRow {
        id: None,
        contract_id: "contract2".to_string(),
        tx_id: 4,
        height: 75, // Still in the second 50-block interval
        path: "/test/path4".to_string(),
        value: Some(b"test value 4".to_vec()),
        deleted: false,
    };
    insert_contract_state(&conn, contract_state4.clone()).await?;

    // Verify the second checkpoint was updated
    let checkpoint4 = get_checkpoint_by_id(&conn, 2).await?;
    assert_eq!(checkpoint4.height, 75);
    let expected_hash4 = calculate_combined_hash(&contract_state4, &checkpoint3.hash)?;
    assert_eq!(
        checkpoint4.hash.to_lowercase(),
        expected_hash4.to_lowercase()
    );
    let checkpoint_count4 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count4, 2);

    // Test case 5: Insertion in yet another new interval creates another checkpoint
    let contract_state5 = ContractStateRow {
        id: None,
        contract_id: "contract3".to_string(),
        tx_id: 5,
        height: 120, // In the third 50-block interval
        path: "/test/path5".to_string(),
        value: Some(b"test value 5".to_vec()),
        deleted: false,
    };
    insert_contract_state(&conn, contract_state5.clone()).await?;

    // Verify a third checkpoint was created
    let checkpoint5 = get_checkpoint_by_id(&conn, 3).await?;
    assert_eq!(checkpoint5.height, 120);
    let expected_hash5 = calculate_combined_hash(&contract_state5, &checkpoint4.hash)?;
    assert_eq!(
        checkpoint5.hash.to_lowercase(),
        expected_hash5.to_lowercase()
    );
    let checkpoint_count5 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count5, 3);

    // Test case 6: Insertion in another new interval creates another checkpoint without a value
    let contract_state6 = ContractStateRow {
        id: None,
        contract_id: "contract4".to_string(),
        tx_id: 6,
        height: 190, // In the fourth 50-block interval
        path: "/test/path6".to_string(),
        value: None,
        deleted: false,
    };
    insert_contract_state(&conn, contract_state6.clone()).await?;

    // Verify a fourth checkpoint was created
    let checkpoint6 = get_checkpoint_by_id(&conn, 4).await?;
    assert_eq!(checkpoint6.height, 190);
    let expected_hash6 = calculate_combined_hash(&contract_state6, &checkpoint5.hash)?;
    assert_eq!(
        checkpoint6.hash.to_lowercase(),
        expected_hash6.to_lowercase()
    );
    let checkpoint_count6 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count6, 4);

    // Test case 7: Insertion in the same interval overwrites previous checkpoint
    let contract_state7 = ContractStateRow {
        id: None,
        contract_id: "contract4".to_string(),
        tx_id: 7,
        height: 199, // Still in the fourth 50-block interval
        path: "/test/path7".to_string(),
        value: Some(b"test value 7".to_vec()),
        deleted: false,
    };
    insert_contract_state(&conn, contract_state7.clone()).await?;

    // Verify the fourth checkpoint was updated
    let checkpoint7 = get_checkpoint_by_id(&conn, 4).await?;
    assert_eq!(checkpoint7.height, 199);
    let expected_hash7 = calculate_combined_hash(&contract_state7, &checkpoint6.hash)?;
    assert_eq!(
        checkpoint7.hash.to_lowercase(),
        expected_hash7.to_lowercase()
    );
    let checkpoint_count7 = count_checkpoints(&conn).await?;
    assert_eq!(checkpoint_count7, 4);

    Ok(())
}

async fn get_checkpoint_by_id(conn: &libsql::Connection, id: i64) -> Result<CheckpointRow> {
    let mut stmt = conn
        .prepare("SELECT id, height, hash FROM checkpoints WHERE id = ?")
        .await?;
    let mut rows = stmt.query(params![id]).await?;

    if let Some(row) = rows.next().await? {
        Ok(CheckpointRow {
            id: row.get(0)?,
            height: row.get(1)?,
            hash: row.get(2)?,
        })
    } else {
        anyhow::bail!("No checkpoint found with id {}", id)
    }
}

async fn count_checkpoints(conn: &libsql::Connection) -> Result<i64> {
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM checkpoints").await?;
    let mut rows = stmt.query(params![]).await?;

    if let Some(row) = rows.next().await? {
        Ok(row.get(0)?)
    } else {
        Ok(0) // Return 0 if no rows (shouldn't happen for COUNT query)
    }
}

fn calculate_row_hash(state: &ContractStateRow) -> Result<String> {
    let value_part = match &state.value {
        Some(v) => String::from_utf8_lossy(v).to_string(),
        None => "".to_string(), // Empty string for NULL, matching concat() behavior
    };

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

async fn insert_contract_state(conn: &libsql::Connection, row: ContractStateRow) -> Result<i64> {
    let _result = conn
        .execute(
            "INSERT INTO contract_state (contract_id, tx_id, height, path, value, deleted) 
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                row.contract_id,
                row.tx_id,
                row.height,
                row.path,
                row.value,
                row.deleted
            ],
        )
        .await?;

    // Get the last inserted row ID
    let last_id = conn.last_insert_rowid();

    Ok(last_id)
}
