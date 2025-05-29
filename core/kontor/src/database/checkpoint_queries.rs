use anyhow::Result;
use hex;
use libsql::{Connection, params};
use sha2::{Digest, Sha256};

use super::types::ContractStateRow;

pub async fn insert_checkpoint(conn: &Connection, height: u64, state_hash: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO checkpoints (height, hash) VALUES (?, ?)",
        // add autoincrementing primary key
        // have an insert, and then an update where id =
        params![height, state_hash],
    )
    .await?;

    Ok(())
}

pub async fn create_checkpoint_from_state(
    conn: &Connection,
    height: u64,
    contract_state_row: &ContractStateRow,
    previous_hash: Option<&str>,
) -> Result<String> {
    // 1. Hash the new contract state row
    let state_data = match &contract_state_row.value {
        Some(value) => format!( // can this be done in sql rather than rust?
            "{}:{}:{}:{}",
            contract_state_row.contract_id,
            contract_state_row.path,
            hex::encode(value),
            contract_state_row.deleted
        ),
        None => format!(
            "{}:{}:{}",
            contract_state_row.contract_id, contract_state_row.path, contract_state_row.deleted
        ),
    };
    // do a select and call hex on each column and then concat on each column in the row? https://www.sqlite.org/lang_corefunc.html#hex
    // do one piece at a time - query to hash the row, query to wrap last checkpoint hash with new checkpoint hash 
    let row_hash = calculate_hash(&state_data);

    // 2. Combine with previous hash if available
    let new_hash = match previous_hash {
        Some(prev) => calculate_hash(&format!("{}{}", row_hash, prev)),
        None => row_hash,
    };

    // 3. Insert the new checkpoint
    insert_checkpoint(conn, height, &new_hash).await?;

    Ok(new_hash)
}

fn calculate_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result) // should I be hex encoding here -- try to get the hex and concat in sql
    // concat everything, pull out as concat string, turn that to byte array, hash it

}

pub async fn get_latest_checkpoint_hash(conn: &Connection) -> Result<Option<String>> {
    let mut rows = conn
        .query(
            "SELECT hash FROM checkpoints ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;

    Ok(match rows.next().await? {
        Some(row) => Some(row.get(0)?),
        None => None,
    })
}

pub async fn maybe_create_checkpoint(
    conn: &Connection,
    height: u64,
    checkpoint_interval: u64,
    contract_state_row: &ContractStateRow,
) -> Result<Option<String>> {
    // Only create checkpoints at the specified interval
    if height % checkpoint_interval == 0 {  // if height difference is not greater than n rows, we replace the existing highest, otherwise create a new row
        // do we just update or create a new one
        // if the gap is beneath the trheshold, keep updating 

        // Get the previous checkpoint hash
        let previous_hash = get_latest_checkpoint_hash(conn).await?;

        // Create the new checkpoint
        let new_hash = create_checkpoint_from_state(
            conn,
            height,
            contract_state_row,
            previous_hash.as_deref(),
        )
        .await?;

        Ok(Some(new_hash))
    } else {
        Ok(None)
    }
}
