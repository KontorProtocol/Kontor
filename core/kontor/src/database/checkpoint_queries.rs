use anyhow::Result;
use hex;
use libsql::{Connection, params};

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

pub async fn create_checkpoint_from_state(conn: &Connection, height: u64) -> Result<String> {
    // Perform the entire checkpoint creation in a single SQL query
    let mut query_result = conn
        .query(
            "WITH latest_row AS (
                SELECT 
                    contract_id,
                    path,
                    value,
                    deleted
                FROM contract_state 
                WHERE id = (SELECT MAX(id) FROM contract_state WHERE deleted = FALSE)
            ),
            row_data AS (
                SELECT 
                    CONCAT(
                        contract_id,
                        path,
                        value,
                        deleted
                    ) as concatenated_data
                FROM latest_row
            ),
            row_hash AS (
                SELECT hex(crypto_sha256(concatenated_data)) as hash
                FROM row_data
            ),
            prev_hash AS (
                SELECT hash
                FROM checkpoints
                WHERE id = (SELECT MAX(id) FROM checkpoints)
            ),
            new_hash AS (
                SELECT 
                    CASE 
                        WHEN p.hash IS NOT NULL THEN 
                            hex(crypto_sha256(CONCAT(r.hash, p.hash)))
                        ELSE 
                            r.hash
                    END AS hash
                FROM row_hash r
                LEFT JOIN prev_hash p ON 1=1
            )
            SELECT hash FROM new_hash",
            params![],
        )
        .await?;

    // Get the calculated hash
    let hash_row = match query_result.next().await? {
        Some(row) => row,
        None => return Err(anyhow::anyhow!("Failed to calculate checkpoint hash")),
    };

    let new_hash = hash_row.get::<String>(0)?;

    // Insert the new checkpoint
    conn.execute(
        "INSERT INTO checkpoints (height, hash) VALUES (?, ?)",
        params![height, new_hash.clone()],
    )
    .await?;

    Ok(new_hash)
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
) -> Result<Option<String>> {
    // Only create checkpoints at the specified interval
    if height % checkpoint_interval == 0 {
        // if height difference is not greater than n rows, we replace the existing highest, otherwise create a new row
        // do we just update or create a new one
        // if the gap is beneath the trheshold, keep updating

        // Get the previous checkpoint hash
        let previous_hash = get_latest_checkpoint_hash(conn).await?;

        // Create the new checkpoint
        let new_hash = create_checkpoint_from_state(conn, height).await?;

        Ok(Some(new_hash))
    } else {
        Ok(None)
    }
}
