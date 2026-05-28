use libsql::{Connection, Value, de::from_row, params};

use super::Error;
use crate::database::types::CheckpointRow;

pub async fn get_checkpoint_by_height(
    conn: &Connection,
    height: u64,
) -> Result<Option<CheckpointRow>, Error> {
    let mut row = conn
        .query(
            "SELECT height, hash FROM checkpoints WHERE height = ?",
            params![Value::try_from(height)?],
        )
        .await?;
    Ok(row.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_checkpoint_latest(conn: &Connection) -> Result<Option<CheckpointRow>, Error> {
    let mut row = conn
        .query(
            "SELECT height, hash FROM checkpoints ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;
    Ok(row.next().await?.map(|r| from_row(&r)).transpose()?)
}
