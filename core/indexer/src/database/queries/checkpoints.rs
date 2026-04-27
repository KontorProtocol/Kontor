use turso::{Connection, params};

use super::Error;
use crate::database::de::first_row;
use crate::database::types::CheckpointRow;

pub async fn get_checkpoint_by_height(
    conn: &Connection,
    height: i64,
) -> Result<Option<CheckpointRow>, Error> {
    let mut row = conn
        .query(
            "SELECT height, hash FROM checkpoints WHERE height = ?",
            params![height],
        )
        .await?;
    first_row(&mut row).await
}

pub async fn get_checkpoint_latest(conn: &Connection) -> Result<Option<CheckpointRow>, Error> {
    let mut row = conn
        .query(
            "SELECT height, hash FROM checkpoints ORDER BY height DESC LIMIT 1",
            params![],
        )
        .await?;
    first_row(&mut row).await
}
