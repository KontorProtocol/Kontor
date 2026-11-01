use libsql::{Connection, de::from_row, params};

use indexer_types::CheckpointRow;

use super::Error;

/// The latest checkpoint at or before `height`. Well-defined for any height
/// (the trigger only writes a checkpoint where contract state changed), and
/// immutable once a node has processed past `height` — so it's safe to compare
/// across nodes regardless of how far each has since advanced.
pub async fn get_checkpoint_as_of_height(
    conn: &Connection,
    height: u64,
) -> Result<Option<CheckpointRow>, Error> {
    let mut row = conn
        .query(
            "SELECT height, hash FROM checkpoints WHERE height <= ? ORDER BY height DESC LIMIT 1",
            params![height],
        )
        .await?;
    Ok(row.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_checkpoint_by_height(
    conn: &Connection,
    height: u64,
) -> Result<Option<CheckpointRow>, Error> {
    let mut row = conn
        .query(
            "SELECT height, hash FROM checkpoints WHERE height = ?",
            params![height],
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
