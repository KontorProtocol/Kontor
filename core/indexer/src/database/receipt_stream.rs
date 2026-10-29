use libsql::{Connection, TransactionBehavior, params};

use super::queries::Error;

pub const MAX_SAFE_RECEIPT_ID: u64 = 9_007_199_254_740_991;
pub const RECOVERY_BATCH_LIMIT: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamState {
    pub epoch: String,
    pub generation: u64,
    pub max_result_id: u64,
    pub unsupported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBoundary {
    pub generation: u64,
    pub cursor: u64,
    pub surviving_height: u64,
}

pub async fn initialize_receipt_stream(conn: &Connection) -> Result<(), libsql::Error> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    tx.execute_batch(include_str!("sql/receipt_stream.sql"))
        .await?;
    tx.commit().await
}

/// Call within the reader's snapshot when combining this state with receipt rows.
pub async fn stream_state(conn: &Connection) -> Result<StreamState, Error> {
    let mut rows = conn
        .query(
            "SELECT epoch, generation, unsupported,
                    COALESCE((SELECT MAX(id) FROM contract_results), 0)
             FROM receipt_stream_state WHERE singleton = 1",
            (),
        )
        .await?;
    let row = rows
        .next()
        .await?
        .ok_or_else(|| Error::InvalidData("missing receipt stream state".into()))?;
    Ok(StreamState {
        epoch: row.get(0)?,
        generation: row.get(1)?,
        unsupported: row.get::<i64>(2)? != 0,
        max_result_id: row.get(3)?,
    })
}

/// Runs after the canonical cascade, inside its existing rollback savepoint.
pub(super) async fn record_rollback(conn: &Connection, height: u64) -> Result<(), Error> {
    let changed = conn
        .execute(
            "UPDATE receipt_stream_state SET generation = generation + 1 WHERE singleton = 1",
            (),
        )
        .await?;
    if changed != 1 {
        return Err(Error::InvalidData("missing receipt stream state".into()));
    }
    conn.execute(
        "INSERT INTO receipt_stream_rollbacks
           (generation, surviving_height, surviving_max_id)
         SELECT generation, ?1, MAX(0, COALESCE((SELECT MAX(id) FROM contract_results), 0))
         FROM receipt_stream_state WHERE singleton = 1",
        [height],
    )
    .await?;
    Ok(())
}

/// The caller validates epoch/filter identity and keeps the same read snapshot.
pub async fn recovery_boundary(
    conn: &Connection,
    state: &StreamState,
    generation: u64,
    cursor: u64,
) -> Result<Option<RecoveryBoundary>, Error> {
    if generation > state.generation || cursor > MAX_SAFE_RECEIPT_ID {
        return Err(Error::InvalidCursor);
    }
    if state.unsupported {
        return Err(Error::InvalidData(
            "unsupported receipt stream lineage".into(),
        ));
    }
    if generation == state.generation {
        return Ok(None);
    }
    let mut rows = conn
        .query(
            "SELECT generation, surviving_height, surviving_max_id
             FROM receipt_stream_rollbacks WHERE generation > ?1 AND generation <= ?2
             ORDER BY generation LIMIT ?3",
            params![generation, state.generation, RECOVERY_BATCH_LIMIT],
        )
        .await?;
    let mut next_generation = generation;
    let mut next_cursor = cursor;
    let mut surviving_height = u64::MAX;
    while let Some(row) = rows.next().await? {
        let observed: u64 = row.get(0)?;
        if next_generation.checked_add(1) != Some(observed) {
            return Err(Error::InvalidData(
                "missing receipt rollback history".into(),
            ));
        }
        next_generation = observed;
        surviving_height = surviving_height.min(row.get(1)?);
        next_cursor = next_cursor.min(row.get(2)?);
    }
    let expected = (state.generation - generation).min(RECOVERY_BATCH_LIMIT);
    if next_generation - generation != expected {
        return Err(Error::InvalidData(
            "missing receipt rollback history".into(),
        ));
    }
    Ok(Some(RecoveryBoundary {
        generation: next_generation,
        cursor: next_cursor,
        surviving_height,
    }))
}

pub async fn rotate_stream_epoch(conn: &Connection) -> Result<String, Error> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let mut invalid = tx
        .query(
            "SELECT 1 FROM contract_results WHERE id < 1 OR id > ?1 LIMIT 1",
            [MAX_SAFE_RECEIPT_ID],
        )
        .await?;
    if invalid.next().await?.is_some() {
        return Err(Error::InvalidData(
            "receipt IDs are outside the supported range".into(),
        ));
    }
    drop(invalid);
    let changed = tx
        .execute(
            "UPDATE receipt_stream_state
             SET epoch = lower(hex(randomblob(32))), generation = 0, unsupported = 0
             WHERE singleton = 1",
            (),
        )
        .await?;
    if changed != 1 {
        return Err(Error::InvalidData("missing receipt stream state".into()));
    }
    tx.execute("DELETE FROM receipt_stream_rollbacks", ())
        .await?;
    let epoch = stream_state(&tx).await?.epoch;
    tx.commit().await?;
    Ok(epoch)
}

#[cfg(test)]
mod tests;
