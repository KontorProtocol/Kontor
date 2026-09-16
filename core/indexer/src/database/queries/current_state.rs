use libsql::Connection;

use super::Error;

// Queries also run directly in tooling/tests. A nested savepoint makes history
// and its derived index atomic both with and without a caller's transaction.
pub(super) async fn with_state_savepoint<T>(
    conn: &Connection,
    operation: impl AsyncFnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    conn.execute("SAVEPOINT current_state_change", ()).await?;
    match operation().await {
        Ok(value) => {
            conn.execute("RELEASE current_state_change", ()).await?;
            Ok(value)
        }
        Err(error) => {
            conn.execute_batch("ROLLBACK TO current_state_change; RELEASE current_state_change;")
                .await?;
            Err(error)
        }
    }
}

pub(super) async fn prepare_affected_keys(conn: &Connection) -> Result<(), Error> {
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS affected_state_keys (
             contract_id INTEGER NOT NULL, path BLOB NOT NULL,
             PRIMARY KEY (contract_id, path)
         ) WITHOUT ROWID;
         DELETE FROM affected_state_keys;",
    )
    .await?;
    Ok(())
}

pub(super) const RESTORE_AFFECTED_KEYS: &str = "INSERT INTO current_contract_state (contract_id, path, height, size)
         SELECT s.contract_id, s.path, s.height, s.size
         FROM affected_state_keys a CROSS JOIN contract_state s ON s.rowid = (
             SELECT n.rowid FROM contract_state n
             WHERE n.contract_id = a.contract_id AND n.path = a.path
             ORDER BY n.height DESC LIMIT 1
         ) WHERE s.deleted = 0
         ON CONFLICT (contract_id, path) DO UPDATE SET height = excluded.height, size = excluded.size";

// The height cascade (reorg) or exact-key delete (variant cleanup) removes
// displaced pointers first. Pick the newest survivor BEFORE testing liveness.
pub(super) async fn restore_affected_keys(conn: &Connection) -> Result<(), Error> {
    conn.execute(RESTORE_AFFECTED_KEYS, ()).await?;
    conn.execute("DELETE FROM affected_state_keys", ()).await?;
    Ok(())
}
