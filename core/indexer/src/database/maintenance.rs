use anyhow::{Context, Result};
use libsql::Connection;

pub(crate) async fn validate_node_schema(conn: &Connection) -> Result<()> {
    // Maintenance must reject unrelated files before DDL and avoid node startup.
    for projection in [
        "SELECT height, hash, relevant FROM blocks LIMIT 0",
        "SELECT id, txid, height, confirmed_height, tx_index, batch_height FROM transactions LIMIT 0",
        "SELECT id, name, height, tx_index, bytes FROM contracts LIMIT 0",
        "SELECT contract_id, path, height, value, deleted FROM contract_state LIMIT 0",
        "SELECT id, contract_id, tx_id, status FROM contract_results LIMIT 0",
        "SELECT height, hash FROM checkpoints LIMIT 0",
        "SELECT key, value FROM node_meta LIMIT 0",
    ] {
        conn.query(projection, ())
            .await
            .context("not a supported node database")?;
    }
    Ok(())
}
