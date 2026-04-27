use std::path::Path;

use turso::Error;

pub const CREATE_SCHEMA: &str = include_str!("sql/schema.sql");
pub const CREATE_CONTRACT_STATE_TRIGGER: &str = include_str!("sql/checkpoint_trigger.sql");

pub async fn initialize_database(_data_dir: &Path, conn: &turso::Connection) -> Result<(), Error> {
    conn.query("PRAGMA foreign_keys = ON;", ()).await?;
    conn.execute_batch(CREATE_SCHEMA).await?;
    conn.execute(CREATE_CONTRACT_STATE_TRIGGER, ()).await?;
    conn.query("PRAGMA journal_mode = WAL;", ()).await?;
    conn.query("PRAGMA synchronous = NORMAL;", ()).await?;
    // crypto_sha256() comes from the limbo_crypto extension, auto-registered
    // because we depend on turso_core with the `crypto` feature enabled (a
    // feature added in our turso fork; see workspace Cargo.toml). REGEXP is
    // built into Turso core unconditionally.
    Ok(())
}
