use std::path::Path;

use libsql::Error;
use tokio::fs;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.28.2/macos-arm64/crypto.dylib");

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.28.2/macos-x64/crypto.dylib");

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.28.2/linux-x64/crypto.so");

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.28.2/linux-arm64/crypto.so");

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.28.2/windows-x64/crypto.dll");

#[cfg(target_os = "macos")]
const LIB_FILE_EXT: &str = "dylib";
#[cfg(target_os = "linux")]
const LIB_FILE_EXT: &str = "so";
#[cfg(target_os = "windows")]
const LIB_FILE_EXT: &str = "dll";

pub const CREATE_SCHEMA: &str = include_str!("sql/schema.sql");
pub const CREATE_CONTRACT_STATE_TRIGGER: &str = include_str!("sql/checkpoint_trigger.sql");

pub async fn initialize_database(data_dir: &Path, conn: &libsql::Connection) -> Result<(), Error> {
    conn.query("PRAGMA foreign_keys = ON;", ()).await?;
    // Set BEFORE creating any tables so a fresh DB is born in INCREMENTAL
    // auto_vacuum mode: pages freed by state pruning can then be returned to the
    // OS via `PRAGMA incremental_vacuum`. On an existing DB the mode is fixed at
    // creation time, so this is a no-op there — `ensure_incremental_auto_vacuum`
    // does the one-time VACUUM conversion (called from the prune-enabled path).
    conn.query("PRAGMA auto_vacuum = INCREMENTAL;", ()).await?;
    conn.execute_batch(CREATE_SCHEMA).await?;
    conn.execute(CREATE_CONTRACT_STATE_TRIGGER, ()).await?;
    conn.query("PRAGMA journal_mode = WAL;", ()).await?;
    conn.query("PRAGMA synchronous = NORMAL;", ()).await?;
    // Wait-and-retry (up to 5s) on lock contention instead of failing instantly with
    // "database is locked" (SQLITE_BUSY). WAL keeps readers and the single writer
    // concurrent, but a WAL checkpoint or a concurrent prune/vacuum write can still take
    // a transient lock; without a busy_timeout the loser errors immediately, and the
    // reactor treats a failed block-decision insert as FATAL and exits the node — the
    // root cause of the flaky cluster-test node deaths (and a crash risk for a loaded
    // production node). Per-connection (this runs for every `new_connection`). 5s sits
    // under the consensus propose timeout, so a stalled write can't outlast a round.
    conn.query("PRAGMA busy_timeout = 5000;", ()).await?;
    conn.load_extension_enable()?;
    for (name, bytes) in [("crypto", CRYPTO_LIB)] {
        let p = data_dir.join(format!("{}.{}", name, LIB_FILE_EXT));
        if !fs::try_exists(&p)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?
        {
            fs::write(&p, bytes)
                .await
                .map_err(|e| Error::ConnectionFailed(e.to_string()))?;
        }
        // SQLite automatically adds platform-specific suffix (.so/.dylib/.dll)
        // so pass path without extension to avoid double extension
        let extension_path = data_dir.join(name);
        conn.load_extension(extension_path, None)?;
    }
    Ok(())
}

/// Ensure the database is in INCREMENTAL `auto_vacuum` mode so pages freed by
/// state pruning can be returned to the OS via `PRAGMA incremental_vacuum`. Fresh
/// DBs are created in this mode by [`initialize_database`]; an existing DB created
/// in another mode (SQLite's default is NONE) can only be converted by a full
/// `VACUUM` after setting the pragma. Idempotent — short-circuits once the mode is
/// already INCREMENTAL; returns `true` only when a conversion VACUUM was run.
///
/// The conversion is a one-time cost (exclusive lock, up to ~2x disk) paid on the
/// first prune-enabled startup of a pre-existing DB, so callers gate it on the
/// `prune` config to keep archive nodes from paying it.
pub async fn ensure_incremental_auto_vacuum(conn: &libsql::Connection) -> Result<bool, Error> {
    // PRAGMA auto_vacuum returns 0 = NONE, 1 = FULL, 2 = INCREMENTAL. Scope the read
    // so its cursor is dropped before VACUUM — an open statement makes VACUUM fail
    // with "SQL statements in progress".
    let current: i64 = {
        let mut rows = conn.query("PRAGMA auto_vacuum;", ()).await?;
        match rows.next().await? {
            Some(row) => row.get(0)?,
            None => return Ok(false),
        }
    };
    if current == 2 {
        return Ok(false);
    }
    conn.execute("PRAGMA auto_vacuum = INCREMENTAL;", ())
        .await?;
    conn.execute("VACUUM;", ()).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::new_connection;
    use tempfile::TempDir;

    async fn auto_vacuum_mode(conn: &libsql::Connection) -> i64 {
        let mut rows = conn.query("PRAGMA auto_vacuum;", ()).await.unwrap();
        rows.next().await.unwrap().unwrap().get(0).unwrap()
    }

    #[tokio::test]
    async fn fresh_db_is_born_incremental_auto_vacuum() {
        let dir = TempDir::new().unwrap();
        let conn = new_connection(dir.path(), "av_fresh.db").await.unwrap();
        assert_eq!(
            auto_vacuum_mode(&conn).await,
            2,
            "a fresh DB must be created in INCREMENTAL (2) auto_vacuum mode"
        );
    }

    #[tokio::test]
    async fn ensure_incremental_converts_existing_none_db_in_wal() {
        // A DB created in SQLite's default NONE mode, in WAL, with data — the
        // pre-pruning shape an upgrading node has. Asserts the conversion VACUUM
        // actually flips it to INCREMENTAL under WAL (audit concern #4) and keeps data.
        let dir = TempDir::new().unwrap();
        let db = libsql::Builder::new_local(dir.path().join("legacy.db"))
            .build()
            .await
            .unwrap();
        let conn = db.connect().unwrap();
        conn.query("PRAGMA journal_mode = WAL;", ()).await.unwrap();
        conn.execute("CREATE TABLE t (x)", ()).await.unwrap();
        conn.execute("INSERT INTO t VALUES (1), (2), (3)", ())
            .await
            .unwrap();
        assert_eq!(auto_vacuum_mode(&conn).await, 0, "precondition: NONE mode");

        let converted = ensure_incremental_auto_vacuum(&conn).await.unwrap();

        assert!(converted, "an existing NONE-mode DB should convert");
        assert_eq!(
            auto_vacuum_mode(&conn).await,
            2,
            "conversion VACUUM must flip the mode to INCREMENTAL even under WAL"
        );
        let mut rows = conn.query("SELECT COUNT(*) FROM t", ()).await.unwrap();
        let n: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
        assert_eq!(n, 3, "data must survive the conversion VACUUM");
    }

    #[tokio::test]
    async fn ensure_incremental_is_noop_on_fresh_db() {
        let dir = TempDir::new().unwrap();
        let conn = new_connection(dir.path(), "av_idem.db").await.unwrap();
        // Born incremental, so no conversion VACUUM should run.
        assert!(!ensure_incremental_auto_vacuum(&conn).await.unwrap());
        assert_eq!(auto_vacuum_mode(&conn).await, 2);
    }
}
