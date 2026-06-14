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

/// On-disk format version, stored in `PRAGMA user_version`. Bump on ANY
/// non-backward-compatible change to how indexed state is encoded — the rows are
/// fully reconstructible from Bitcoin (reindex-from-genesis), so an upgrade across
/// a bump means wipe-and-resync, not in-place migration. `1` is the first versioned
/// format: `contract_state.path` is order-preserving tuple-codec `BLOB` (the codec
/// migration), incompatible with the old dotted-TEXT paths which the byte-range
/// query logic can no longer match.
const SCHEMA_VERSION: i64 = 1;

pub async fn initialize_database(data_dir: &Path, conn: &libsql::Connection) -> Result<(), Error> {
    conn.query("PRAGMA foreign_keys = ON;", ()).await?;
    guard_schema_version(conn).await?;
    conn.execute_batch(CREATE_SCHEMA).await?;
    conn.execute(CREATE_CONTRACT_STATE_TRIGGER, ()).await?;
    // Stamp the format version (no-op once set; new on a fresh DB).
    conn.query(&format!("PRAGMA user_version = {SCHEMA_VERSION};"), ())
        .await?;
    conn.query("PRAGMA journal_mode = WAL;", ()).await?;
    conn.query("PRAGMA synchronous = NORMAL;", ()).await?;
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

/// Refuse to boot on a database whose format predates / mismatches
/// [`SCHEMA_VERSION`], rather than silently running new byte-range/codec queries
/// against incompatible rows (e.g. legacy dotted-TEXT `contract_state.path`), which
/// would make state look missing and diverge across nodes. The state is
/// reconstructible from Bitcoin, so the fix is to delete the data directory and
/// resync — surfaced as a clear, loud error rather than silent corruption.
///
/// A fresh DB has `user_version = 0` and no `contract_state` table → it's stamped
/// to the current version after the schema is created. A pre-versioning (legacy)
/// DB also has `user_version = 0` but DOES have the table → that's the
/// incompatible case we reject. Any other non-current version is likewise rejected.
async fn guard_schema_version(conn: &libsql::Connection) -> Result<(), Error> {
    let version: i64 = conn
        .query("PRAGMA user_version;", ())
        .await?
        .next()
        .await?
        .map(|row| row.get::<i64>(0))
        .transpose()?
        .unwrap_or(0);

    if version == SCHEMA_VERSION {
        return Ok(());
    }

    let has_contract_state = conn
        .query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'contract_state';",
            (),
        )
        .await?
        .next()
        .await?
        .is_some();

    // version 0 + no table = a genuinely fresh DB; let it initialize.
    if version == 0 && !has_contract_state {
        return Ok(());
    }

    Err(Error::ConnectionFailed(format!(
        "incompatible database format (on-disk version {version}, expected {SCHEMA_VERSION}): \
         indexed state — including `contract_state.path` encoding — changed in a \
         backward-incompatible way. Delete the data directory and resync from genesis."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsql::Builder;

    async fn mem_conn() -> libsql::Connection {
        Builder::new_local(":memory:")
            .build()
            .await
            .unwrap()
            .connect()
            .unwrap()
    }

    #[tokio::test]
    async fn fresh_db_passes_guard() {
        // user_version 0 + no contract_state table = genuinely fresh.
        assert!(guard_schema_version(&mem_conn().await).await.is_ok());
    }

    #[tokio::test]
    async fn current_version_passes_guard() {
        let conn = mem_conn().await;
        conn.query(&format!("PRAGMA user_version = {SCHEMA_VERSION};"), ())
            .await
            .unwrap();
        assert!(guard_schema_version(&conn).await.is_ok());
    }

    #[tokio::test]
    async fn legacy_unversioned_db_is_rejected() {
        let conn = mem_conn().await;
        // Pre-versioning DB: user_version stays 0 but the table already exists
        // (the old dotted-TEXT format) — must be rejected, not silently mixed.
        conn.execute("CREATE TABLE contract_state (path TEXT)", ())
            .await
            .unwrap();
        let err = guard_schema_version(&conn).await.unwrap_err();
        assert!(format!("{err}").contains("incompatible database format"));
    }

    #[tokio::test]
    async fn unknown_version_is_rejected() {
        let conn = mem_conn().await;
        conn.query("PRAGMA user_version = 999;", ()).await.unwrap();
        assert!(guard_schema_version(&conn).await.is_err());
    }
}
