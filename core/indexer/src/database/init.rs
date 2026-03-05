use std::path::Path;

use libsql::Error;
use libsql::params;
use tokio::fs;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.28.0/macos-arm64/crypto.dylib");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const REGEXP_LIB: &[u8] = include_bytes!("../../sqlean-0.28.0/macos-arm64/regexp.dylib");

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.28.0/macos-x64/crypto.dylib");
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const REGEXP_LIB: &[u8] = include_bytes!("../../sqlean-0.28.0/macos-x64/regexp.dylib");

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.28.0/linux-x64/crypto.so");
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const REGEXP_LIB: &[u8] = include_bytes!("../../sqlean-0.28.0/linux-x64/regexp.so");

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.28.0/linux-arm64/crypto.so");
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const REGEXP_LIB: &[u8] = include_bytes!("../../sqlean-0.28.0/linux-arm64/regexp.so");

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.28.0/windows-x64/crypto.dll");
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const REGEXP_LIB: &[u8] = include_bytes!("../../sqlean-0.28.0/windows-x64/regexp.dll");

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
    conn.execute_batch(CREATE_SCHEMA).await?;
    ensure_file_metadata_ledger_index(conn).await?;
    conn.execute(CREATE_CONTRACT_STATE_TRIGGER, ()).await?;
    conn.query("PRAGMA journal_mode = WAL;", ()).await?;
    conn.query("PRAGMA synchronous = NORMAL;", ()).await?;
    conn.load_extension_enable()?;
    for (name, bytes) in [("crypto", CRYPTO_LIB), ("regexp", REGEXP_LIB)] {
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

async fn ensure_file_metadata_ledger_index(conn: &libsql::Connection) -> Result<(), Error> {
    // Detect whether `file_metadata` exists and whether it already has a `ledger_index` column.
    let mut pragma = conn.query("PRAGMA table_info(file_metadata);", ()).await?;
    let mut saw_any = false;
    let mut has_ledger_index = false;
    while let Some(row) = pragma.next().await? {
        saw_any = true;
        let name: String = row.get(1)?;
        if name == "ledger_index" {
            has_ledger_index = true;
            break;
        }
    }

    // Older DBs may not have the filestorage tables at all.
    if !saw_any {
        return Ok(());
    }

    if !has_ledger_index {
        // SQLite can't add a NOT NULL column without a default; add it nullable and backfill.
        conn.execute(
            "ALTER TABLE file_metadata ADD COLUMN ledger_index INTEGER;",
            (),
        )
        .await?;
    }

    // Backfill any NULL ledger_index values deterministically.
    let null_count: i64 = conn
        .query(
            "SELECT COUNT(*) FROM file_metadata WHERE ledger_index IS NULL",
            (),
        )
        .await?
        .next()
        .await?
        .map(|r| r.get(0))
        .transpose()?
        .unwrap_or(0);

    if null_count > 0 {
        // Prefer a single-statement backfill (fast). Fall back to a row-by-row update if the
        // bundled SQLite does not support window functions.
        let backfill = r#"
WITH ordered AS (
  SELECT
    id,
    (ROW_NUMBER() OVER (ORDER BY height ASC, id ASC) - 1) AS idx
  FROM file_metadata
)
UPDATE file_metadata
SET ledger_index = (SELECT idx FROM ordered WHERE ordered.id = file_metadata.id)
WHERE ledger_index IS NULL;
"#;
        if let Err(_err) = conn.execute_batch(backfill).await {
            let mut rows = conn
                .query(
                    "SELECT id FROM file_metadata ORDER BY height ASC, id ASC",
                    (),
                )
                .await?;
            let mut idx: i64 = 0;
            while let Some(row) = rows.next().await? {
                let id: i64 = row.get(0)?;
                conn.execute(
                    "UPDATE file_metadata SET ledger_index = ? WHERE id = ?",
                    params![idx, id],
                )
                .await?;
                idx += 1;
            }
        }
    }

    // Enforce uniqueness for upgraded DBs (new DBs get this from schema.sql).
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_file_metadata_ledger_index_unique ON file_metadata (ledger_index);",
        (),
    )
    .await?;

    Ok(())
}
