use libsql::Error;
use tokio::fs;

use crate::config::Config;

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

pub async fn initialize_database(config: &Config, conn: &libsql::Connection) -> Result<(), Error> {
    conn.query("PRAGMA foreign_keys = ON;", ()).await?;
    conn.execute_batch(CREATE_SCHEMA).await?;
    conn.execute(CREATE_CONTRACT_STATE_TRIGGER, ()).await?;
    conn.query("PRAGMA journal_mode = WAL;", ()).await?;
    conn.query("PRAGMA synchronous = NORMAL;", ()).await?;
    conn.load_extension_enable()?;
    for (name, bytes) in [("crypto", CRYPTO_LIB), ("regexp", REGEXP_LIB)] {
        let p = config.data_dir.join(format!("{}.{}", name, LIB_FILE_EXT));
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
        let extension_path = config.data_dir.join(name);
        conn.load_extension(extension_path, None)?;
    }
    Ok(())
}
