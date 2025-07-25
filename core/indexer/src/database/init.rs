use libsql::Error;
use tokio::fs;

use crate::config::Config;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/macos-arm64/crypto.dylib");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const REGEXP_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/macos-arm64/regexp.dylib");

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/macos-x86/crypto.dylib");
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const REGEXP_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/macos-x86/regexp.dylib");

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/linux-x86/crypto.so");
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const REGEXP_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/linux-x86/regexp.so");

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/linux-arm64/crypto.so");
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const REGEXP_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/linux-arm64/regexp.so");

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/windows-x64/crypto.dll");
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const REGEXP_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/windows-x64/regexp.dll");

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
        conn.load_extension(p, None)?;
    }
    Ok(())
}
