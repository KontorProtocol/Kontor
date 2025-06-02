use libsql::Error;
use tokio::fs;

use crate::config::Config;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/macos-arm64/crypto.dylib");
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/macos-x86/crypto.dylib");
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/linux-x86/crypto.so");
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const CRYPTO_LIB: &[u8] = include_bytes!("../../sqlean-0.27.2/linux-arm64/crypto.so");

#[cfg(target_os = "macos")]
const LIB_FILE_EXT: &str = "dylib";
#[cfg(target_os = "linux")]
const LIB_FILE_EXT: &str = "so";

pub const CREATE_BLOCKS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS blocks (
        height INTEGER PRIMARY KEY,
        hash TEXT NOT NULL
    )";

pub const CREATE_CHECKPOINTS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS checkpoints (
        id INTEGER PRIMARY KEY,
        height INTEGER UNIQUE,
        hash TEXT NOT NULL UNIQUE,
        FOREIGN KEY (height) REFERENCES blocks(height) ON DELETE CASCADE
    )";

pub const CREATE_TRANSACTIONS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY,
        tx_index INTEGER NOT NULL,
        txid TEXT NOT NULL UNIQUE,
        block_index INTEGER NOT NULL,
        FOREIGN KEY (block_index) REFERENCES blocks(height) ON DELETE CASCADE
    )";

pub const CREATE_CONTRACT_STATE_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS contract_state (
        id INTEGER PRIMARY KEY,
        contract_id TEXT NOT NULL,
        tx_id INTEGER NOT NULL,
        height INTEGER NOT NULL,
        path TEXT NOT NULL,
        value BLOB,
        deleted BOOLEAN NOT NULL DEFAULT 0,

        UNIQUE (contract_id, height, path),
        FOREIGN KEY (height) REFERENCES blocks(height) ON DELETE CASCADE
    )";

pub const CREATE_CONTRACT_STATE_INDEX: &str = "
    CREATE INDEX IF NOT EXISTS idx_contract_state_lookup 
    ON contract_state(contract_id, height, path)
    "; // what type of index??

pub async fn initialize_database(config: &Config, conn: &libsql::Connection) -> Result<(), Error> {
    conn.query("PRAGMA foreign_keys = ON;", ()).await?;
    conn.execute(CREATE_BLOCKS_TABLE, ()).await?;
    conn.execute(CREATE_CHECKPOINTS_TABLE, ()).await?;
    conn.execute(CREATE_TRANSACTIONS_TABLE, ()).await?;
    conn.execute(CREATE_CONTRACT_STATE_TABLE, ()).await?;
    conn.execute(CREATE_CONTRACT_STATE_INDEX, ()).await?;
    conn.query("PRAGMA journal_mode = WAL;", ()).await?;
    conn.query("PRAGMA synchronous = NORMAL;", ()).await?;
    let p = config.data_dir.join(format!("crypto.{}", LIB_FILE_EXT));
    if !fs::try_exists(&p)
        .await
        .map_err(|e| Error::ConnectionFailed(e.to_string()))?
    {
        fs::write(&p, CRYPTO_LIB)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;
    }
    conn.load_extension_enable()?;
    conn.load_extension(p, None)?;
    Ok(())
}
