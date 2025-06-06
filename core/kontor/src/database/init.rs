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
    ";

pub const CREATE_CONTRACT_STATE_TRIGGER: &str = "
    CREATE TRIGGER IF NOT EXISTS trigger_checkpoint_on_contract_state_insert
    AFTER INSERT ON contract_state
    BEGIN
        -- Insert a new checkpoint with the calculated hash
        INSERT INTO checkpoints (id, height, hash)
        VALUES (
            -- Determine the ID
            CASE
                -- If no checkpoints exist, use ID 1
                WHEN NOT EXISTS(SELECT 1 FROM checkpoints) THEN 1

                -- If we've reached a new interval, increment the ID
                WHEN (NEW.height / 50) > ((SELECT height FROM checkpoints WHERE id = (SELECT MAX(id) FROM checkpoints)) / 50) THEN
                    (SELECT MAX(id) FROM checkpoints) + 1

                -- Otherwise, use the same ID as the latest checkpoint
                ELSE
                    (SELECT MAX(id) FROM checkpoints)
            END,

            NEW.height,
            (
                WITH row_hash AS (
                    SELECT hex(crypto_sha256(
                        concat(
                            NEW.contract_id,
                            NEW.path,
                            NEW.value,
                            NEW.deleted
                        )
                    )) AS hash
                )
                SELECT
                    CASE
                        WHEN EXISTS(SELECT 1 FROM checkpoints) THEN
                            hex(crypto_sha256(
                                concat(
                                    (SELECT hash FROM row_hash),
                                    (SELECT hash FROM checkpoints WHERE id = (SELECT MAX(id) FROM checkpoints))
                                )
                            ))
                        ELSE
                            (SELECT hash FROM row_hash)
                    END
            )
        )
        ON CONFLICT(id) DO UPDATE SET
            height = NEW.height,
            hash = excluded.hash;
    END;
";

pub async fn initialize_database(config: &Config, conn: &libsql::Connection) -> Result<(), Error> {
    conn.query("PRAGMA foreign_keys = ON;", ()).await?;
    conn.execute(CREATE_BLOCKS_TABLE, ()).await?;
    conn.execute(CREATE_CHECKPOINTS_TABLE, ()).await?;
    conn.execute(CREATE_TRANSACTIONS_TABLE, ()).await?;
    conn.execute(CREATE_CONTRACT_STATE_TABLE, ()).await?;
    conn.execute(CREATE_CONTRACT_STATE_INDEX, ()).await?;
    conn.execute(CREATE_CONTRACT_STATE_TRIGGER, ()).await?;
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
