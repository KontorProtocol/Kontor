pub const CREATE_BLOCKS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS blocks (
        height INTEGER PRIMARY KEY,
        hash TEXT NOT NULL
    )";         // autoincrement id?


pub const CREATE_CHECKPOINTS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS checkpoints (
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

pub async fn initialize_database(conn: &libsql::Connection) -> Result<(), libsql::Error> {
    conn.query("PRAGMA foreign_keys = ON;", ()).await?;
    conn.execute(CREATE_BLOCKS_TABLE, ()).await?;
    conn.execute(CREATE_CHECKPOINTS_TABLE, ()).await?;
    conn.execute(CREATE_TRANSACTIONS_TABLE, ()).await?;
    conn.execute(CREATE_CONTRACT_STATE_TABLE, ()).await?;
    conn.execute(CREATE_CONTRACT_STATE_INDEX, ()).await?;
    conn.query("PRAGMA journal_mode = WAL;", ()).await?;
    conn.query("PRAGMA synchronous = NORMAL;", ()).await?;
    Ok(())
}
