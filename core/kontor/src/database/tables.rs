pub const CREATE_BLOCKS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS blocks (
        height INTEGER PRIMARY KEY,
        hash TEXT NOT NULL
    )";

pub async fn initialize_database(conn: &libsql::Connection) -> Result<(), libsql::Error> {
    conn.execute(CREATE_BLOCKS_TABLE, ()).await?;
    conn.query("PRAGMA journal_mode = WAL;", ()).await?;
    conn.query("PRAGMA synchronous = NORMAL;", ()).await?;
    Ok(())
}
