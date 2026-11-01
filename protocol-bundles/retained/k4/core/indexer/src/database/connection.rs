use std::path::Path;

use libsql::{Builder, Connection, Error};

use super::init::initialize_database;

pub async fn new_connection(data_dir: &Path, filename: &str) -> Result<Connection, Error> {
    let db = Builder::new_local(data_dir.join(filename)).build().await?;
    let conn = db.connect()?;
    initialize_database(data_dir, &conn).await?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards against silently dropping the `busy_timeout` PRAGMA again (it was once
    // reverted on the false premise that libsql sets a default — it does not; a raw
    // connection reports 0). Without a non-zero timeout, transient WAL lock
    // contention returns `database is locked` immediately and the reactor exits.
    #[tokio::test]
    async fn new_connection_sets_busy_timeout() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::new()?;
        let conn = new_connection(dir.path(), "bt.db").await?;
        let mut rows = conn.query("PRAGMA busy_timeout", ()).await?;
        let val: i64 = rows.next().await?.expect("PRAGMA returns a row").get(0)?;
        assert_eq!(
            val, 5000,
            "new_connection must set busy_timeout; libsql defaults to 0"
        );
        Ok(())
    }
}
