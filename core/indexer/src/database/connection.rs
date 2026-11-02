use std::path::Path;

use libsql::{Builder, Connection, Error, OpenFlags};

use super::init::{initialize_database, load_extensions};

pub async fn new_connection(data_dir: &Path, filename: &str) -> Result<Connection, Error> {
    let db = Builder::new_local(data_dir.join(filename)).build().await?;
    let conn = db.connect()?;
    initialize_database(data_dir, &conn).await?;
    Ok(conn)
}

pub(crate) async fn new_read_only_connection(
    data_dir: &Path,
    filename: &str,
) -> Result<Connection, Error> {
    // Pool growth must not rerun schema installation and invalidate a canonical
    // writer's deferred transaction snapshot. The writer initializes the database.
    let db = Builder::new_local(data_dir.join(filename))
        .flags(OpenFlags::SQLITE_OPEN_READ_ONLY)
        .build()
        .await?;
    let conn = db.connect()?;
    conn.execute_batch(
        "PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON; PRAGMA query_only = ON;",
    )
    .await?;
    load_extensions(data_dir, &conn).await?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use crate::database::Reader;

    use super::*;

    #[tokio::test]
    async fn opening_reader_preserves_writer_snapshot() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::new()?;
        let writer = new_connection(dir.path(), "reader.db").await?;
        writer
            .execute("CREATE TABLE reader_probe (value INTEGER)", ())
            .await?;
        writer.execute("BEGIN", ()).await?;
        let mut rows = writer
            .query("SELECT count(*) FROM reader_probe", ())
            .await?;
        assert_eq!(rows.next().await?.unwrap().get::<i64>(0)?, 0);
        drop(rows);

        let pool = Reader::new(dir.path(), "reader.db").await?;
        let reader = pool.connection().await?;
        writer
            .execute("INSERT INTO reader_probe VALUES (1)", ())
            .await?;
        writer.execute("COMMIT", ()).await?;
        let mut rows = reader
            .query("SELECT count(*) FROM reader_probe", ())
            .await?;
        assert_eq!(rows.next().await?.unwrap().get::<i64>(0)?, 1);
        drop(rows);
        assert!(
            reader
                .execute("INSERT INTO reader_probe VALUES (2)", ())
                .await
                .is_err()
        );
        let mut rows = reader
            .query("SELECT length(crypto_sha256('reader'))", ())
            .await?;
        assert_eq!(rows.next().await?.unwrap().get::<i64>(0)?, 32);
        Ok(())
    }

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
