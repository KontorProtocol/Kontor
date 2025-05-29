use std::path::Path;

use anyhow::Result;
use libsql::{Builder, Connection};

use super::tables::initialize_database;

pub async fn new_connection(path: &Path) -> Result<Connection> {
    let db = Builder::new_local(path).build().await?;
    let conn = db.connect()?;
    initialize_database(&conn).await?;
    Ok(conn)
}
