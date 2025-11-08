use std::path::Path;

use libsql::{Builder, Connection, Error};

use super::init::initialize_database;

pub async fn new_connection(data_dir: &Path, filename: &str) -> Result<Connection, Error> {
    let db = Builder::new_local(data_dir.join(filename)).build().await?;
    let conn = db.connect()?;
    initialize_database(data_dir, &conn).await?;
    Ok(conn)
}
