use std::path::Path;

use turso::{Builder, Connection, Error};

use super::init::initialize_database;

pub async fn new_connection(data_dir: &Path, filename: &str) -> Result<Connection, Error> {
    let path = data_dir.join(filename);
    let db = Builder::new_local(&path.to_string_lossy()).build().await?;
    let conn = db.connect()?;
    initialize_database(data_dir, &conn).await?;
    Ok(conn)
}
