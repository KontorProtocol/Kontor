use libsql::{Builder, Connection, Error};

use crate::config::Config;

use super::tables::initialize_database;

pub async fn new_connection(config: &Config, filename: &str) -> Result<Connection, Error> {
    let db = Builder::new_local(config.data_dir.join(filename))
        .build()
        .await?;
    let conn = db.connect()?;
    initialize_database(&conn).await?;
    Ok(conn)
}
