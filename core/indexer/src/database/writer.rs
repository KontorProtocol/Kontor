use anyhow::Result;
use libsql::Connection;

use crate::config::Config;

use super::{connection::new_connection, init::initialize_database};

#[derive(Clone)]
pub struct Writer {
    conn: Connection,
}

impl Writer {
    pub async fn new(config: &Config, filename: &str) -> Result<Self> {
        let conn = new_connection(config, filename).await?;
        Ok(Self { conn })
    }

    pub async fn new_in_memory(config: &Config) -> Result<Self> {
        let db = libsql::Builder::new_local(":memory:")
            .build()
            .await
            .unwrap();
        let conn = db.connect()?;
        initialize_database(config, &conn).await?;
        Ok(Self { conn })
    }

    pub fn connection(&self) -> Connection {
        self.conn.clone()
    }
}
