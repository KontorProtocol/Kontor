use anyhow::Result;
use libsql::Connection;

use crate::config::Config;

use super::{connection::new_connection, init::initialize_database_wo_crypto};

#[derive(Clone)]
pub struct Writer {
    conn: Connection,
}

impl Writer {
    pub async fn new(config: &Config, filename: &str) -> Result<Self> {
        let conn = new_connection(config, filename).await?;
        Ok(Self { conn })
    }

    pub async fn new_in_memory() -> Result<Self> {
        let db = libsql::Builder::new_local(":memory:")
            .build()
            .await
            .unwrap();
        let conn = db.connect()?;
        initialize_database_wo_crypto(&conn).await?;
        Ok(Self { conn })
    }

    pub fn connection(&self) -> Connection {
        self.conn.clone()
    }
}
