use anyhow::Result;
use libsql::Connection;

use crate::config::Config;

use super::connection::new_connection;

#[derive(Clone)]
pub struct Writer {
    conn: Connection,
}

impl Writer {
    pub async fn new(config: &Config, filename: &str) -> Result<Self> {
        let conn = new_connection(config, filename).await?;
        Ok(Self { conn })
    }

    pub fn connection(&self) -> Connection {
        self.conn.clone()
    }
}
