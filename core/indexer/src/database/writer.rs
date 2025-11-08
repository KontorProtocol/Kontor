use std::path::Path;

use anyhow::Result;
use libsql::Connection;

use super::connection::new_connection;

#[derive(Clone)]
pub struct Writer {
    conn: Connection,
}

impl Writer {
    pub async fn new(data_dir: &Path, filename: &str) -> Result<Self> {
        let conn = new_connection(data_dir, filename).await?;
        Ok(Self { conn })
    }

    pub fn connection(&self) -> Connection {
        self.conn.clone()
    }
}
