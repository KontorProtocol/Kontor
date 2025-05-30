use anyhow::{Context, Result};
use deadpool::managed::{Object, Pool};

use crate::config::Config;

use super::pool::{Manager, new_pool};

#[derive(Clone)]
pub struct Reader {
    pool: Pool<Manager>,
}

impl Reader {
    pub async fn new(config: Config, filename: &str) -> Result<Self> {
        let pool = new_pool(config, filename).await?;
        Ok(Self { pool })
    }

    pub async fn connection(&self) -> Result<Object<Manager>> {
        self.pool
            .get()
            .await
            .context("Failed to get connection for database reader pool")
    }
}
