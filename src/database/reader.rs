use std::path::Path;

use anyhow::{Context, Result};
use deadpool::managed::{Object, Pool};

use super::pool::{Manager, new_pool};

#[derive(Clone)]
pub struct Reader {
    pool: Pool<Manager>,
}

impl Reader {
    pub async fn new(path: &Path) -> Result<Self> {
        let pool = new_pool(path).await?;
        Ok(Self { pool })
    }

    pub async fn connection(&self) -> Result<Object<Manager>> {
        self.pool
            .get()
            .await
            .context("Failed to get connection for database reader pool")
    }
}
