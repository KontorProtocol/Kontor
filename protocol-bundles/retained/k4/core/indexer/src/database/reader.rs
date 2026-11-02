use std::path::Path;

use anyhow::{Context, Result};
use deadpool::managed::{Object, Pool};

use super::pool::{Manager, new_pool};

#[derive(Clone, Debug)]
pub struct Reader {
    pool: Pool<Manager>,
}

impl Reader {
    pub async fn new(data_dir: &Path, filename: &str) -> Result<Self> {
        let pool = new_pool(data_dir, filename).await?;
        Ok(Self { pool })
    }

    pub async fn connection(&self) -> Result<Object<Manager>> {
        self.pool
            .get()
            .await
            .context("Failed to get connection for database reader pool")
    }
}
