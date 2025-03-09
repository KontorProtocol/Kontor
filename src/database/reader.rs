use std::path::Path;

use anyhow::{Context, Result};
use bitcoin::BlockHash;
use deadpool::managed::{Object, Pool};
use libsql::{de::from_row, params};

use super::{
    pool::{Manager, new_pool},
    types::BlockRow,
};

#[derive(Clone)]
pub struct Reader {
    pool: Pool<Manager>,
}

impl Reader {
    pub async fn new(path: &Path) -> Result<Self> {
        let pool = new_pool(path).await?;
        Ok(Self { pool })
    }

    async fn get_connection(&self) -> Result<Object<Manager>> {
        self.pool
            .get()
            .await
            .context("Failed to get connection for database reader pool")
    }

    pub async fn get_block_latest(&self) -> Result<Option<BlockRow>> {
        let conn = self.get_connection().await?;
        let mut rows = conn
            .query(
                "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
                params![],
            )
            .await?;
        Ok(match rows.next().await? {
            Some(row) => Some(from_row::<BlockRow>(&row)?),
            None => None,
        })
    }

    pub async fn get_block_at_height(&self, height: u64) -> Result<Option<BlockRow>> {
        let conn = self.get_connection().await?;
        let mut rows = conn
            .query(
                "SELECT height, hash FROM blocks WHERE height = ?",
                params![height],
            )
            .await?;
        Ok(match rows.next().await? {
            Some(row) => Some(from_row::<BlockRow>(&row)?),
            None => None,
        })
    }

    pub async fn get_block_with_hash(&self, hash: &BlockHash) -> Result<Option<BlockRow>> {
        let conn = self.get_connection().await?;
        let mut rows = conn
            .query(
                "SELECT height, hash FROM blocks WHERE hash = ?",
                params![hash.to_string()],
            )
            .await?;
        Ok(match rows.next().await? {
            Some(row) => Some(from_row::<BlockRow>(&row)?),
            None => None,
        })
    }
}
