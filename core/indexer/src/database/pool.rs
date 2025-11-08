use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use anyhow::{Context, Result};
use deadpool::managed::{self, Pool, RecycleError};
use libsql::Error;

use super::connection::new_connection;

#[derive(Debug)]
pub struct Manager {
    data_dir: PathBuf,
    filename: String,
    recycle_count: AtomicUsize,
}

impl Manager {
    pub fn new(data_dir: PathBuf, filename: String) -> Self {
        Self {
            data_dir,
            filename,
            recycle_count: AtomicUsize::new(0),
        }
    }
}

impl managed::Manager for Manager {
    type Type = libsql::Connection;
    type Error = Error;

    async fn create(&self) -> Result<Self::Type, Error> {
        new_connection(&self.data_dir, &self.filename).await
    }

    async fn recycle(
        &self,
        conn: &mut Self::Type,
        _: &managed::Metrics,
    ) -> managed::RecycleResult<Error> {
        let recycle_count = self.recycle_count.fetch_add(1, Ordering::Relaxed) as u64;
        let n: u64 = conn
            .query("SELECT $1", libsql::params![recycle_count])
            .await
            .map_err(|e| RecycleError::Message(format!("{}", e).into()))?
            .next()
            .await
            .map_err(|e| RecycleError::Message(format!("{}", e).into()))?
            .ok_or_else(|| RecycleError::Message("No rows returned".into()))?
            .get(0)
            .map_err(|e| RecycleError::Message(format!("{}", e).into()))?;

        if n == recycle_count {
            Ok(())
        } else {
            Err(RecycleError::Message("Recycle count mismatch".into()))
        }
    }
}

pub async fn new_pool(data_dir: &Path, filename: &str) -> anyhow::Result<Pool<Manager>> {
    let manager = Manager::new(data_dir.to_path_buf(), filename.to_string());
    Pool::builder(manager)
        .max_size(10)
        .build()
        .context("Failed to build database pool")
}
