use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};

use anyhow::Context;
use deadpool::managed::{self, Pool, RecycleError};
use libsql::{Builder, Error};

use super::tables::initialize_database;

#[derive(Debug)]
pub struct Manager {
    path: String,
    recycle_count: AtomicUsize,
}

impl Manager {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_string_lossy().into_owned(),
            recycle_count: AtomicUsize::new(0),
        }
    }
}

impl managed::Manager for Manager {
    type Type = libsql::Connection;
    type Error = Error;

    async fn create(&self) -> Result<Self::Type, Error> {
        let db = Builder::new_local(&self.path).build().await?;
        let conn = db.connect()?;
        initialize_database(&conn).await?;
        Ok(conn)
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

pub async fn new_pool(path: &Path) -> anyhow::Result<Pool<Manager>> {
    let manager = Manager::new(path);
    Pool::builder(manager)
        .max_size(10)
        .build()
        .context("Failed to build database pool")
}
