use std::path::PathBuf;

use anyhow::Context;
use deadpool::managed::{self, Pool, RecycleResult};
use thiserror::Error;
use wasmtime::Engine;

use crate::{
    database::connection::new_connection,
    runtime::{ComponentCache, Runtime},
};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("Failed to create runtime: {0}")]
    CreationFailed(String),
    #[error("Failed to create database connection: {0}")]
    DatabaseConnection(String),
}

pub struct Manager {
    data_dir: PathBuf,
    filename: String,
    engine: Engine,
    component_cache: ComponentCache,
}

impl Manager {
    pub fn new(data_dir: PathBuf, filename: String) -> anyhow::Result<Self> {
        Ok(Self {
            data_dir,
            filename,
            engine: Runtime::new_engine()?,
            component_cache: ComponentCache::new(),
        })
    }
}

impl managed::Manager for Manager {
    type Type = Runtime;
    type Error = RuntimeError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        Runtime::new_read_only(
            new_connection(&self.data_dir, &self.filename)
                .await
                .map_err(|e| RuntimeError::DatabaseConnection(e.to_string()))?,
            self.engine.clone(),
            self.component_cache.clone(),
        )
        .await
        .map_err(|e| RuntimeError::CreationFailed(e.to_string()))
    }

    async fn recycle(
        &self,
        _obj: &mut Self::Type,
        _metrics: &deadpool::managed::Metrics,
    ) -> RecycleResult<Self::Error> {
        Ok(())
    }
}

pub async fn new(data_dir: PathBuf, filename: String) -> anyhow::Result<Pool<Manager>> {
    Pool::builder(Manager::new(data_dir, filename)?)
        .max_size(std::thread::available_parallelism()?.into())
        .build()
        .context("Failed to build runtime pool")
}
