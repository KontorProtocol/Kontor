use std::path::PathBuf;

use anyhow::Context;
use deadpool::managed::{self, Pool, RecycleResult};
use thiserror::Error;
use wasmtime::Engine;

use crate::{
    database::connection::new_connection,
    runtime::{ComponentCache, Linkers, Runtime},
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
    linkers: Linkers,
    component_cache: ComponentCache,
    network: bitcoin::Network,
}

impl Manager {
    pub fn new(
        data_dir: PathBuf,
        filename: String,
        network: bitcoin::Network,
    ) -> anyhow::Result<Self> {
        let engine = Runtime::new_engine()?;
        let linkers = Runtime::new_linkers(&engine)?;
        Ok(Self {
            data_dir,
            filename,
            engine,
            linkers,
            component_cache: ComponentCache::new(),
            network,
        })
    }
}

impl managed::Manager for Manager {
    type Type = Runtime;
    type Error = RuntimeError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let conn = new_connection(&self.data_dir, &self.filename)
            .await
            .map_err(|e| RuntimeError::DatabaseConnection(e.to_string()))?;
        // `new_read_only` pins the connection `query_only` — this pool serves only
        // reads (the `/contracts` view endpoint and signer lookups), and that keeps a
        // view from upgrading its snapshot to a write and racing the reactor writer.
        let mut runtime = Runtime::new_read_only(
            self.engine.clone(),
            self.linkers.clone(),
            self.component_cache.clone(),
            conn,
        )
        .await
        .map_err(|e| RuntimeError::CreationFailed(e.to_string()))?;
        // Chain-identity constant, surfaced to contracts via `network()`.
        runtime.network = self.network;
        Ok(runtime)
    }

    async fn recycle(
        &self,
        _obj: &mut Self::Type,
        _metrics: &deadpool::managed::Metrics,
    ) -> RecycleResult<Self::Error> {
        Ok(())
    }
}

pub async fn new(
    data_dir: PathBuf,
    filename: String,
    network: bitcoin::Network,
) -> anyhow::Result<Pool<Manager>> {
    Pool::builder(Manager::new(data_dir, filename, network)?)
        .max_size(std::thread::available_parallelism()?.into())
        .build()
        .context("Failed to build runtime pool")
}
