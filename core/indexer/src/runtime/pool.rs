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
    /// Operator-set per-call gas budget for `/view` reads served by this pool.
    /// Applied to each pooled runtime in `create`; the reactor's consensus runtime
    /// is a separate instance and keeps the fixed consensus limit.
    view_gas_limit: u64,
}

impl Manager {
    pub fn new(
        data_dir: PathBuf,
        filename: String,
        network: bitcoin::Network,
        view_gas_limit: u64,
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
            view_gas_limit,
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
        // Operator-set `/view` budget. Sets ONLY `view_gas_limit` (the read-only view
        // path), never `gas_limit_for_non_procs` (the consensus core-call budget) — so
        // an operator can't starve core calls no matter how low they set this, and it
        // only ever applies to pooled read-only runtimes anyway.
        runtime.view_gas_limit = self.view_gas_limit;
        Ok(runtime)
    }

    async fn recycle(
        &self,
        obj: &mut Self::Type,
        _metrics: &deadpool::managed::Metrics,
    ) -> RecycleResult<Self::Error> {
        // Reset any transaction left open on this connection before it is reused.
        // A view wraps its call in BEGIN…COMMIT; if `execute` returns early without
        // reaching the commit/rollback in `handle_call` (e.g. the spawned call task
        // fails to join), the connection goes back into the pool with an OPEN read
        // transaction — pinning it to a stale WAL snapshot so every later view on it
        // reads pre-commit state forever. Best-effort `ROLLBACK` (+ clearing the
        // savepoint stack) makes every reused connection start from a fresh snapshot.
        // Errors when no transaction is open, which is the normal case — ignore them.
        let _ = obj.storage.rollback_transaction().await;
        Ok(())
    }
}

pub async fn new(
    data_dir: PathBuf,
    filename: String,
    network: bitcoin::Network,
    view_gas_limit: u64,
) -> anyhow::Result<Pool<Manager>> {
    Pool::builder(Manager::new(data_dir, filename, network, view_gas_limit)?)
        .max_size(std::thread::available_parallelism()?.into())
        .build()
        .context("Failed to build runtime pool")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_VIEW_GAS_LIMIT;
    use crate::runtime::Storage;
    use deadpool::managed::Manager as _; // brings the `create` trait method into scope
    use tempfile::TempDir;

    // The operator's view cap sets ONLY `view_gas_limit`, and only on pooled
    // (read-only) runtimes. It must NEVER touch `gas_limit_for_non_procs` — the
    // consensus core-call budget — so a too-low view cap can only break views, never
    // starve core calls / affect consensus.
    #[tokio::test]
    async fn view_cap_is_decoupled_from_core_call_budget() -> anyhow::Result<()> {
        let dir = TempDir::new()?;
        let custom = 9_000_000u64;
        assert_ne!(
            custom, DEFAULT_VIEW_GAS_LIMIT,
            "test needs a non-default cap"
        );

        let pool = Manager::new(
            dir.path().to_path_buf(),
            "view_cap.db".into(),
            bitcoin::Network::Regtest,
            custom,
        )?;
        let pooled = pool.create().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        // The view cap moved...
        assert_eq!(
            pooled.view_gas_limit, custom,
            "pooled /view runtime must use the operator-configured view cap"
        );
        // ...but the consensus core-call budget did NOT, even on the pool runtime.
        assert_eq!(
            pooled.gas_limit_for_non_procs, DEFAULT_VIEW_GAS_LIMIT,
            "the view cap must not touch the core-call budget"
        );

        // Consensus path: a directly-built Runtime is untouched on both fields.
        let conn = new_connection(dir.path(), "consensus.db").await?;
        let consensus =
            Runtime::new(ComponentCache::new(), Storage::builder().conn(conn).build()).await?;
        assert_eq!(consensus.gas_limit_for_non_procs, DEFAULT_VIEW_GAS_LIMIT);
        assert_eq!(consensus.view_gas_limit, DEFAULT_VIEW_GAS_LIMIT);
        Ok(())
    }
}
