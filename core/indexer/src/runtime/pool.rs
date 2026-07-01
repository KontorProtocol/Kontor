use std::path::PathBuf;

use anyhow::Context;
use deadpool::managed::{self, Pool, RecycleError, RecycleResult};
use thiserror::Error;
use tracing::warn;
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
        // THE floor-view flake fix. A view can leave a streaming-iterator resource
        // (e.g. an undrained `Keys` map iterator) in the runtime's resource table; its
        // backing libsql `Rows` stays an ACTIVE STATEMENT while held. In WAL mode a
        // connection cannot advance its read snapshot while it has an active statement
        // (SQLite WAL / SQLDelight #2123), so the NEXT view checked out on this pooled
        // connection reads a STALE, frozen snapshot — silently missing just-committed
        // writes (`/view`, `/signers`). Crucially this does NOT flip `is_autocommit`
        // (it's an implicit statement lock, not a `BEGIN`), so the check below can't
        // see it. Dropping the resource table finalizes those cursors and releases the
        // pin, letting the connection advance to the latest commit on the next read.
        *obj.table.lock().await = wasmtime::component::ResourceTable::new();
        // Then reset any explicit transaction a cancelled view left open (`BEGIN…COMMIT`
        // not reached). `ROLLBACK` errors harmlessly when nothing is open (the normal
        // case), so ignore it and verify the outcome below.
        let _ = obj.storage.rollback_transaction().await;
        // Only hand the connection back if it is provably out of any transaction. If the
        // rollback could not clear it (e.g. a statement still in progress), it is still
        // pinned — discard it so deadpool builds a fresh connection rather than serve
        // stale reads.
        if obj.storage.conn.is_autocommit() {
            Ok(())
        } else {
            warn!("Discarding pooled view connection still in a transaction after rollback");
            Err(RecycleError::Message(
                "pooled view connection could not be reset to a fresh snapshot".into(),
            ))
        }
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
    // fixed system budget — so a too-low view cap can only break views, never
    // affect consensus.
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
        // A directly-built (consensus) Runtime carries the untouched defaults.
        let conn = new_connection(dir.path(), "consensus.db").await?;
        let consensus =
            Runtime::new(ComponentCache::new(), Storage::builder().conn(conn).build()).await?;

        // The view cap moved on the pooled runtime...
        assert_eq!(
            pooled.view_gas_limit, custom,
            "pooled /view runtime must use the operator-configured view cap"
        );
        // ...but the fixed system budget did NOT — it matches a directly-built
        // runtime even on the pool runtime.
        assert_eq!(
            pooled.gas_limit_for_non_procs, consensus.gas_limit_for_non_procs,
            "the view cap must not touch the system core-call budget"
        );
        // And the consensus runtime's view field stays at the default.
        assert_eq!(consensus.view_gas_limit, DEFAULT_VIEW_GAS_LIMIT);
        Ok(())
    }

    // A view runtime that leaks an open transaction (its task dropped before commit)
    // must be rolled back to autocommit on recycle so the next checkout reads a fresh
    // snapshot — never the leaked connection's pinned (stale) snapshot. The clean case
    // must NOT be discarded.
    #[tokio::test]
    async fn recycle_resets_leaked_transaction_before_reuse() -> anyhow::Result<()> {
        use deadpool::managed::{Manager as _, Metrics};

        let dir = TempDir::new()?;
        let manager = Manager::new(
            dir.path().to_path_buf(),
            "recycle.db".into(),
            bitcoin::Network::Regtest,
            DEFAULT_VIEW_GAS_LIMIT,
        )?;

        // A freshly created connection is clean — recycle keeps it.
        let mut runtime = manager.create().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        assert!(runtime.storage.conn.is_autocommit());
        manager
            .recycle(&mut runtime, &Metrics::default())
            .await
            .map_err(|e| anyhow::anyhow!("clean connection must not be discarded: {e:?}"))?;

        // Simulate a view that opened its BEGIN but never reached commit/rollback.
        runtime.storage.savepoint().await?;
        assert!(
            !runtime.storage.conn.is_autocommit(),
            "savepoint opens a transaction"
        );

        // Recycle must restore autocommit (fresh snapshot on next read) and accept it.
        manager
            .recycle(&mut runtime, &Metrics::default())
            .await
            .map_err(|e| anyhow::anyhow!("recycle should reset, not discard: {e:?}"))?;
        assert!(
            runtime.storage.conn.is_autocommit(),
            "recycle must roll the leaked transaction back to autocommit"
        );
        Ok(())
    }

    // End-to-end proof of the floor-view fix: a leaked `Keys` cursor in a pooled
    // runtime's resource table pins its connection to a stale WAL snapshot (a fresh
    // read misses a concurrent commit), and `recycle` clearing the table drops the
    // cursor and releases the pin so the next read sees the latest commit.
    #[tokio::test]
    async fn recycle_clears_leaked_cursor_that_pinned_the_snapshot() -> anyhow::Result<()> {
        use crate::database::queries::{footprint_cache_get, footprint_cache_set, insert_block};
        use crate::runtime::wit::resources::Keys;
        use crate::test_utils::new_mock_block_hash;
        use deadpool::managed::{Manager as _, Metrics};
        use futures_util::StreamExt;
        use indexer_types::BlockRow;

        let dir = TempDir::new()?;
        let manager = Manager::new(
            dir.path().to_path_buf(),
            "leak.db".into(),
            bitcoin::Network::Regtest,
            DEFAULT_VIEW_GAS_LIMIT,
        )?;
        let mut rt = manager.create().await.map_err(|e| anyhow::anyhow!("{e}"))?;

        // Seed via a separate writer connection: a block (FK), contract_state rows for
        // the cursor to stream, and a footprint row to read back.
        let writer = new_connection(dir.path(), "leak.db").await?;
        let signer = 1u64;
        insert_block(
            &writer,
            BlockRow::builder()
                .height(1)
                .hash(new_mock_block_hash(1))
                .build(),
        )
        .await?;
        for i in 0..50i64 {
            writer
                .execute(
                    "INSERT INTO contract_state (contract_id, height, tx_id, size, path, value, deleted) \
                     VALUES (1, 1, NULL, 1, ?1, ?2, 0)",
                    libsql::params![vec![i as u8], vec![1u8]],
                )
                .await?;
        }
        footprint_cache_set(&writer, signer, Some(1)).await?;

        // Leak a Keys cursor into the pooled runtime's table (read one row → ACTIVE
        // statement, never drained), exactly as a partially-consumed `map.keys()` view.
        let mut stream = Box::pin(rt.storage.keys(1, vec![], None, None).await?);
        let _ = stream.next().await;
        rt.table.lock().await.push(Keys { stream })?;

        // The writer commits a newer footprint; the pinned pooled connection reads stale.
        footprint_cache_set(&writer, signer, Some(2)).await?;
        assert_eq!(
            footprint_cache_get(&rt.storage.conn, signer).await?,
            Some(1),
            "a leaked cursor must pin the pooled connection to the stale snapshot"
        );
        assert!(
            rt.storage.conn.is_autocommit(),
            "the pin does NOT flip autocommit — the recycle check alone is blind to it"
        );

        // recycle clears the table → drops the leaked cursor → releases the pin.
        manager
            .recycle(&mut rt, &Metrics::default())
            .await
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        assert_eq!(
            footprint_cache_get(&rt.storage.conn, signer).await?,
            Some(2),
            "after recycle drops the leaked cursor, the connection reads the latest commit"
        );
        Ok(())
    }

    // Faithful reproduction of the floor-view flake at the pool level: a real runtime
    // pool (checkout/recycle + read-only-runtime savepoint reads), a reactor-style
    // writer committing via explicit transactions, and heavy concurrent pool load.
    // INVARIANT: after the writer's COMMIT returns, a freshly-checked-out pooled view
    // MUST see >= the just-committed value. A view that lags a committed write IS the
    // production bug (a `/view` read missing a confirmed write).
    #[tokio::test]
    async fn runtime_pool_view_never_lags_committed_write_under_load() -> anyhow::Result<()> {
        use crate::database::queries::{footprint_cache_get, footprint_cache_set};
        use std::sync::Arc;

        let dir = TempDir::new()?;
        let path = dir.path().to_path_buf();
        let writer = new_connection(&path, "stress.db").await?;
        let pool = Arc::new(
            super::new(
                path.clone(),
                "stress.db".into(),
                bitcoin::Network::Regtest,
                DEFAULT_VIEW_GAS_LIMIT,
            )
            .await?,
        );
        let signer = 1u64;
        footprint_cache_set(&writer, signer, Some(1)).await?;

        // Background load: many tasks hammer pool checkout/recycle + savepoint-wrapped
        // reads, plus a second writer churning the WAL — the concurrency the bug needs.
        let mut bg = Vec::new();
        for _ in 0..16 {
            let p = pool.clone();
            bg.push(tokio::spawn(async move {
                loop {
                    if let Ok(rt) = p.get().await {
                        let _ = rt.storage.savepoint().await;
                        let _ = footprint_cache_get(&rt.storage.conn, signer).await;
                        let _ = rt.storage.commit().await;
                    }
                }
            }));
        }

        for v in 2..=6000u64 {
            writer.execute("BEGIN", ()).await?;
            footprint_cache_set(&writer, signer, Some(v)).await?;
            writer.execute("COMMIT", ()).await?;

            let rt = pool.get().await.map_err(|e| anyhow::anyhow!("{e:?}"))?;
            rt.storage.savepoint().await?;
            let seen = footprint_cache_get(&rt.storage.conn, signer)
                .await?
                .unwrap_or(0);
            rt.storage.commit().await?;
            assert!(
                seen >= v,
                "runtime pool view LAGGED a committed write: committed {v}, pooled view saw {seen}"
            );
        }
        for h in bg {
            h.abort();
        }
        Ok(())
    }
}
