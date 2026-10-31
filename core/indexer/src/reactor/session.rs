#[cfg(test)]
use std::future::Future;

use anyhow::{Result, ensure};

use super::Reactor;
use super::executor::Executor;
use crate::database::queries::prune_contract_state;
use crate::protocol::coordinator::linked;
use crate::protocol::coordinator::selection::{ApplicationPosition, ExecutionSelection};
use crate::runtime::ownership::LinkedCanonicalRootLease;
use crate::runtime::ownership::adapter::HostFailure;

#[cfg(test)]
use crate::protocol::coordinator::linked::{PreparedBlock, TransactionRecognizer};
#[cfg(test)]
use crate::runtime::Runtime;
#[cfg(test)]
use crate::runtime::bundle_session::BundleSession;
#[cfg(test)]
use crate::runtime::pool::LinkedSession;
#[cfg(test)]
use tokio::sync::MutexGuard;

impl<E: Executor> Reactor<E> {
    pub(super) async fn begin_unit(
        &mut self,
        selection: &ExecutionSelection,
        simulation: bool,
    ) -> Result<LinkedCanonicalRootLease> {
        linked::begin_canonical_unit(
            &self.owner_service,
            &self.session,
            selection,
            self.network,
            simulation,
        )
        .await
    }

    pub(super) async fn finish_unit<T>(
        &mut self,
        lease: LinkedCanonicalRootLease,
        result: Result<T>,
        commit: bool,
    ) -> Result<T> {
        linked::finish_canonical_unit(lease, result, commit).await
    }

    pub(super) async fn maintain_executor(&mut self, rollback_height: Option<u64>) -> Result<()> {
        let selection = self
            .select_executor(ApplicationPosition::Maintenance { rollback_height })
            .await?;
        let lease = self.begin_unit(&selection, false).await?;
        let result = (self.session.executor.operations.maintenance)(
            self.session.executor.owner.clone(),
            selection.envelope(),
        )
        .await
        .map_err(HostFailure::from)
        .map_err(Into::into);
        self.finish_unit(lease, result, true).await
    }

    pub(super) async fn prune_state(&mut self, previous: u64, height: u64) -> Result<u64> {
        let conn = &self.session.conn;
        ensure!(conn.is_autocommit(), "pruning requires an idle writer");
        conn.execute("BEGIN TRANSACTION", ()).await?;
        match prune_contract_state(conn, previous, height).await {
            Ok(deleted) => {
                conn.execute("COMMIT", ()).await?;
                Ok(deleted)
            }
            Err(error) => {
                conn.execute("ROLLBACK", ()).await?;
                Err(error.into())
            }
        }
    }

    pub(super) async fn freelist_count(&mut self) -> Result<i64> {
        let mut rows = self
            .session
            .conn
            .query("PRAGMA freelist_count;", ())
            .await?;
        Ok(match rows.next().await? {
            Some(row) => row.get(0)?,
            None => 0,
        })
    }

    pub(super) async fn vacuum(&mut self, pages: i64) -> Result<()> {
        self.session
            .conn
            .query(&format!("PRAGMA incremental_vacuum({pages});"), ())
            .await?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn test_runtime(&self) -> impl Future<Output = MutexGuard<'_, Runtime>> + Send {
        self.session
            .executor
            .owner
            .downcast_ref::<BundleSession>()
            .expect("test reactor has an in-tree retained session")
            .test_runtime()
    }

    #[cfg(test)]
    pub(super) fn replace_test_runtime(&mut self, runtime: Runtime) {
        assert!(self.session.conn.is_autocommit());
        self.network = runtime.network;
        self.session = LinkedSession::new(
            runtime.get_storage_conn(),
            linked::link_runtime(runtime, true),
        );
        self.recognizer = TransactionRecognizer::new(
            self.session.origin(),
            self.network,
            self.session.executor.operations.recognize.clone(),
        );
    }

    #[cfg(test)]
    pub(super) async fn execute_block_unit(
        &mut self,
        selection: &ExecutionSelection,
        block: &PreparedBlock,
    ) -> Result<(usize, u64, Vec<Vec<Vec<Option<String>>>>)> {
        let lease = self.begin_unit(selection, false).await?;
        let result = self.execute_block(selection, block).await;
        self.finish_unit(lease, result, true).await
    }
}
