use anyhow::{Result, ensure};
use bitcoin::BlockHash;
use indexer_types::Block;
use libsql::Connection;

use super::PruneConfig;
use super::build_genesis_from_staking;
use super::execution::ExecutionContext;
use super::executor::Executor;
use crate::bitcoin_follower::block::BlockInput;
use crate::consensus::test_fixtures::context;
use crate::database::canonical_history::{self, HistoryState};
use crate::database::queries::select_block_at_height;
use crate::protocol::coordinator::linked::{self, TransactionRecognizer};
use crate::protocol::coordinator::selection::ApplicationPosition;
use crate::runtime::Runtime;
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::LinkedSession;

// Unit tests of accounting/failure paths can seed state directly. They must never
// promote that state to certified history or use it to start a consensus engine.
pub(super) struct ExecutionFixture<E: Executor> {
    pub(super) execution: ExecutionContext<E>,
}

impl<E: Executor> ExecutionFixture<E> {
    pub(super) async fn new(
        runtime: Runtime,
        executor: E,
        height: u64,
        hash: Option<BlockHash>,
    ) -> Result<Self> {
        let conn = runtime.get_storage_conn();
        ensure!(canonical_history::state(&conn).await? == HistoryState::Unavailable);
        let network = runtime.network;
        let session = LinkedSession::new(conn, linked::link_runtime(runtime, true));
        Ok(Self {
            execution: ExecutionContext::new(
                executor,
                session,
                network,
                OwnerService::new(),
                context(),
                PruneConfig {
                    enabled: false,
                    retain_blocks: 144,
                },
                height,
                hash,
            ),
        })
    }

    pub(super) fn db_conn(&self) -> Connection {
        self.execution.db_conn()
    }

    pub(super) async fn block(&mut self, block: Block, consensus_height: u64) -> Result<()> {
        ensure!(canonical_history::state(&self.db_conn()).await? == HistoryState::Unavailable);
        ensure!(block.height == self.execution.last_height + 1);
        ensure!(
            self.execution
                .last_hash
                .is_none_or(|hash| hash == block.prev_hash)
        );
        let selection = self
            .execution
            .select_executor(ApplicationPosition::Block {
                height: block.height,
                hash: block.hash,
                consensus_height,
            })
            .await?;
        let block = self
            .execution
            .executor
            .prepare_block(
                &self.execution.recognizer,
                &selection,
                BlockInput::from(block),
            )
            .await?;
        let lease = self.execution.begin_unit(&selection, false).await?;
        let result = self
            .execution
            .block_txn(&selection, &block, consensus_height, &[])
            .await;
        self.execution.finish_unit(lease, result, true).await?;
        self.execution.last_height = block.height;
        self.execution.last_hash = Some(block.hash);
        build_genesis_from_staking(&mut *self.execution.test_runtime().await).await?;
        Ok(())
    }

    pub(super) async fn rollback(&mut self, height: u64) -> Result<()> {
        self.execution.maintain_executor(Some(height)).await?;
        self.execution.last_height = height;
        self.execution.last_hash = select_block_at_height(&self.db_conn(), height)
            .await?
            .map(|row| row.hash);
        self.execution.recognizer = TransactionRecognizer::new(
            self.execution.session.origin(),
            self.execution.network,
            self.execution.session.executor.operations.recognize.clone(),
        );
        Ok(())
    }
}
