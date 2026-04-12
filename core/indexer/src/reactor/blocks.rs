use anyhow::{Context, Result, bail};
use bitcoin::hashes::Hash;
use indexer_types::{Block, BlockRow, Event, OpWithResult};
use tracing::{info, warn};

use crate::block;
use crate::consensus::finality_types::StateEvent;
use crate::database::queries::{
    confirm_transaction, get_transaction_by_txid, insert_batch, insert_block, insert_transaction,
    rollback_to_height, select_block_at_height, select_block_latest,
};
use crate::runtime::{
    filestorage::api::{expire_challenges, generate_challenges_for_block},
    staking::api::process_pending_validators,
    wit::Signer,
};
use crate::test_utils::new_mock_block_hash;

use super::Reactor;
use super::consensus_state;
use super::executor::Executor;

impl<E: Executor> Reactor<E> {
    pub(super) async fn rollback(&mut self, height: u64) -> Result<()> {
        rollback_to_height(&self.db_conn(), height)
            .await
            .context("rollback_to_height failed")?;
        self.runtime
            .file_ledger
            .force_resync_from_db(&self.runtime.storage.conn)
            .await
            .context("file_ledger resync after rollback failed")?;
        self.last_height = height;

        if let Ok(Some(row)) = select_block_at_height(&self.db_conn(), height as i64).await {
            self.last_hash = Some(row.hash);
            info!("Rollback to height {} ({})", height, row.hash);
        } else {
            self.last_hash = None;
            warn!("Rollback to height {}, no previous block found", height);
        }

        // Refresh cached validator set — rolled-back state may have different active set
        self.refresh_validator_set().await?;

        if let Some(tx) = &self.event_tx
            && tx.send(Event::Rolledback { height }).await.is_err()
        {
            warn!("Event receiver dropped, cannot send Rolledback event");
        }

        Ok(())
    }

    /// Execute a block: insert block row, process transactions.
    /// Returns the number of unbatched (non-deduped) transactions.
    pub(super) async fn execute_block(&mut self, block: &Block) -> Result<usize> {
        insert_block(
            &self.db_conn(),
            BlockRow::builder()
                .height(block.height as i64)
                .hash(block.hash)
                .relevant(!block.transactions.is_empty())
                .build(),
        )
        .await
        .context("insert_block failed")?;

        let mut unbatched_count = 0;
        for (i, t) in block.transactions.iter().enumerate() {
            if get_transaction_by_txid(&self.db_conn(), &t.txid.to_string())
                .await
                .context("get_transaction_by_txid failed")?
                .is_some()
            {
                confirm_transaction(
                    &self.db_conn(),
                    &t.txid.to_string(),
                    block.height as i64,
                    i as i64,
                )
                .await
                .context("confirm_transaction failed")?;
                continue;
            }

            unbatched_count += 1;
            let tx_id = insert_transaction(
                &self.db_conn(),
                indexer_types::TransactionRow::builder()
                    .height(block.height as i64)
                    .tx_index(i as i64)
                    .confirmed_height(block.height as i64)
                    .txid(t.txid.to_string())
                    .build(),
            )
            .await
            .context("insert_transaction failed")?;

            self.executor
                .execute_transaction(&mut self.runtime, block.height as i64, tx_id, t)
                .await;
        }

        Ok(unbatched_count)
    }

    /// Simulate a transaction: execute in a temporary block, inspect results, then rollback.
    pub(super) async fn simulate(
        &mut self,
        tx: indexer_types::Transaction,
    ) -> Result<Vec<OpWithResult>> {
        self.runtime
            .storage
            .savepoint()
            .await
            .context("Failed to begin simulation savepoint")?;
        let block_row = select_block_latest(&self.db_conn())
            .await
            .context("Failed to query latest block for simulation")?;
        let height = block_row.as_ref().map_or(1, |row| row.height as u64 + 1);
        let block = Block {
            height,
            hash: new_mock_block_hash(height as u32),
            prev_hash: block_row
                .as_ref()
                .map_or(new_mock_block_hash(0), |row| row.hash),
            transactions: vec![tx],
        };
        self.execute_block(&block)
            .await
            .context("execute_block failed during simulation")?;
        let result = block::inspect(&self.db_conn(), &block.transactions[0]).await;
        self.runtime
            .storage
            .rollback()
            .await
            .context("Failed to rollback simulation")?;
        result
    }

    /// Run block lifecycle operations: challenge expiry/generation and epoch transitions.
    async fn run_block_lifecycle(&mut self, block: &Block) -> Result<()> {
        let core_signer = Signer::Core(Box::new(Signer::Nobody));
        let block_hash: Vec<u8> = block.hash.to_byte_array().to_vec();
        self.runtime
            .set_context(block.height as i64, None, None, None)
            .await;
        expire_challenges(&mut self.runtime, &core_signer, block.height)
            .await
            .context("Failed to expire challenges")?;
        let challenges = generate_challenges_for_block(
            &mut self.runtime,
            &core_signer,
            block.height,
            block_hash,
        )
        .await
        .context("Failed to generate challenges")?;
        if !challenges.is_empty() {
            info!(
                "Generated {} challenges at block height {}",
                challenges.len(),
                block.height
            );
        }

        let change = process_pending_validators(&mut self.runtime, &core_signer, block.height)
            .await
            .context("Failed to call process_pending_validators")?
            .map_err(|e| anyhow::anyhow!("{e:?}"))
            .context("process_pending_validators returned error")?;
        if change.activated > 0 || change.deactivated > 0 {
            info!(
                "Validator set change at height {}: {} activated, {} deactivated",
                block.height, change.activated, change.deactivated
            );
        }
        Ok(())
    }

    pub(super) async fn handle_block_with_decision(
        &mut self,
        block: Block,
        decision: &consensus_state::DeferredDecision,
    ) -> Result<()> {
        insert_batch(
            &self.db_conn(),
            decision.consensus_height.as_u64() as i64,
            block.height as i64,
            &block.hash.to_string(),
            &decision.certificate,
            true,
        )
        .await
        .context("Failed to insert block batch decision")?;
        self.handle_block(block)
            .await
            .context("handle_block failed after block batch decision")?;
        Ok(())
    }

    pub(super) async fn handle_block(&mut self, block: Block) -> Result<()> {
        let height = block.height;
        let hash = block.hash;
        let prev_hash = block.prev_hash;
        if height != self.last_height + 1 {
            bail!(
                "Unexpected block height {}, expected {}",
                height,
                self.last_height + 1
            );
        }

        if let Some(last_hash) = self.last_hash {
            if prev_hash != last_hash {
                bail!(
                    "Block at height {} has prev_hash {} but expected {}",
                    height,
                    prev_hash,
                    last_hash
                );
            }
        } else {
            info!(
                "Initial block received at height {} (hash {})",
                height, hash
            );
        }

        self.last_height = height;
        self.last_hash = Some(hash);

        self.runtime
            .storage
            .savepoint()
            .await
            .context("Failed to begin block transaction")?;

        let unbatched_count = self
            .execute_block(&block)
            .await
            .context("execute_block failed")?;
        self.run_block_lifecycle(&block)
            .await
            .context("run_block_lifecycle failed")?;

        self.runtime
            .storage
            .commit()
            .await
            .context("Failed to commit block transaction")?;

        // Update cached validator set after block execution
        // (process_pending_validators may have activated/deactivated validators)
        self.refresh_validator_set().await?;

        let checkpoint = self.consensus.get_checkpoint(&self.db_conn()).await;
        self.consensus.emit_state_event(StateEvent::BlockProcessed {
            height,
            unbatched_count,
            checkpoint,
        });

        if let Some(tx) = &self.event_tx {
            let txids = block
                .transactions
                .iter()
                .map(|t| t.txid.to_string())
                .collect();
            if tx
                .send(Event::Processed {
                    block: (&block).into(),
                    txids,
                })
                .await
                .is_err()
            {
                warn!("Event receiver dropped, cannot send Processed event");
            }
        }
        info!(
            height,
            %hash,
            unbatched_count,
            tx_count = block.transactions.len(),
            "Block processed"
        );

        Ok(())
    }
}
