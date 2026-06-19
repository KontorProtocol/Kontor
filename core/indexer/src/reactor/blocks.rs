use std::time::Instant;

use anyhow::{Context, Result, bail};
use bitcoin::hashes::Hash;
use indexer_types::{Block, BlockRow, Event, OpWithResult};
use metrics::{counter, gauge};
use tracing::{debug, info, warn};

use crate::block;
use crate::consensus::finality_types::{FINALITY_WINDOW, StateEvent};
use crate::database::queries::{
    confirm_transaction, get_transaction_by_txid, insert_batch, insert_block, insert_transaction,
    prune_contract_state, rollback_to_height, select_block_at_height, select_block_latest,
};
use crate::metrics::{BLOCK_HEIGHT, ITEMS_INDEXED};
use crate::runtime::{
    filestorage::api::{expire_challenges, generate_challenges_for_block, record_block_root},
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
        // Cascade-deleted contracts free their ids for reuse by replayed
        // publishes; drop cached components so none is served stale WASM.
        self.runtime.component_cache.clear();
        self.last_height = height;

        if let Ok(Some(row)) = select_block_at_height(&self.db_conn(), height).await {
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
    /// Returns the number of unbatched (non-deduped) transactions, the count
    /// of ops actually executed (only ops in non-deduped txs — deduped txs
    /// were already executed via batch), and a per-tx vector of per-input
    /// per-op deterministic-failure entries.
    ///
    /// The failures vec has one outer entry per `block.transactions[i]`:
    /// - For ops that were deduped (already-confirmed txs), the entry is
    ///   an empty `Vec<Vec<_>>` (nothing was newly executed).
    /// - For ops freshly executed, the entry is a per-input per-op
    ///   positional vector aligned with `t.inputs[*].insts.ops[*]`.
    ///
    /// The reactor's canonical block-processing path discards this; the
    /// simulate handler consumes it.
    pub(super) async fn execute_block(
        &mut self,
        block: &Block,
    ) -> Result<(usize, u64, Vec<Vec<Vec<Option<anyhow::Error>>>>)> {
        insert_block(
            &self.db_conn(),
            BlockRow::builder()
                .height(block.height)
                .hash(block.hash)
                .relevant(!block.transactions.is_empty())
                .build(),
        )
        .await
        .context("insert_block failed")?;

        let mut unbatched_count = 0;
        let mut executed_ops: u64 = 0;
        let mut failures: Vec<Vec<Vec<Option<anyhow::Error>>>> =
            Vec::with_capacity(block.transactions.len());
        for (i, t) in block.transactions.iter().enumerate() {
            if get_transaction_by_txid(&self.db_conn(), &t.txid.to_string())
                .await
                .context("get_transaction_by_txid failed")?
                .is_some()
            {
                confirm_transaction(&self.db_conn(), &t.txid.to_string(), block.height, i as u32)
                    .await
                    .context("confirm_transaction failed")?;
                failures.push(Vec::new());
                continue;
            }

            unbatched_count += 1;
            executed_ops += t
                .inputs
                .iter()
                .map(|input| input.insts.ops.len() as u64)
                .sum::<u64>();
            let tx_id = insert_transaction(
                &self.db_conn(),
                indexer_types::TransactionRow::builder()
                    .height(block.height)
                    .tx_index(i as u32)
                    .confirmed_height(block.height)
                    .txid(t.txid.to_string())
                    .build(),
            )
            .await
            .context("insert_transaction failed")?;

            let tx_failures = self
                .executor
                .execute_transaction(&mut self.runtime, block.height, tx_id, t)
                .await
                .context("execute_transaction failed")?;
            failures.push(tx_failures);
        }

        Ok((unbatched_count, executed_ops, failures))
    }

    /// Simulate a transaction: execute in a temporary block, inspect results,
    /// merge in any deterministic-failure messages captured during execution,
    /// then rollback. Unlike `/inspect`, this carries live error strings —
    /// they're not persisted to chain state, only available here while the
    /// virtual block is still in scope.
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
        let height = block_row.as_ref().map_or(1, |row| row.height + 1);
        let block = Block {
            height,
            hash: new_mock_block_hash(height as u32),
            prev_hash: block_row
                .as_ref()
                .map_or(new_mock_block_hash(0), |row| row.hash),
            transactions: vec![tx],
        };
        let (_unbatched, _executed, failures) = self
            .execute_block(&block)
            .await
            .context("execute_block failed during simulation")?;
        let mut results = block::inspect(&self.db_conn(), &block.transactions[0]).await?;

        // Simulate's block has exactly one tx; failures[0] is the per-input
        // per-op failure vec for it. Flatten in declaration order (inputs
        // then ops) to align with inspect's flat OpWithResult vec — both
        // produce one entry per inst in input.insts.ops.
        if let Some(tx_failures) = failures.into_iter().next() {
            let mut flat = tx_failures
                .into_iter()
                .flat_map(|input_errs| input_errs.into_iter());
            for ow in results.iter_mut() {
                if let Some(Some(e)) = flat.next() {
                    let msg = format!("{e:#}");
                    match ow {
                        OpWithResult::Materialized { error_message, .. }
                        | OpWithResult::Rejected { error_message, .. } => {
                            *error_message = Some(msg);
                        }
                    }
                }
            }
        }

        self.runtime
            .storage
            .rollback()
            .await
            .context("Failed to rollback simulation")?;
        Ok(results)
    }

    /// Run block lifecycle operations: challenge expiry/generation and epoch transitions.
    async fn run_block_lifecycle(&mut self, block: &Block) -> Result<()> {
        let core_signer = Signer::Core(Box::new(Signer::Nobody));
        let block_hash: Vec<u8> = block.hash.to_byte_array().to_vec();
        self.runtime
            .set_context(block.height, None, None, None)
            .await;
        // Finalize the registry root for the block's `create_agreement`s (deferred
        // off the user's gas) before the challenge lifecycle. No-op if no files
        // were added this block.
        record_block_root(&mut self.runtime, &core_signer)
            .await
            .context("Failed to record block root")?
            .map_err(|e| anyhow::anyhow!("{e:?}"))
            .context("record_block_root returned error")?;
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
            decision.consensus_height.as_u64(),
            block.height,
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
        let started_at = Instant::now();
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

        let (unbatched_count, executed_ops, _failures) = self
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
        // Reflect what's actually persisted, not what we're mid-processing.
        // Op counter increments only after commit so the simulation path
        // (rolls back instead of committing) doesn't inflate it.
        gauge!(BLOCK_HEIGHT).set(height as f64);
        if executed_ops > 0 {
            counter!(ITEMS_INDEXED).increment(executed_ops);
        }

        // Update cached validator set after block execution
        // (process_pending_validators may have activated/deactivated validators)
        self.refresh_validator_set().await?;

        let checkpoint = self.consensus.get_checkpoint(&self.db_conn()).await;
        self.consensus.emit_state_event(StateEvent::BlockProcessed {
            height,
            unbatched_count,
            checkpoint,
        });

        // GC finalized superseded contract_state versions (separate from the block's
        // committed transaction — it only touches rows below the finality watermark).
        self.maybe_prune_state().await?;

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
            duration_ms = started_at.elapsed().as_millis() as u64,
            "Block processed"
        );

        Ok(())
    }

    /// Prune finalized, superseded `contract_state` versions below the finality
    /// watermark `tip − max(retain, FINALITY_WINDOW)`. No-op for archive nodes
    /// (`prune.enabled == false`) and until the chain is taller than the retain
    /// window. Runs once per block; the per-block churn is small. Returning freed
    /// pages to the OS (`incremental_vacuum`) is a separate, throttled step.
    async fn maybe_prune_state(&self) -> Result<()> {
        if !self.prune.enabled {
            return Ok(());
        }
        let retain = self.prune.retain_blocks.max(FINALITY_WINDOW);
        let Some(watermark) = self.last_height.checked_sub(retain) else {
            return Ok(());
        };
        let deleted = prune_contract_state(&self.db_conn(), watermark)
            .await
            .context("prune_contract_state failed")?;
        if deleted > 0 {
            debug!(
                watermark,
                deleted, "pruned finalized superseded contract_state versions"
            );
        }
        Ok(())
    }
}
