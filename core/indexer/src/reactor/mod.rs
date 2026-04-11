pub mod consensus;
pub mod engine;
pub mod executor;
#[cfg(test)]
pub(crate) mod lite_executor;
pub mod mock_bitcoin;
#[cfg(test)]
mod reactor_cluster_tests;
pub mod types;

use anyhow::{Context, Result, bail};
use futures_util::future::pending;
use indexer_types::{Block, BlockRow, Event, OpWithResult};
use tokio::{
    select,
    sync::{
        mpsc::{self, Receiver},
        oneshot,
    },
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use malachitebft_app_channel::app::types::core::VotingPower;
use malachitebft_core_types::LinearTimeouts;
use tracing::{debug, error, info, warn};

use crate::consensus::finality_types::StateEvent;
use crate::{
    bitcoin_follower::event::{BlockEvent, MempoolEvent},
    consensus::{Genesis, Validator, ValidatorSet, signing::PublicKey},
    database::{
        self,
        queries::{
            confirm_transaction, get_transaction_by_txid, insert_batch, insert_block,
            insert_transaction, rollback_to_height, select_block_at_height, select_block_latest,
            select_unconfirmed_batch_tx,
        },
    },
    runtime::{
        ComponentCache, Decimal, Runtime, Storage,
        filestorage::api::{expire_challenges, generate_challenges_for_block},
        numerics::decimal_to_string,
        staking::api::{get_active_set, process_pending_validators},
        wit::Signer,
    },
    test_utils::new_mock_block_hash,
};

use crate::block;
use executor::Executor;

pub type Simulation = (
    indexer_types::Transaction,
    oneshot::Sender<Result<Vec<OpWithResult>>>,
);

pub struct Reactor<E: Executor> {
    executor: E,
    runtime: Runtime,
    cancel_token: CancellationToken,
    block_rx: Receiver<BlockEvent>,
    mempool_rx: Receiver<MempoolEvent>,
    ready_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
    consensus: consensus::ConsensusState,

    last_height: u64,
    last_hash: Option<BlockHash>,
}

impl<E: Executor> Reactor<E> {
    pub fn new(
        executor: E,
        runtime: Runtime,
        block_rx: Receiver<BlockEvent>,
        mempool_rx: Receiver<MempoolEvent>,
        cancel_token: CancellationToken,
        ready_tx: Option<oneshot::Sender<bool>>,
        event_tx: Option<mpsc::Sender<Event>>,
        simulate_rx: Option<Receiver<Simulation>>,
        consensus: consensus::ConsensusState,
        last_height: u64,
        last_hash: Option<BlockHash>,
    ) -> Self {
        let mut runtime = runtime;
        runtime.node_label = consensus
            .validator_index
            .map(|i| format!("node_{i}"))
            .unwrap_or_else(|| "follower".to_string());
        Self {
            executor,
            runtime,
            cancel_token,
            block_rx,
            mempool_rx,
            simulate_rx,
            last_height,
            last_hash,
            ready_tx,
            event_tx,
            consensus,
        }
    }

    /// Clone of the shared write connection from Runtime.storage.
    /// All DB connections in the reactor (Reactor, ConsensusState, Storage)
    /// share the same underlying connection via Arc.
    fn db_conn(&self) -> libsql::Connection {
        self.runtime.storage.conn.clone()
    }

    /// Check unconfirmed_batch_txs for a raw transaction (DB-level resolution).
    async fn resolve_tx_from_db(
        conn: &libsql::Connection,
        txid: &Txid,
    ) -> Option<bitcoin::Transaction> {
        if let Ok(Some(raw_bytes)) = select_unconfirmed_batch_tx(conn, &txid.to_string()).await
            && let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw_bytes)
        {
            return Some(tx);
        }
        None
    }

    async fn rollback(&mut self, height: u64) -> Result<()> {
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
        if let Ok(vs) = build_validator_set(&mut self.runtime).await {
            self.consensus.validator_index = vs
                .validators
                .iter()
                .position(|v| v.address == self.consensus.address);
            self.consensus.current_validator_set = vs;
        }

        if let Some(tx) = &self.event_tx
            && tx.send(Event::Rolledback { height }).await.is_err()
        {
            warn!("Event receiver dropped, cannot send Rolledback event");
        }

        Ok(())
    }

    /// Execute a block: insert block row, process transactions.
    /// Returns the number of unbatched (non-deduped) transactions.
    async fn execute_block(&mut self, block: &Block) -> Result<usize> {
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
    /// The caller (API layer) must validate with block::filter_map before sending.
    async fn simulate(&mut self, tx: indexer_types::Transaction) -> Result<Vec<OpWithResult>> {
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

    async fn handle_block_with_decision(
        &mut self,
        block: Block,
        decision: &consensus::DeferredDecision,
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

    async fn handle_block(&mut self, block: Block) -> Result<()> {
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
        if let Ok(vs) = build_validator_set(&mut self.runtime).await {
            self.consensus.validator_index = vs
                .validators
                .iter()
                .position(|v| v.address == self.consensus.address);
            self.consensus.current_validator_set = vs;
        }

        let checkpoint = self.consensus.get_checkpoint().await;
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

    async fn drain_deferred_decisions(&mut self) -> Result<()> {
        loop {
            let cs = &mut self.consensus;
            let Some(decision) = cs.deferred_decisions.pop_front() else {
                break;
            };

            match &decision.value {
                crate::consensus::Value::Block { height: bh, .. } => {
                    let bh = *bh;
                    let block = {
                        let cs = &mut self.consensus;
                        cs.pending_blocks.remove(&bh)
                    };
                    if let Some(block) = block {
                        info!(
                            block_height = bh,
                            consensus_height = %decision.consensus_height,
                            "Draining deferred block decision"
                        );
                        self.handle_block_with_decision(block, &decision)
                            .await
                            .context("handle_block_with_decision failed in deferred drain")?;
                    } else {
                        // Block data not yet available — put back and stop
                        info!(
                            block_height = bh,
                            consensus_height = %decision.consensus_height,
                            "Deferred block still waiting for data"
                        );
                        let cs = &mut self.consensus;
                        cs.deferred_decisions.push_front(decision);
                        break;
                    }
                }
                crate::consensus::Value::Batch {
                    anchor_height,
                    anchor_hash,
                    txs,
                    ..
                } => {
                    if *anchor_height <= self.last_height {
                        info!(
                            anchor_height = *anchor_height,
                            consensus_height = %decision.consensus_height,
                            num_txs = txs.len(),
                            "Draining deferred batch decision"
                        );
                        let anchor_height = *anchor_height;
                        let anchor_hash = *anchor_hash;
                        let mut resolved_txs = Vec::with_capacity(txs.len());
                        for tx in txs {
                            match tx {
                                crate::consensus::BatchTx::Raw(raw) => {
                                    resolved_txs.push(raw.clone());
                                }
                                crate::consensus::BatchTx::Id(txid) => {
                                    if let Some(tx) =
                                        Self::resolve_tx_from_db(&self.db_conn(), txid).await
                                    {
                                        resolved_txs.push(tx);
                                    } else if let Some(tx) =
                                        self.executor.resolve_transaction(txid).await
                                    {
                                        resolved_txs.push(tx);
                                    } else {
                                        warn!(%txid, "Could not resolve txid during deferred execution — skipping");
                                    }
                                }
                            }
                        }
                        let cs = &mut self.consensus;
                        cs.process_decided_batch(
                            &self.executor,
                            &mut self.runtime,
                            anchor_height,
                            anchor_hash,
                            decision.consensus_height,
                            &decision.certificate,
                            &resolved_txs,
                        )
                        .await
                        .context("process_decided_batch failed in deferred drain")?;
                        if let Some(tx) = &self.event_tx {
                            let txids: Vec<String> = resolved_txs
                                .iter()
                                .map(|tx| tx.compute_txid().to_string())
                                .collect();
                            if tx.send(Event::BatchProcessed { txids }).await.is_err() {
                                warn!("Event receiver dropped, cannot send BatchProcessed event");
                            }
                        }
                    } else {
                        info!(
                            anchor_height = *anchor_height,
                            last_height = self.last_height,
                            consensus_height = %decision.consensus_height,
                            "Deferred batch still waiting for anchor"
                        );
                        let cs = &mut self.consensus;
                        cs.deferred_decisions.push_front(decision);
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn process_block_event(&mut self, event: BlockEvent) -> Result<()> {
        match event {
            BlockEvent::BlockInsert {
                target_height,
                block,
            } => {
                let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid).collect();
                for txid in &txids {
                    self.consensus.pending_transactions.remove(txid);
                }
                info!("Block {}/{} {}", block.height, target_height, block.hash);

                info!(
                    block_height = block.height,
                    %block.hash,
                    pending_count = self.consensus.pending_blocks.len() + 1,
                    "Adding block to pending_blocks"
                );
                self.consensus
                    .pending_blocks
                    .insert(block.height, block.clone());
                self.drain_deferred_decisions()
                    .await
                    .context("drain_deferred_decisions failed after block insert")?;
                // A pending block may be what we're waiting to propose
                if self.consensus.pending_proposal.is_some() {
                    self.consensus
                        .try_fulfill_pending_proposal(
                            &self.executor,
                            self.last_height,
                            self.last_hash.unwrap_or(BlockHash::all_zeros()),
                        )
                        .await
                        .context("try_fulfill_pending_proposal failed after block insert")?;
                }
            }
            BlockEvent::Rollback { to_height } => {
                info!(to_height, "Bitcoin rollback — truncating state");
                self.rollback(to_height)
                    .await
                    .context("rollback failed during Bitcoin reorg")?;
                self.consensus.clear_on_rollback();
                let checkpoint = self.consensus.get_checkpoint().await;
                self.consensus
                    .emit_state_event(StateEvent::RollbackExecuted {
                        to_anchor: to_height,
                        entries_removed: 0,
                        checkpoint,
                    });
            }
        }
        Ok(())
    }

    async fn run_event_loop(&mut self) -> Result<()> {
        self.ready_tx.take().map(|tx| tx.send(true));

        let debounce_duration = std::time::Duration::from_millis(500);
        let mut debounce_deadline: Option<tokio::time::Instant> = None;

        loop {
            // Drain pending block events before entering select
            while let Ok(event) = self.block_rx.try_recv() {
                self.process_block_event(event)
                    .await
                    .context("process_block_event failed (try_recv drain)")?;
            }

            let hard_deadline_instant = self.consensus.pending_proposal.as_ref().map(|p| {
                let deadline = p.hard_deadline();
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                tokio::time::Instant::now() + remaining
            });

            let simulate_rx = async {
                if let Some(rx) = self.simulate_rx.as_mut() {
                    rx.recv().await
                } else {
                    pending().await
                }
            };

            let consensus_rx = self.consensus.channels.consensus.recv();

            let debounce_sleep = async {
                match debounce_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => pending().await,
                }
            };

            let hard_deadline_sleep = async {
                match hard_deadline_instant {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => pending().await,
                }
            };

            select! {
                _ = self.cancel_token.cancelled() => {
                    info!("Cancelled");
                    break;
                }
                Some(event) = self.block_rx.recv() => {
                    self.process_block_event(event)
                        .await
                        .context("process_block_event failed")?;
                }
                Some(event) = self.mempool_rx.recv() => {
                    match event {
                        MempoolEvent::Sync(txs) => {
                            let count = txs.len();
                            self.consensus.pending_transactions.clear();
                            for (raw, parsed) in txs {
                                self.consensus.pending_transactions.insert(
                                    raw.compute_txid(),
                                    (raw, parsed),
                                );
                            }
                            info!("MempoolSync {}", count);
                            if self.consensus.pending_proposal.is_some() {
                                debounce_deadline = Some(tokio::time::Instant::now() + debounce_duration);
                            }
                        },
                        MempoolEvent::Insert(tx, parsed) => {
                            let txid = tx.compute_txid();
                            self.consensus.pending_transactions.insert(txid, (tx, parsed));
                            debug!("MempoolInsert {}", txid);
                            if self.consensus.pending_proposal.is_some() {
                                debounce_deadline = Some(tokio::time::Instant::now() + debounce_duration);
                            }
                        },
                        MempoolEvent::Remove(txid) => {
                            self.consensus.pending_transactions.remove(&txid);
                            debug!("MempoolRemove {}", txid);
                        },
                    }
                }
                _ = debounce_sleep => {
                    debounce_deadline = None;
                    self.consensus.try_fulfill_pending_proposal(
                        &self.executor,
                        self.last_height,
                        self.last_hash.unwrap_or(BlockHash::all_zeros()),
                    ).await
                    .context("try_fulfill_pending_proposal failed (debounce)")?;
                }
                _ = hard_deadline_sleep => {
                    self.consensus.try_fulfill_pending_proposal(
                        &self.executor,
                        self.last_height,
                        self.last_hash.unwrap_or(BlockHash::all_zeros()),
                    ).await
                    .context("try_fulfill_pending_proposal failed (hard deadline)")?;
                }
                Some(msg) = consensus_rx => {
                    debug!("REACTOR: processing consensus msg");
                    let cs = &mut self.consensus;
                    let consensus_result = cs
                        .handle_consensus_msg(
                            &self.executor,
                            &mut self.runtime,
                            msg,
                            self.last_height,
                            self.last_hash.unwrap_or(BlockHash::all_zeros()),
                        )
                        .await
                        .context("handle_consensus_msg failed")?;
                    if let consensus::ConsensusResult::BatchProcessed { txids } = &consensus_result
                        && let Some(tx) = &self.event_tx
                        && tx
                            .send(Event::BatchProcessed {
                                txids: txids.clone(),
                            })
                            .await
                            .is_err()
                    {
                        warn!("Event receiver dropped, cannot send BatchProcessed event");
                    }
                    if let consensus::ConsensusResult::Block(block, decision) = consensus_result {
                        self.handle_block_with_decision(block, &decision)
                            .await
                            .context("handle_block_with_decision failed after consensus block")?;
                        self.drain_deferred_decisions()
                            .await
                            .context("drain_deferred_decisions failed after consensus block")?;
                        // Check finality after block execution — batch txids may now be confirmed
                        let cs = &mut self.consensus;
                        if cs
                            .unfinalized_batches
                            .iter()
                            .any(|b| b.deadline <= self.last_height)
                            && let Some((rollback_anchor, excluded)) = cs.run_finality_checks(self.last_height).await {
                                // Read replay decisions from DB before deleting state
                                let cs = &mut self.consensus;
                                cs.initiate_rollback(
                                    &mut self.executor,
                                    rollback_anchor,
                                    excluded,
                                ).await
                                .context("initiate_rollback failed")?;

                                // Rollback to before the invalid anchor so all state at the
                                // anchor height (including invalid tx effects) is wiped cleanly.
                                self.rollback(rollback_anchor.saturating_sub(1))
                                    .await
                                    .context("rollback failed during finality rollback")?;

                                // Emit rollback event
                                let cs = &mut self.consensus;
                                let checkpoint = cs.get_checkpoint().await;
                                cs.emit_state_event(StateEvent::RollbackExecuted {
                                    to_anchor: rollback_anchor,
                                    entries_removed: 0,
                                    checkpoint,
                                });

                                // Process deferred decisions using already-cached blocks
                                self.drain_deferred_decisions()
                                    .await
                                    .context("drain_deferred_decisions failed after finality rollback")?;
                            }
                    }
                    // Yield to allow other channels (block_rx, mempool_rx) to be polled
                    tokio::task::yield_now().await;
                }
                option_event = simulate_rx => {
                    if let Some((tx, ret_tx)) = option_event {
                        let result = self.simulate(tx).await;
                        let err_msg = result.as_ref().err().map(|e| format!("{e:#}"));
                        let _ = ret_tx.send(result);
                        if let Some(msg) = err_msg {
                            bail!("simulation failed: {msg}");
                        }
                    }
                }

            }
        }
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(node = %self.runtime.node_label))]
    pub async fn run(&mut self) -> Result<()> {
        let result = self.run_event_loop().await;

        // Gracefully stop the Malachite consensus engine and wait for cleanup
        let _ = self
            .consensus
            .engine_handle
            .actor
            .get_cell()
            .stop_and_wait(Some("Reactor shutting down".to_string()), None)
            .await;

        result
    }
}

/// Query the staking contract and build a ValidatorSet from the active validators.
async fn build_validator_set(runtime: &mut Runtime) -> Result<ValidatorSet> {
    let active_set = get_active_set(runtime)
        .await
        .context("Failed to query active validator set from staking contract")?;

    let validators: Vec<Validator> = active_set
        .into_iter()
        .filter_map(|v| {
            if v.ed25519_pubkey.len() != 32 {
                warn!(
                    xonly = v.x_only_pubkey,
                    "Skipping validator with invalid ed25519 pubkey length"
                );
                return None;
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&v.ed25519_pubkey);
            let public_key = PublicKey::from_bytes(key_bytes);
            let voting_power = match stake_to_voting_power(v.stake) {
                Ok(vp) => vp,
                Err(e) => {
                    warn!(
                        xonly = v.x_only_pubkey,
                        "Skipping validator with invalid stake: {e}"
                    );
                    return None;
                }
            };
            Some(Validator::new(public_key, voting_power))
        })
        .collect();

    Ok(ValidatorSet::new(validators))
}

fn stake_to_voting_power(stake: Decimal) -> Result<VotingPower> {
    let s = decimal_to_string(stake);
    let integer_part = s
        .split('.')
        .next()
        .context("decimal string missing integer part")?;
    let power = integer_part
        .parse::<u64>()
        .context("stake integer part is not a valid u64")?;
    Ok(power)
}

/// Build a Genesis from the staking contract's active validator set.
async fn build_genesis_from_staking(runtime: &mut Runtime) -> Result<Genesis> {
    let validator_set = build_validator_set(runtime).await?;
    Ok(Genesis { validator_set })
}

pub async fn create_runtime_executor(
    starting_block_height: u64,
    writer: &database::Writer,
    cancel_token: CancellationToken,
    bitcoin_client: Option<&crate::bitcoin_client::Client>,
    replay_tx: Option<mpsc::Sender<u64>>,
    genesis_validators: &[crate::runtime::GenesisValidator],
) -> Result<(executor::RuntimeExecutor, Runtime, u64, Option<BlockHash>)> {
    let conn = writer.connection();
    let (last_height, last_hash) = match select_block_latest(&conn)
        .await
        .context("Failed to query latest block during startup")?
    {
        Some(block) => {
            let block_height = block.height as u64;
            if block_height < starting_block_height - 1 {
                bail!(
                    "Latest block has height {}, less than start height {}",
                    block_height,
                    starting_block_height
                );
            }

            info!(
                "Continuing from block height {} ({})",
                block_height, block.hash
            );
            (block_height, Some(block.hash))
        }
        None => {
            info!(
                "No previous blocks found, starting from height {}",
                starting_block_height
            );
            (starting_block_height - 1, None)
        }
    };

    // ensure 0 (native) block exists
    if select_block_at_height(&conn, 0)
        .await
        .context("Failed to check for native block at height 0")?
        .is_none()
    {
        info!("Creating native block");
        insert_block(
            &conn,
            BlockRow::builder()
                .height(0)
                .hash(new_mock_block_hash(0))
                .relevant(true)
                .build(),
        )
        .await
        .context("Failed to insert native block at height 0")?;
    }
    let storage = Storage::builder()
        .height(0)
        .conn(writer.connection())
        .build();

    let mut runtime = Runtime::new(ComponentCache::new(), storage)
        .await
        .context("Failed to initialize runtime")?;
    runtime
        .publish_native_contracts(genesis_validators)
        .await
        .context("Failed to publish native contracts")?;

    let mut exec = executor::RuntimeExecutor::new(cancel_token);

    if let Some(client) = bitcoin_client {
        exec = exec.with_bitcoin_client(client.clone());
    }
    if let Some(tx) = replay_tx {
        exec = exec.with_replay_tx(tx);
    }

    Ok((exec, runtime, last_height, last_hash))
}

pub async fn start_consensus(
    engine_config: engine::EngineConfig,
    runtime: &mut Runtime,
    observation_channels: Option<consensus::ObservationChannels>,
    timeouts: Option<LinearTimeouts>,
    last_block_height: u64,
) -> Result<consensus::ConsensusState> {
    let genesis = build_genesis_from_staking(runtime)
        .await
        .context("Failed to build genesis from staking contract")?;

    let engine_output = engine::start(engine_config)
        .await
        .context("Failed to start Malachite consensus engine")?;
    info!(address = %engine_output.address, "Consensus engine started");

    let validator_index = genesis
        .validator_set
        .validators
        .iter()
        .position(|v| v.address == engine_output.address);

    let mut state = consensus::ConsensusState::new(
        runtime.get_storage_conn(),
        engine_output.signing_provider,
        genesis,
        engine_output.address,
        last_block_height,
        engine_output.channels,
        engine_output._handle,
        validator_index,
    )
    .await;
    state.observation = observation_channels;
    if let Some(t) = timeouts {
        state.timeouts = t;
    }

    Ok(state)
}

pub fn run(
    starting_block_height: u64,
    cancel_token: CancellationToken,
    writer: database::Writer,
    block_rx: Receiver<BlockEvent>,
    mempool_rx: Receiver<MempoolEvent>,
    ready_tx: Option<oneshot::Sender<bool>>,
    event_tx: Option<mpsc::Sender<Event>>,
    simulate_rx: Option<Receiver<Simulation>>,
    engine_config: engine::EngineConfig,
    bitcoin_client: Option<crate::bitcoin_client::Client>,
    replay_tx: Option<mpsc::Sender<u64>>,
    genesis_validators: Vec<crate::runtime::GenesisValidator>,
    observation_channels: Option<consensus::ObservationChannels>,
    consensus_propose_timeout_ms: Option<u64>,
) -> JoinHandle<()> {
    tokio::spawn({
        async move {
            let result: Result<()> = async {
                let (exec, mut runtime, last_height, last_hash) = create_runtime_executor(
                    starting_block_height,
                    &writer,
                    cancel_token.clone(),
                    bitcoin_client.as_ref(),
                    replay_tx,
                    &genesis_validators,
                )
                .await
                .context("create_runtime_executor failed")?;

                let timeouts = consensus_propose_timeout_ms.map(|ms| LinearTimeouts {
                    propose: std::time::Duration::from_millis(ms),
                    ..LinearTimeouts::default()
                });
                let consensus = start_consensus(
                    engine_config,
                    &mut runtime,
                    observation_channels,
                    timeouts,
                    last_height,
                )
                .await
                .context("start_consensus failed")?;

                let mut reactor = Reactor::new(
                    exec,
                    runtime,
                    block_rx,
                    mempool_rx,
                    cancel_token.clone(),
                    ready_tx,
                    event_tx,
                    simulate_rx,
                    consensus,
                    last_height,
                    last_hash,
                );

                reactor.run().await
            }
            .await;

            if let Err(e) = result {
                error!("Reactor error: {e:#}, exiting");
                cancel_token.cancel();
            }

            info!("Exited");
        }
    })
}
