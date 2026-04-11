pub mod consensus;
pub mod engine;
pub mod executor;
#[cfg(test)]
pub(crate) mod lite_executor;
pub mod mock_bitcoin;
#[cfg(test)]
mod reactor_cluster_tests;
pub mod types;

use std::collections::HashSet;
use std::time::Instant;

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
use malachitebft_app_channel::app::types::codec::Codec;
use malachitebft_app_channel::app::types::core::VotingPower;
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_app_channel::{AppMsg, NetworkMsg};
use malachitebft_core_types::{LinearTimeouts, Round, Validity};
use malachitebft_engine::host::Next;
use prost::Message;
use tracing::{debug, error, info, warn};

use crate::consensus::codec::{ProtobufCodec, encode_commit_certificate};
use crate::consensus::finality_types::{FINALITY_WINDOW, StateEvent, UnfinalizedBatch};
use crate::consensus::{BatchTx, Value};
use crate::{
    bitcoin_follower::event::{BlockEvent, MempoolEvent},
    consensus::{Genesis, Validator, ValidatorSet, signing::PublicKey},
    database::{
        self,
        queries::{
            confirm_transaction, get_transaction_by_txid, insert_batch, insert_block,
            insert_transaction, insert_unconfirmed_batch_tx, rollback_to_height,
            select_block_at_height, select_block_latest, select_existing_txids,
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

    async fn process_decided_batch(
        &mut self,
        anchor_height: u64,
        anchor_hash: BlockHash,
        consensus_height: crate::consensus::Height,
        certificate: &[u8],
        batch_txs: &[bitcoin::Transaction],
    ) -> Result<()> {
        let conn = self.db_conn();

        info!(
            %consensus_height,
            anchor_height,
            %anchor_hash,
            num_txs = batch_txs.len(),
            "Processing decided batch"
        );

        // Empty batch — just record for sync, no execution or finality tracking
        if batch_txs.is_empty() {
            insert_batch(
                &conn,
                consensus_height.as_u64() as i64,
                anchor_height as i64,
                &anchor_hash.to_string(),
                certificate,
                false,
            )
            .await
            .context("Failed to insert empty batch")?;

            let checkpoint = self.consensus.get_checkpoint(&conn).await;
            self.consensus.emit_state_event(StateEvent::BatchApplied {
                consensus_height,
                anchor_height,
                txid_count: 0,
                checkpoint,
            });

            info!(
                anchor = anchor_height,
                consensus_height = %consensus_height,
                "Empty batch recorded"
            );
            return Ok(());
        }

        let parsed_txs: Vec<indexer_types::Transaction> = batch_txs
            .iter()
            .filter_map(|btx| self.executor.parse_transaction(btx))
            .collect();

        // Track for finality — must happen once per batch execution
        let txids: Vec<Txid> = batch_txs.iter().map(|tx| tx.compute_txid()).collect();
        self.consensus.unfinalized_batches.push(UnfinalizedBatch {
            consensus_height,
            anchor_height,
            anchor_hash,
            txids,
            deadline: anchor_height + FINALITY_WINDOW,
        });

        self.runtime
            .storage
            .savepoint()
            .await
            .context("Failed to begin batch transaction")?;

        insert_batch(
            &conn,
            consensus_height.as_u64() as i64,
            anchor_height as i64,
            &anchor_hash.to_string(),
            certificate,
            false,
        )
        .await
        .context("Failed to insert batch")?;

        // Store raw txs for replay/sync recovery
        for raw_tx in batch_txs {
            let txid = raw_tx.compute_txid();
            let serialized = bitcoin::consensus::serialize(raw_tx);
            insert_unconfirmed_batch_tx(
                &conn,
                &txid.to_string(),
                consensus_height.as_u64() as i64,
                &serialized,
            )
            .await
            .context("Failed to insert unconfirmed batch tx")?;
        }

        for t in &parsed_txs {
            let tx_id = insert_transaction(
                &conn,
                indexer_types::TransactionRow::builder()
                    .height(anchor_height as i64)
                    .batch_height(consensus_height.as_u64() as i64)
                    .txid(t.txid.to_string())
                    .build(),
            )
            .await
            .context("Failed to insert transaction")?;

            self.executor
                .execute_transaction(&mut self.runtime, anchor_height as i64, tx_id, t)
                .await;
        }

        self.runtime
            .storage
            .commit()
            .await
            .context("Failed to commit batch transaction")?;

        let checkpoint = self.consensus.get_checkpoint(&conn).await;
        self.consensus.emit_state_event(StateEvent::BatchApplied {
            consensus_height,
            anchor_height,
            txid_count: parsed_txs.len(),
            checkpoint,
        });

        info!(
            anchor = anchor_height,
            consensus_height = %consensus_height,
            "Batch processing complete"
        );

        Ok(())
    }

    async fn make_value(&mut self) -> Option<crate::consensus::Value> {
        let conn = self.db_conn();
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        // If blocks are pending, always propose the next one first
        if let Some((&height, block)) = self.consensus.pending_blocks.first_key_value() {
            return Some(crate::consensus::Value::new_block(height, block.hash));
        }

        // Pre-filter already-processed txids to avoid unnecessary validation
        let pending_txids: Vec<Txid> = self
            .consensus
            .pending_transactions
            .keys()
            .copied()
            .collect();
        let txid_strs: Vec<String> = pending_txids.iter().map(|t| t.to_string()).collect();
        let existing = select_existing_txids(&conn, &txid_strs)
            .await
            .unwrap_or_default();
        let unbatched_set: HashSet<Txid> = pending_txids
            .into_iter()
            .filter(|t| !existing.contains(&t.to_string()))
            .collect();

        // Remove already-processed txids from the pool
        for txid_str in &existing {
            if let Ok(txid) = txid_str.parse::<Txid>() {
                self.consensus.pending_transactions.remove(&txid);
            }
        }

        // Per-tx validation — remove invalid txs from the pool
        let mut txs = Vec::new();
        let mut invalid_txids = Vec::new();
        for (raw_tx, parsed) in self.consensus.pending_transactions.values() {
            let txid = raw_tx.compute_txid();
            if !unbatched_set.contains(&txid) {
                continue;
            }
            if self.executor.validate_transaction(raw_tx, parsed).await {
                txs.push(raw_tx.clone());
            } else {
                invalid_txids.push(txid);
            }
        }
        for txid in &invalid_txids {
            self.consensus.pending_transactions.remove(txid);
        }
        if txs.is_empty() {
            return None;
        }

        // Batch-level validation (already-processed check will pass since we pre-filtered)
        let candidate_txids: Vec<String> =
            txs.iter().map(|tx| tx.compute_txid().to_string()).collect();
        if let Some(reason) = self
            .consensus
            .validate_batch(
                &conn,
                last_height,
                last_hash,
                &candidate_txids,
                last_height,
                last_hash,
            )
            .await
        {
            info!("Not proposing batch: {reason}");
            return None;
        }

        let value = crate::consensus::Value::new_batch_raw(last_height, last_hash, txs);
        Some(value)
    }

    async fn validate_and_accept_proposal(
        &mut self,
        data: &crate::consensus::ProposalData,
        height: crate::consensus::Height,
        round: malachitebft_core_types::Round,
    ) -> Option<ProposedValue<crate::consensus::Ctx>> {
        let conn = self.db_conn();
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        let value = match data {
            crate::consensus::ProposalData::Block { height: bh, hash } => {
                if let Some(block) = self.consensus.pending_blocks.get(bh) {
                    if block.hash != *hash {
                        warn!(
                            block_height = bh,
                            proposed = %hash,
                            local = %block.hash,
                            "Rejecting block proposal: hash mismatch"
                        );
                        return None;
                    }
                } else {
                    warn!(
                        block_height = bh,
                        "Rejecting block proposal: block not yet received"
                    );
                    return None;
                }
                crate::consensus::Value::new_block(*bh, *hash)
            }
            crate::consensus::ProposalData::Batch {
                anchor_height,
                anchor_hash,
                transactions,
            } => {
                let txid_strs: Vec<String> = transactions
                    .iter()
                    .map(|tx| tx.compute_txid().to_string())
                    .collect();
                if let Some(reason) = self
                    .consensus
                    .validate_batch(
                        &conn,
                        *anchor_height,
                        *anchor_hash,
                        &txid_strs,
                        last_height,
                        last_hash,
                    )
                    .await
                {
                    warn!("Rejecting batch proposal: {reason}");
                    return None;
                }
                for tx in transactions {
                    let txid = tx.compute_txid();
                    let parsed =
                        if let Some((_, cached)) = self.consensus.pending_transactions.get(&txid) {
                            cached.clone()
                        } else if let Some(p) = self.executor.parse_transaction(tx) {
                            p
                        } else {
                            warn!(%txid, "Rejecting proposal: transaction failed to parse");
                            return None;
                        };
                    if !self.executor.validate_transaction(tx, &parsed).await {
                        warn!(%txid, "Rejecting proposal: transaction failed validation");
                        return None;
                    }
                    self.consensus
                        .pending_transactions
                        .entry(txid)
                        .or_insert_with(|| (tx.clone(), parsed));
                }
                crate::consensus::Value::new_batch_raw(
                    *anchor_height,
                    *anchor_hash,
                    transactions.clone(),
                )
            }
        };

        let proposed = ProposedValue {
            height,
            round,
            valid_round: malachitebft_core_types::Round::Nil,
            proposer: self.consensus.address,
            value,
            validity: Validity::Valid,
        };
        self.consensus
            .undecided
            .insert((height, round), proposed.clone());
        Some(proposed)
    }

    async fn try_fulfill_pending_proposal(&mut self) -> Result<bool> {
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        let (past_deadline, pending_height, pending_round) = match &self.consensus.pending_proposal
        {
            Some(p) => (Instant::now() >= p.hard_deadline(), p.height, p.round),
            None => return Ok(false),
        };

        let value = if let Some(value) = self.make_value().await {
            value
        } else if past_deadline {
            info!(
                height = %pending_height,
                round = %pending_round,
                "Proposing empty batch at hard deadline"
            );
            crate::consensus::Value::new_batch_raw(last_height, last_hash, vec![])
        } else {
            return Ok(false);
        };

        let pending = self.consensus.pending_proposal.take().unwrap();
        let proposed = ProposedValue {
            height: pending.height,
            round: pending.round,
            valid_round: Round::Nil,
            proposer: self.consensus.address,
            value: value.clone(),
            validity: Validity::Valid,
        };
        self.consensus
            .undecided
            .insert((pending.height, pending.round), proposed);
        let proposal = LocallyProposedValue::new(pending.height, pending.round, value);
        for stream_msg in self.consensus.stream_proposal(&proposal, Round::Nil) {
            self.consensus
                .channels
                .network
                .send(malachitebft_app_channel::NetworkMsg::PublishProposalPart(
                    stream_msg,
                ))
                .await
                .context("Failed to send proposal part to network")?;
        }
        let _ = pending.reply.send(proposal);

        Ok(true)
    }

    async fn initiate_rollback(
        &mut self,
        from_anchor: u64,
        excluded_txids: HashSet<Txid>,
    ) -> Result<()> {
        let conn = self.db_conn();
        let replay_batches = self
            .consensus
            .get_decided_from_anchor(&conn, from_anchor)
            .await
            .context("Failed to load replay batches for rollback")?;

        info!(
            from_anchor,
            replay_batches = replay_batches.len(),
            excluded = excluded_txids.len(),
            "Initiating rollback"
        );

        let mut deferred: std::collections::VecDeque<consensus::DeferredDecision> =
            replay_batches.into();
        if !excluded_txids.is_empty() {
            for decision in &mut deferred {
                if let crate::consensus::Value::Batch { ref mut txs, .. } = decision.value {
                    txs.retain(|tx| !excluded_txids.contains(&tx.txid()));
                }
            }
        }
        self.consensus.deferred_decisions = deferred;
        self.consensus
            .unfinalized_batches
            .retain(|b| b.anchor_height < from_anchor);

        self.executor
            .replay_blocks_from(from_anchor)
            .await
            .context("Failed to send replay request")?;
        Ok(())
    }

    async fn handle_consensus_msg(
        &mut self,
        msg: AppMsg<crate::consensus::Ctx>,
    ) -> Result<consensus::ConsensusResult> {
        let conn = self.db_conn();
        let last_height = self.last_height;

        let mut result = consensus::ConsensusResult::None;
        match msg {
            AppMsg::ConsensusReady { reply } => {
                let start_height = self.consensus.current_height;
                info!(%start_height, "Consensus is ready");

                reply
                    .send((start_height, self.consensus.height_params()))
                    .map_err(|_| anyhow::anyhow!("Failed to send ConsensusReady reply"))?;
            }

            AppMsg::StartedRound {
                height,
                round,
                proposer,
                role,
                reply_value,
            } => {
                info!(%height, %round, %proposer, ?role, "Started round");
                self.consensus.current_height = height;
                self.consensus.current_round = round;

                if let Some(pending) = &self.consensus.pending_proposal
                    && (pending.height != height || pending.round != round)
                {
                    info!(
                        pending_height = %pending.height,
                        pending_round = %pending.round,
                        "Clearing stale pending proposal"
                    );
                    self.consensus.pending_proposal = None;
                }

                let proposals: Vec<_> = self
                    .consensus
                    .undecided
                    .get(&(height, round))
                    .cloned()
                    .into_iter()
                    .collect();

                reply_value
                    .send(proposals)
                    .map_err(|_| anyhow::anyhow!("Failed to send StartedRound reply"))?;
            }

            AppMsg::GetValue {
                height,
                round,
                timeout,
                reply,
            } => {
                info!(%height, %round, "Building value to propose");

                if let Some(existing) = self.consensus.undecided.get(&(height, round)) {
                    let proposal = LocallyProposedValue::new(
                        existing.height,
                        existing.round,
                        existing.value.clone(),
                    );
                    for stream_msg in self.consensus.stream_proposal(&proposal, Round::Nil) {
                        self.consensus
                            .channels
                            .network
                            .send(NetworkMsg::PublishProposalPart(stream_msg))
                            .await
                            .context("Failed to send proposal part to network")?;
                    }
                    reply
                        .send(proposal)
                        .map_err(|_| anyhow::anyhow!("Failed to send GetValue reply"))?;
                } else if let Some(value) = self.make_value().await {
                    let proposed = ProposedValue {
                        height,
                        round,
                        valid_round: Round::Nil,
                        proposer: self.consensus.address,
                        value: value.clone(),
                        validity: Validity::Valid,
                    };
                    self.consensus.undecided.insert((height, round), proposed);
                    let proposal = LocallyProposedValue::new(height, round, value);
                    for stream_msg in self.consensus.stream_proposal(&proposal, Round::Nil) {
                        self.consensus
                            .channels
                            .network
                            .send(NetworkMsg::PublishProposalPart(stream_msg))
                            .await
                            .context("Failed to send proposal part to network")?;
                    }
                    reply
                        .send(proposal)
                        .map_err(|_| anyhow::anyhow!("Failed to send GetValue reply"))?;
                } else {
                    info!(%height, %round, "Nothing to propose, holding reply for pending transactions");
                    self.consensus.pending_proposal = Some(consensus::PendingProposal {
                        height,
                        round,
                        reply,
                        timeout,
                        created_at: Instant::now(),
                    });
                }
            }

            AppMsg::ReceivedProposalPart {
                from: _,
                part,
                reply,
            } => {
                let height = self.consensus.current_height;
                let round = self.consensus.current_round;

                let proposed = if round == Round::Nil {
                    None
                } else {
                    match &part.content {
                        malachitebft_app_channel::app::streaming::StreamContent::Data(
                            crate::consensus::ProposalPart::Data(data),
                        ) => {
                            if !self.consensus.undecided.contains_key(&(height, round)) {
                                self.validate_and_accept_proposal(data, height, round).await
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                };

                reply
                    .send(proposed)
                    .map_err(|_| anyhow::anyhow!("Failed to send ReceivedProposalPart reply"))?;
            }

            AppMsg::ExtendVote { reply, .. } => {
                reply
                    .send(None)
                    .map_err(|_| anyhow::anyhow!("Failed to send ExtendVote reply"))?;
            }

            AppMsg::VerifyVoteExtension { reply, .. } => {
                reply
                    .send(Ok(()))
                    .map_err(|_| anyhow::anyhow!("Failed to send VerifyVoteExtension reply"))?;
            }

            AppMsg::Decided {
                certificate,
                extensions: _,
            } => {
                info!(
                    height = %certificate.height,
                    round = %certificate.round,
                    value = %certificate.value_id,
                    "Decided"
                );
            }

            AppMsg::Finalized {
                certificate,
                extensions: _,
                evidence,
                reply,
            } => {
                info!(
                    height = %certificate.height,
                    round = %certificate.round,
                    value = %certificate.value_id,
                    evidence = ?evidence,
                    "Finalized"
                );

                if let Some(proposal) = self
                    .consensus
                    .undecided
                    .remove(&(certificate.height, certificate.round))
                {
                    if let Some(obs) = &self.consensus.observation {
                        let _ = obs.decided_tx.try_send(
                            crate::consensus::finality_types::DecidedBatch {
                                validator_index: self.consensus.validator_index,
                                consensus_height: certificate.height,
                                value: proposal.value.clone(),
                            },
                        );
                    }
                    match &proposal.value {
                        Value::Batch {
                            anchor_height,
                            anchor_hash,
                            txs,
                        } => {
                            let mut full_txs = Vec::new();
                            for entry in txs {
                                match entry {
                                    BatchTx::Raw(tx) => full_txs.push(tx.clone()),
                                    BatchTx::Id(txid) => {
                                        if let Some(tx) =
                                            self.executor.resolve_transaction(txid).await
                                        {
                                            full_txs.push(tx);
                                        }
                                    }
                                }
                            }

                            for tx in &full_txs {
                                self.consensus
                                    .pending_transactions
                                    .remove(&tx.compute_txid());
                            }

                            let cert_bytes = encode_commit_certificate(&certificate)
                                .map(|p| p.encode_to_vec())
                                .unwrap_or_default();

                            if *anchor_height < last_height {
                                warn!(
                                    anchor = anchor_height,
                                    last_height,
                                    consensus_height = %certificate.height,
                                    "Skipping stale batch — anchor below current height"
                                );
                                insert_batch(
                                    &conn,
                                    certificate.height.as_u64() as i64,
                                    *anchor_height as i64,
                                    &anchor_hash.to_string(),
                                    &cert_bytes,
                                    false,
                                )
                                .await
                                .context("Failed to record stale batch for sync")?;
                            } else if *anchor_height > last_height {
                                info!(
                                    anchor = anchor_height,
                                    last_height,
                                    consensus_height = %certificate.height,
                                    "Deferring batch — anchor block not yet processed"
                                );
                                self.consensus.deferred_decisions.push_back(
                                    consensus::DeferredDecision {
                                        consensus_height: certificate.height,
                                        value: proposal.value.clone(),
                                        certificate: cert_bytes,
                                    },
                                );
                            } else {
                                self.process_decided_batch(
                                    *anchor_height,
                                    *anchor_hash,
                                    certificate.height,
                                    &cert_bytes,
                                    &full_txs,
                                )
                                .await
                                .context("process_decided_batch failed in Finalized handler")?;
                                result = consensus::ConsensusResult::BatchProcessed {
                                    txids: full_txs
                                        .iter()
                                        .map(|tx| tx.compute_txid().to_string())
                                        .collect(),
                                };
                            }
                        }
                        Value::Block { height, hash } => {
                            let cert_bytes = encode_commit_certificate(&certificate)
                                .map(|p| p.encode_to_vec())
                                .unwrap_or_default();

                            if let Some(block) = self.consensus.pending_blocks.remove(height) {
                                info!(
                                    block_height = height,
                                    block_hash = %hash,
                                    consensus_height = %certificate.height,
                                    "Block decided and ready to process"
                                );
                                result = consensus::ConsensusResult::Block(
                                    block,
                                    consensus::DeferredDecision {
                                        consensus_height: certificate.height,
                                        value: proposal.value.clone(),
                                        certificate: cert_bytes.clone(),
                                    },
                                );
                            } else {
                                let is_stale =
                                    match select_block_at_height(&conn, *height as i64).await {
                                        Ok(Some(row)) => row.hash != *hash,
                                        _ => false,
                                    };
                                if !is_stale {
                                    info!(
                                        block_height = height,
                                        block_hash = %hash,
                                        consensus_height = %certificate.height,
                                        "Block decided but not yet received — deferring"
                                    );
                                    self.consensus.deferred_decisions.push_back(
                                        consensus::DeferredDecision {
                                            consensus_height: certificate.height,
                                            value: proposal.value.clone(),
                                            certificate: cert_bytes.clone(),
                                        },
                                    );
                                } else {
                                    warn!(
                                        block_height = height,
                                        block_hash = %hash,
                                        "Ignoring stale block decision (post-rollback)"
                                    );
                                }
                            }
                        }
                    }
                }

                self.consensus.current_height = certificate.height.increment();
                self.consensus.current_round = Round::Nil;
                self.consensus.pending_proposal = None;

                let next = Next::Start(
                    self.consensus.current_height,
                    self.consensus.height_params(),
                );

                reply
                    .send(next)
                    .map_err(|_| anyhow::anyhow!("Failed to send Finalized reply"))?;
            }

            AppMsg::GetHistoryMinHeight { reply } => {
                let min = self
                    .consensus
                    .min_decided_height(&conn)
                    .await
                    .unwrap_or(crate::consensus::Height::new(1));
                reply
                    .send(min)
                    .map_err(|_| anyhow::anyhow!("Failed to send GetHistoryMinHeight reply"))?;
            }

            AppMsg::GetDecidedValues { range, reply } => {
                let decided = self
                    .consensus
                    .get_decided_range(&conn, *range.start(), *range.end())
                    .await;
                let values: Vec<_> = decided
                    .into_iter()
                    .filter_map(|(value, cert)| {
                        ProtobufCodec
                            .encode(&value)
                            .ok()
                            .map(|encoded| RawDecidedValue {
                                certificate: cert,
                                value_bytes: encoded,
                            })
                    })
                    .collect();
                reply
                    .send(values)
                    .map_err(|_| anyhow::anyhow!("Failed to send GetDecidedValues reply"))?;
            }

            AppMsg::ProcessSyncedValue {
                height,
                round,
                proposer,
                value_bytes,
                reply,
            } => {
                let result: Option<ProposedValue<crate::consensus::Ctx>> =
                    if let Ok(value) = ProtobufCodec.decode(value_bytes) {
                        let proposed = ProposedValue {
                            height,
                            round,
                            valid_round: Round::Nil,
                            proposer,
                            value,
                            validity: Validity::Valid,
                        };
                        self.consensus
                            .undecided
                            .insert((height, round), proposed.clone());
                        Some(proposed)
                    } else {
                        None
                    };

                reply
                    .send(result)
                    .map_err(|_| anyhow::anyhow!("Failed to send ProcessSyncedValue reply"))?;
            }

            AppMsg::RestreamProposal {
                height,
                round,
                valid_round,
                address: _,
                value_id,
            } => {
                let lookup_round = if valid_round == Round::Nil {
                    round
                } else {
                    valid_round
                };
                if let Some(proposal) = self.consensus.undecided.get(&(height, lookup_round))
                    && proposal.value.id() == value_id
                {
                    let locally_proposed =
                        LocallyProposedValue::new(height, round, proposal.value.clone());
                    for stream_msg in self
                        .consensus
                        .stream_proposal(&locally_proposed, valid_round)
                    {
                        self.consensus
                            .channels
                            .network
                            .send(NetworkMsg::PublishProposalPart(stream_msg))
                            .await
                            .context("Failed to send proposal part to network")?;
                    }
                }
            }
        }

        Ok(result)
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
                        self.process_decided_batch(
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
                    self.try_fulfill_pending_proposal()
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
                let checkpoint = self.consensus.get_checkpoint(&self.db_conn()).await;
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
                let remaining = deadline.saturating_duration_since(Instant::now());
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
                    self.try_fulfill_pending_proposal().await
                        .context("try_fulfill_pending_proposal failed (debounce)")?;
                }
                _ = hard_deadline_sleep => {
                    self.try_fulfill_pending_proposal().await
                        .context("try_fulfill_pending_proposal failed (hard deadline)")?;
                }
                Some(msg) = consensus_rx => {
                    debug!("REACTOR: processing consensus msg");
                    let consensus_result = self.handle_consensus_msg(msg)
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
                        let conn = self.db_conn();
                        if self.consensus
                            .unfinalized_batches
                            .iter()
                            .any(|b| b.deadline <= self.last_height)
                            && let Some((rollback_anchor, excluded)) = self.consensus.run_finality_checks(&conn, self.last_height).await {
                                // Read replay decisions from DB before deleting state
                                self.initiate_rollback(
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
                                let checkpoint = self.consensus.get_checkpoint(&conn).await;
                                self.consensus.emit_state_event(StateEvent::RollbackExecuted {
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
