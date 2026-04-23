use std::collections::HashSet;
use std::time::Instant;

use anyhow::{Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use indexer_types::Event;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_core_types::{Round, Validity};
use malachitebft_engine::host::Next;
use prost::Message;
use tracing::{info, warn};

use crate::consensus::codec::encode_commit_certificate;
use crate::consensus::finality_types::{
    DecidedBatch, FINALITY_WINDOW, StateEvent, UnfinalizedBatch,
};
use crate::consensus::{CommitCertificate, Ctx, Height, ProposalData, Value};
use crate::database::queries::{
    insert_batch, insert_transaction, insert_unconfirmed_batch_tx, select_block_at_height,
    select_existing_txids,
};

use super::Reactor;
use super::consensus_state;
use super::executor::Executor;
use super::mempool_fee_index::MempoolFeeIndex;

/// Multiplier applied to `MempoolFeeIndex::fastest_fee()` to derive the
/// per-batch acceptance threshold. 0.9 means we accept txs at or above
/// 90% of the median fee rate in projected block 0.
const FEE_THRESHOLD_MULTIPLIER: f64 = 0.9;

/// Compute the per-batch fee acceptance threshold (sat/vB). Hoisted out
/// of `validate_transaction` so callers compute it once per validation
/// pass rather than per-tx.
fn compute_fee_threshold(fee_index: &MempoolFeeIndex) -> u64 {
    (fee_index.fastest_fee() as f64 * FEE_THRESHOLD_MULTIPLIER) as u64
}

impl<E: Executor> Reactor<E> {
    pub(super) async fn process_decided_batch(
        &mut self,
        anchor_height: u64,
        anchor_hash: BlockHash,
        consensus_height: Height,
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
            .map(|btx| {
                self.executor.parse_transaction(btx).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Failed to parse decided batch transaction {}",
                        btx.compute_txid()
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;

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
                .await
                .context("execute_transaction failed")?;
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

    pub(super) async fn make_value(&mut self) -> Result<Option<Value>> {
        let conn = self.db_conn();
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        // If blocks are pending, always propose the next one first
        if let Some((&height, block)) = self.consensus.pending_blocks.first_key_value() {
            return Ok(Some(Value::new_block(height, block.hash)));
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
            .context("Failed to query existing txids")?;
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

        // Per-tx validation — remove invalid txs from the pool. Compute
        // the fee threshold once for this batch (it's the same for every
        // tx, since the index is a snapshot during this loop).
        let threshold = compute_fee_threshold(&self.consensus.mempool_fee_index);
        let mut txs = Vec::new();
        let mut invalid_txids = Vec::new();
        for (raw_tx, parsed) in self.consensus.pending_transactions.values() {
            let txid = raw_tx.compute_txid();
            if !unbatched_set.contains(&txid) {
                continue;
            }
            if self
                .executor
                .validate_transaction(raw_tx, parsed, threshold)
                .await?
            {
                txs.push(raw_tx.clone());
            } else {
                invalid_txids.push(txid);
            }
        }
        for txid in &invalid_txids {
            self.consensus.pending_transactions.remove(txid);
        }
        if txs.is_empty() {
            return Ok(None);
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
            .await?
        {
            info!("Not proposing batch: {reason}");
            return Ok(None);
        }

        let value = Value::new_batch_raw(last_height, last_hash, txs);
        Ok(Some(value))
    }

    pub(super) async fn validate_and_accept_proposal(
        &mut self,
        data: &ProposalData,
        height: Height,
        round: Round,
    ) -> Result<Option<ProposedValue<Ctx>>> {
        let conn = self.db_conn();
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        let value = match data {
            ProposalData::Block { height: bh, hash } => {
                if let Some(block) = self.consensus.pending_blocks.get(bh) {
                    if block.hash != *hash {
                        warn!(
                            block_height = bh,
                            proposed = %hash,
                            local = %block.hash,
                            "Rejecting block proposal: hash mismatch"
                        );
                        return Ok(None);
                    }
                } else {
                    warn!(
                        block_height = bh,
                        "Rejecting block proposal: block not yet received"
                    );
                    return Ok(None);
                }
                Value::new_block(*bh, *hash)
            }
            ProposalData::Batch {
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
                    .await?
                {
                    warn!("Rejecting batch proposal: {reason}");
                    return Ok(None);
                }
                let threshold = compute_fee_threshold(&self.consensus.mempool_fee_index);
                for tx in transactions {
                    let txid = tx.compute_txid();
                    let parsed =
                        if let Some((_, cached)) = self.consensus.pending_transactions.get(&txid) {
                            cached.clone()
                        } else if let Some(p) = self.executor.parse_transaction(tx) {
                            p
                        } else {
                            warn!(%txid, "Rejecting proposal: transaction failed to parse");
                            return Ok(None);
                        };
                    if !self
                        .executor
                        .validate_transaction(tx, &parsed, threshold)
                        .await?
                    {
                        warn!(%txid, "Rejecting proposal: transaction failed validation");
                        return Ok(None);
                    }
                    self.consensus
                        .pending_transactions
                        .entry(txid)
                        .or_insert_with(|| (tx.clone(), parsed));
                }
                Value::new_batch_raw(*anchor_height, *anchor_hash, transactions.clone())
            }
        };

        let proposed = ProposedValue {
            height,
            round,
            valid_round: Round::Nil,
            proposer: self.consensus.address,
            value,
            validity: Validity::Valid,
        };
        self.consensus
            .undecided
            .insert((height, round), proposed.clone());
        Ok(Some(proposed))
    }

    pub(super) async fn try_fulfill_pending_proposal(&mut self) -> Result<bool> {
        let last_height = self.last_height;
        let last_hash = self.last_hash.unwrap_or(BlockHash::all_zeros());

        let (past_deadline, pending_height, pending_round) = match &self.consensus.pending_proposal
        {
            Some(p) => (Instant::now() >= p.hard_deadline(), p.height, p.round),
            None => return Ok(false),
        };

        let value = if let Some(value) = self.make_value().await? {
            value
        } else if past_deadline {
            info!(
                height = %pending_height,
                round = %pending_round,
                "Proposing empty batch at hard deadline"
            );
            Value::new_batch_raw(last_height, last_hash, vec![])
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
        self.send_proposal_parts(&proposal, Round::Nil).await?;
        let _ = pending.reply.send(proposal);

        Ok(true)
    }

    pub(super) async fn initiate_rollback(
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

        let mut deferred: std::collections::VecDeque<consensus_state::DeferredDecision> =
            replay_batches.into();
        if !excluded_txids.is_empty() {
            for decision in &mut deferred {
                if let Value::Batch { ref mut txs, .. } = decision.value {
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

    pub(super) async fn drain_deferred_decisions(&mut self) -> Result<()> {
        loop {
            let cs = &mut self.consensus;
            let Some(decision) = cs.deferred_decisions.pop_front() else {
                break;
            };

            match &decision.value {
                Value::Block { height: bh, .. } => {
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
                Value::Batch {
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
                        let resolved_txs = self.resolve_batch_txs(txs).await?;
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

    pub(super) async fn handle_get_value(
        &mut self,
        height: Height,
        round: Round,
        timeout: std::time::Duration,
        reply: tokio::sync::oneshot::Sender<LocallyProposedValue<Ctx>>,
    ) -> Result<()> {
        info!(%height, %round, "Building value to propose");

        if let Some(existing) = self.consensus.undecided.get(&(height, round)) {
            let proposal =
                LocallyProposedValue::new(existing.height, existing.round, existing.value.clone());
            self.send_proposal_parts(&proposal, Round::Nil).await?;
            reply
                .send(proposal)
                .map_err(|_| anyhow::anyhow!("Failed to send GetValue reply"))?;
        } else if let Some(value) = self.make_value().await? {
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
            self.send_proposal_parts(&proposal, Round::Nil).await?;
            reply
                .send(proposal)
                .map_err(|_| anyhow::anyhow!("Failed to send GetValue reply"))?;
        } else {
            info!(%height, %round, "Nothing to propose, holding reply for pending transactions");
            self.consensus.pending_proposal = Some(consensus_state::PendingProposal {
                height,
                round,
                reply,
                timeout,
                created_at: Instant::now(),
            });
        }
        Ok(())
    }

    pub(super) async fn handle_finalized(
        &mut self,
        certificate: CommitCertificate<Ctx>,
        reply: tokio::sync::oneshot::Sender<Next<Ctx>>,
    ) -> Result<consensus_state::ConsensusResult> {
        let conn = self.db_conn();
        let last_height = self.last_height;
        let mut result = consensus_state::ConsensusResult::None;

        if let Some(proposal) = self
            .consensus
            .undecided
            .remove(&(certificate.height, certificate.round))
        {
            if let Some(obs) = &self.consensus.observation {
                let _ = obs.decided_tx.try_send(DecidedBatch {
                    validator_index: self.consensus.validator_index,
                    consensus_height: certificate.height,
                    value: proposal.value.clone(),
                });
            }
            match &proposal.value {
                Value::Batch {
                    anchor_height,
                    anchor_hash,
                    txs,
                } => {
                    let full_txs = self.resolve_batch_txs(txs).await?;

                    for tx in &full_txs {
                        self.consensus
                            .pending_transactions
                            .remove(&tx.compute_txid());
                    }

                    let cert_bytes = encode_commit_certificate(&certificate)
                        .context("Failed to encode commit certificate")?
                        .encode_to_vec();

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
                            consensus_state::DeferredDecision {
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
                        result = consensus_state::ConsensusResult::BatchProcessed {
                            txids: full_txs
                                .iter()
                                .map(|tx| tx.compute_txid().to_string())
                                .collect(),
                        };
                    }
                }
                Value::Block { height, hash } => {
                    let cert_bytes = encode_commit_certificate(&certificate)
                        .context("Failed to encode commit certificate")?
                        .encode_to_vec();

                    if let Some(block) = self.consensus.pending_blocks.remove(height) {
                        info!(
                            block_height = height,
                            block_hash = %hash,
                            consensus_height = %certificate.height,
                            "Block decided and ready to process"
                        );
                        result = consensus_state::ConsensusResult::Block(
                            block,
                            consensus_state::DeferredDecision {
                                consensus_height: certificate.height,
                                value: proposal.value.clone(),
                                certificate: cert_bytes.clone(),
                            },
                        );
                    } else {
                        let is_stale = match select_block_at_height(&conn, *height as i64).await {
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
                                consensus_state::DeferredDecision {
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

        Ok(result)
    }
}
