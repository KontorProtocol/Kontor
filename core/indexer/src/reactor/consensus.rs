use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use anyhow::Result;
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::codec::Codec;
use malachitebft_app_channel::app::types::core::{Round, Validity};
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_app_channel::{AppMsg, Channels, NetworkMsg};
use malachitebft_core_types::{HeightParams, LinearTimeouts};
use malachitebft_engine::host::Next;

use crate::consensus::codec::ProtobufCodec;
use crate::consensus::finality_types::*;
use crate::consensus::signing::Ed25519Provider;
use crate::consensus::{
    Address, Ctx, Genesis, Height, ProposalData, ProposalFin, ProposalInit, ProposalPart,
    ValidatorSet, Value, ValueId,
};

use super::bitcoin_state::BitcoinState;
use super::executor::Executor;

/// All consensus-related state for the reactor.
pub struct ConsensusState {
    pub signing_provider: Ed25519Provider,
    pub genesis: Genesis,
    pub address: Address,
    pub current_height: Height,
    pub current_round: Round,
    pub undecided: BTreeMap<(Height, Round), ProposedValue<Ctx>>,

    // Finality tracking
    pub pending_batches: Vec<PendingBatch>,
    pub last_processed_anchor: u64,

    // Replay queue — populated after a rollback, drained before Malachite decisions
    pub replay_queue: VecDeque<(Height, Value)>,
    pub replay_excluded_txids: HashSet<Txid>,

    // Full transaction cache: ValueId → full txs. Populated when proposing or
    // receiving proposals (live consensus). Consumed when the value is decided.
    // Not used for sync/replay — those paths resolve txids via Executor.
    pub tx_cache: HashMap<ValueId, Vec<bitcoin::Transaction>>,

    // Observation channels (optional, for testing)
    pub decided_tx: Option<mpsc::Sender<DecidedBatch>>,
    pub finality_tx: Option<mpsc::Sender<FinalityEvent>>,
    pub state_tx: Option<mpsc::Sender<StateEvent>>,
}

impl ConsensusState {
    pub fn new(signing_provider: Ed25519Provider, genesis: Genesis, address: Address) -> Self {
        Self {
            signing_provider,
            genesis,
            address,
            current_height: Height::new(1),
            current_round: Round::new(0),
            undecided: BTreeMap::new(),
            pending_batches: Vec::new(),
            last_processed_anchor: 0,
            replay_queue: VecDeque::new(),
            replay_excluded_txids: HashSet::new(),
            tx_cache: HashMap::new(),
            decided_tx: None,
            finality_tx: None,
            state_tx: None,
        }
    }

    fn validator_set(&self) -> ValidatorSet {
        self.genesis.validator_set.clone()
    }

    fn height_params(&self) -> HeightParams<Ctx> {
        HeightParams::new(self.validator_set(), LinearTimeouts::default(), None)
    }

    fn stream_id(&self) -> StreamId {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.current_height.as_u64().to_be_bytes());
        bytes.extend_from_slice(&self.current_round.as_u32().unwrap().to_be_bytes());
        StreamId::new(bytes.into())
    }

    fn stream_proposal(
        &self,
        value: &LocallyProposedValue<Ctx>,
        pol_round: Round,
    ) -> Vec<StreamMessage<ProposalPart>> {
        use sha3::Digest;

        let mut hasher = sha3::Keccak256::new();
        hasher.update(value.height.as_u64().to_be_bytes());
        hasher.update(value.round.as_i64().to_be_bytes());
        hasher.update(value.value.anchor_height.to_be_bytes());
        hasher.update(value.value.anchor_hash.to_byte_array());
        for txid in &value.value.txids {
            hasher.update(txid.to_byte_array());
        }

        let hash = hasher.finalize();
        let signature = self.signing_provider.sign(&hash);

        let txs = self
            .tx_cache
            .get(&value.value.id())
            .cloned()
            .unwrap_or_default();

        let parts = vec![
            ProposalPart::Init(ProposalInit::new(
                value.height,
                value.round,
                pol_round,
                self.address,
            )),
            ProposalPart::Data(ProposalData::new(
                value.value.anchor_height,
                value.value.anchor_hash,
                txs,
            )),
            ProposalPart::Fin(ProposalFin::new(signature)),
        ];

        let stream_id = self.stream_id();
        let mut msgs = Vec::with_capacity(parts.len() + 1);

        for (seq, part) in parts.into_iter().enumerate() {
            msgs.push(StreamMessage::new(
                stream_id.clone(),
                seq as u64,
                StreamContent::Data(part),
            ));
        }
        msgs.push(StreamMessage::new(
            stream_id,
            msgs.len() as u64,
            StreamContent::Fin,
        ));

        msgs
    }

    async fn make_value(
        &mut self,
        executor: &impl Executor,
        bitcoin_state: &BitcoinState,
    ) -> Value {
        // Collect txids already in pending (unfinalized) batches to avoid duplicates
        let already_batched: HashSet<Txid> = self
            .pending_batches
            .iter()
            .flat_map(|b| b.txids.iter().copied())
            .collect();

        let mut txs = Vec::new();
        for tx in bitcoin_state.mempool.values() {
            let txid = tx.compute_txid();
            if already_batched.contains(&txid) {
                continue;
            }
            if !executor.validate_transaction(tx).await {
                continue;
            }
            txs.push(tx.clone());
        }
        let txids = txs.iter().map(|tx| tx.compute_txid()).collect();
        let value = Value::new(bitcoin_state.chain_tip, bitcoin_state.chain_tip_hash, txids);
        self.tx_cache.insert(value.id(), txs);
        value
    }

    // --- Finality tracking ---

    pub fn record_decided_batch(&mut self, consensus_height: Height, value: &Value) {
        let pending = PendingBatch {
            consensus_height,
            anchor_height: value.anchor_height,
            anchor_hash: value.anchor_hash,
            txids: value.txids.clone(),
            deadline: value.anchor_height + FINALITY_WINDOW,
        };
        info!(
            consensus_height = %consensus_height,
            anchor = value.anchor_height,
            deadline = pending.deadline,
            txs = value.txids.len(),
            "Tracking batch for finality"
        );
        self.pending_batches.push(pending);
    }

    pub async fn check_finality(
        &mut self,
        executor: &impl Executor,
        bitcoin_state: &BitcoinState,
    ) -> Vec<FinalityEvent> {
        let mut events = Vec::new();
        let tip = bitcoin_state.chain_tip;

        let mut still_pending = Vec::new();
        let mut at_deadline = Vec::new();

        for batch in self.pending_batches.drain(..) {
            if batch.deadline <= tip {
                at_deadline.push(batch);
            } else {
                still_pending.push(batch);
            }
        }

        at_deadline.sort_by_key(|b| (b.anchor_height, b.consensus_height));

        for batch in &at_deadline {
            let mut missing = Vec::new();
            for txid in &batch.txids {
                if !executor.is_confirmed_on_chain(txid).await {
                    missing.push(*txid);
                }
            }

            if missing.is_empty() {
                info!(
                    consensus_height = %batch.consensus_height,
                    anchor = batch.anchor_height,
                    "Batch finalized"
                );
                events.push(FinalityEvent::BatchFinalized {
                    consensus_height: batch.consensus_height,
                    anchor_height: batch.anchor_height,
                });
            } else {
                let from_anchor = batch.anchor_height;
                let mut invalidated = vec![batch.consensus_height];

                let mut surviving = Vec::new();
                for pending in still_pending.drain(..) {
                    if pending.anchor_height >= from_anchor {
                        invalidated.push(pending.consensus_height);
                    } else {
                        surviving.push(pending);
                    }
                }
                still_pending = surviving;

                warn!(
                    from_anchor,
                    invalidated = ?invalidated,
                    missing = missing.len(),
                    "Cascade invalidation triggered"
                );

                events.push(FinalityEvent::Rollback {
                    from_anchor,
                    invalidated_batches: invalidated,
                    missing_txids: missing,
                });

                break;
            }
        }

        self.pending_batches = still_pending;
        events
    }

    fn emit_finality_events(&self, events: &[FinalityEvent]) {
        if let Some(tx) = &self.finality_tx {
            for event in events {
                let _ = tx.try_send(event.clone());
            }
        }
    }

    pub fn emit_state_event(&self, event: StateEvent) {
        if let Some(tx) = &self.state_tx {
            let _ = tx.try_send(event);
        }
    }

    /// Initiate a rollback: query decided batches from the rollback point,
    /// truncate executor state, populate the replay queue, and signal block replay.
    pub async fn initiate_rollback(
        &mut self,
        executor: &mut impl Executor,
        bitcoin_state: &mut BitcoinState,
        from_anchor: u64,
        excluded_txids: HashSet<Txid>,
    ) {
        let replay_batches = executor.get_decided_from_anchor(from_anchor).await;
        let removed = executor.rollback_state(from_anchor).await;

        info!(
            from_anchor,
            removed,
            replay_batches = replay_batches.len(),
            excluded = excluded_txids.len(),
            "Initiating rollback"
        );

        self.replay_queue = replay_batches.into();
        self.replay_excluded_txids = excluded_txids;
        self.pending_batches
            .retain(|b| b.anchor_height < from_anchor);
        self.last_processed_anchor = from_anchor.saturating_sub(1);

        bitcoin_state.reset();

        self.emit_state_event(StateEvent::RollbackExecuted {
            to_anchor: from_anchor,
            entries_removed: removed,
            checkpoint: executor.checkpoint().await,
        });

        executor.replay_blocks_from(from_anchor).await;
    }

    /// Pop the next replay batch, filtering out excluded txids.
    /// Returns None when the queue is empty (back to normal Malachite flow).
    pub fn next_replay_batch(&mut self) -> Option<(Height, Value)> {
        if let Some((height, mut value)) = self.replay_queue.pop_front() {
            if !self.replay_excluded_txids.is_empty() {
                value
                    .txids
                    .retain(|txid| !self.replay_excluded_txids.contains(txid));
            }
            return Some((height, value));
        }
        // Queue drained — clear excluded set
        self.replay_excluded_txids.clear();
        None
    }

    /// Run finality checks and execute any rollbacks.
    pub async fn run_finality_checks(
        &mut self,
        executor: &mut impl Executor,
        bitcoin_state: &mut BitcoinState,
    ) {
        let finality_events = self.check_finality(executor, bitcoin_state).await;
        for event in &finality_events {
            if let FinalityEvent::Rollback {
                from_anchor,
                missing_txids,
                ..
            } = event
            {
                let excluded: HashSet<Txid> = missing_txids.iter().copied().collect();
                self.initiate_rollback(executor, bitcoin_state, *from_anchor, excluded)
                    .await;
            }
        }
        self.emit_finality_events(&finality_events);
    }

    /// Execute a decided batch, then drain pending blocks below the anchor.
    ///
    /// Only blocks with height < anchor are drained. The block at the anchor
    /// stays queued — the node doesn't know if more batches at this anchor are
    /// coming. It gets processed when the anchor advances (next batch has a
    /// higher anchor), the pending-block timeout fires, or finality checks run.
    ///
    /// If blocks at or above the anchor height were already executed (e.g. by a
    /// pending-block timeout), rolls back the executor and resets bitcoin state
    /// so that blocks are re-processed in correct order (batch first, then block).
    pub async fn process_decided_batch(
        &mut self,
        executor: &mut impl Executor,
        bitcoin_state: &mut BitcoinState,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        consensus_height: Height,
        batch_txs: &[bitcoin::Transaction],
    ) {
        // Detect timeout race: blocks executed before this batch was decided
        if let Some(last_block) = executor.last_executed_block_height().await
            && last_block >= anchor_height
        {
            warn!(
                anchor_height,
                last_block, "Timeout race detected — rolling back to re-apply batch before blocks"
            );
            let removed = executor.rollback_state(anchor_height).await;
            bitcoin_state.reset();

            self.emit_state_event(StateEvent::RollbackExecuted {
                to_anchor: anchor_height,
                entries_removed: removed,
                checkpoint: executor.checkpoint().await,
            });
        }

        // Drain blocks below the anchor — these precede all batches at this anchor
        while let Some(block) = bitcoin_state.pending_blocks.front() {
            if block.height < anchor_height {
                let block = bitcoin_state.pending_blocks.pop_front().unwrap();
                executor.execute_block(&block).await;
            } else {
                break;
            }
        }

        executor
            .execute_batch(anchor_height, anchor_hash, consensus_height, batch_txs)
            .await;

        self.last_processed_anchor = anchor_height;

        self.emit_state_event(StateEvent::BatchApplied {
            consensus_height,
            anchor_height,
            txid_count: batch_txs.len(),
            checkpoint: executor.checkpoint().await,
        });

        info!(
            anchor = anchor_height,
            consensus_height = %consensus_height,
            "Batch processing complete"
        );
    }
}

/// Handle a consensus message from the Malachite engine.
pub async fn handle_consensus_msg(
    state: &mut ConsensusState,
    executor: &mut impl Executor,
    bitcoin_state: &mut BitcoinState,
    channels: &mut Channels<Ctx>,
    msg: AppMsg<Ctx>,
    node_index: usize,
) -> Result<()> {
    match msg {
        AppMsg::ConsensusReady { reply } => {
            let start_height = state.current_height;
            info!(%start_height, "Consensus is ready");

            if reply.send((start_height, state.height_params())).is_err() {
                error!("Failed to send ConsensusReady reply");
            }
        }

        AppMsg::StartedRound {
            height,
            round,
            proposer,
            role,
            reply_value,
        } => {
            info!(%height, %round, %proposer, ?role, "Started round");
            state.current_height = height;
            state.current_round = round;

            let proposals: Vec<_> = state
                .undecided
                .get(&(height, round))
                .cloned()
                .into_iter()
                .collect();

            if reply_value.send(proposals).is_err() {
                error!("Failed to send StartedRound reply");
            }
        }

        AppMsg::GetValue {
            height,
            round,
            timeout: _,
            reply,
        } => {
            info!(%height, %round, "Building value to propose");

            let proposal = if let Some(existing) = state.undecided.get(&(height, round)) {
                LocallyProposedValue::new(existing.height, existing.round, existing.value.clone())
            } else {
                let value = state.make_value(executor, bitcoin_state).await;
                let proposed = ProposedValue {
                    height,
                    round,
                    valid_round: Round::Nil,
                    proposer: state.address,
                    value: value.clone(),
                    validity: Validity::Valid,
                };
                state.undecided.insert((height, round), proposed);
                LocallyProposedValue::new(height, round, value)
            };

            if reply.send(proposal.clone()).is_err() {
                error!("Failed to send GetValue reply");
            }

            for stream_msg in state.stream_proposal(&proposal, Round::Nil) {
                channels
                    .network
                    .send(NetworkMsg::PublishProposalPart(stream_msg))
                    .await?;
            }
        }

        AppMsg::ReceivedProposalPart {
            from: _,
            part,
            reply,
        } => {
            let height = state.current_height;
            let round = state.current_round;

            let proposed = if round == Round::Nil {
                None
            } else {
                match &part.content {
                    StreamContent::Data(ProposalPart::Data(data)) => {
                        if !state.undecided.contains_key(&(height, round)) {
                            if data.anchor_height > bitcoin_state.chain_tip {
                                warn!(
                                    anchor = data.anchor_height,
                                    tip = bitcoin_state.chain_tip,
                                    "Rejecting proposal with unknown anchor height"
                                );
                                None
                            } else if let Some(&local_hash) =
                                bitcoin_state.block_hashes.get(&data.anchor_height)
                            {
                                if local_hash != data.anchor_hash {
                                    warn!(
                                        anchor = data.anchor_height,
                                        proposed = %data.anchor_hash,
                                        local = %local_hash,
                                        "Rejecting proposal with mismatched anchor hash"
                                    );
                                    None
                                } else {
                                    let txids = data.txids();
                                    let value =
                                        Value::new(data.anchor_height, data.anchor_hash, txids);
                                    state.tx_cache.insert(value.id(), data.transactions.clone());
                                    let proposed = ProposedValue {
                                        height,
                                        round,
                                        valid_round: Round::Nil,
                                        proposer: state.address,
                                        value,
                                        validity: Validity::Valid,
                                    };
                                    state.undecided.insert((height, round), proposed.clone());
                                    Some(proposed)
                                }
                            } else {
                                // No local hash for this height — accept on height alone
                                // (can happen during sync when we haven't seen the block yet)
                                let txids = data.txids();
                                let value = Value::new(data.anchor_height, data.anchor_hash, txids);
                                state.tx_cache.insert(value.id(), data.transactions.clone());
                                let proposed = ProposedValue {
                                    height,
                                    round,
                                    valid_round: Round::Nil,
                                    proposer: state.address,
                                    value,
                                    validity: Validity::Valid,
                                };
                                state.undecided.insert((height, round), proposed.clone());
                                Some(proposed)
                            }
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            };

            if reply.send(proposed).is_err() {
                error!("Failed to send ReceivedProposalPart reply");
            }
        }

        AppMsg::ExtendVote { reply, .. } => {
            if reply.send(None).is_err() {
                error!("Failed to send ExtendVote reply");
            }
        }

        AppMsg::VerifyVoteExtension { reply, .. } => {
            if reply.send(Ok(())).is_err() {
                error!("Failed to send VerifyVoteExtension reply");
            }
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

            if let Some(proposal) = state
                .undecided
                .remove(&(certificate.height, certificate.round))
            {
                if let Some(tx) = &state.decided_tx {
                    let _ = tx.try_send(DecidedBatch {
                        node_index,
                        consensus_height: certificate.height,
                        value: proposal.value.clone(),
                    });
                }
                state.record_decided_batch(certificate.height, &proposal.value);

                // Live path: full txs available from cache
                let full_txs = state
                    .tx_cache
                    .remove(&proposal.value.id())
                    .unwrap_or_default();

                state
                    .process_decided_batch(
                        executor,
                        bitcoin_state,
                        proposal.value.anchor_height,
                        proposal.value.anchor_hash,
                        certificate.height,
                        &full_txs,
                    )
                    .await;

                executor
                    .store_decided(certificate.height, proposal.value, certificate.clone())
                    .await;
            }

            state.current_height = certificate.height.increment();
            state.current_round = Round::Nil;

            let next = Next::Start(state.current_height, state.height_params());

            if reply.send(next).is_err() {
                error!("Failed to send Finalized reply");
            }
        }

        AppMsg::GetHistoryMinHeight { reply } => {
            let min = executor
                .min_decided_height()
                .await
                .unwrap_or(Height::new(1));
            if reply.send(min).is_err() {
                error!("Failed to send GetHistoryMinHeight reply");
            }
        }

        AppMsg::GetDecidedValues { range, reply } => {
            let mut values = Vec::new();
            let start = *range.start();
            let end = *range.end();
            let mut h = start;
            while h <= end {
                if let Some((value, cert)) = executor.get_decided(h).await
                    && let Ok(encoded) = ProtobufCodec.encode(&value)
                {
                    values.push(RawDecidedValue {
                        certificate: cert,
                        value_bytes: encoded,
                    });
                }
                h = h.increment();
            }
            if reply.send(values).is_err() {
                error!("Failed to send GetDecidedValues reply");
            }
        }

        AppMsg::ProcessSyncedValue {
            height,
            round,
            proposer,
            value_bytes,
            reply,
        } => {
            let result: Option<ProposedValue<Ctx>> =
                if let Ok(value) = ProtobufCodec.decode(value_bytes) {
                    let proposed = ProposedValue {
                        height,
                        round,
                        valid_round: Round::Nil,
                        proposer,
                        value,
                        validity: Validity::Valid,
                    };
                    state.undecided.insert((height, round), proposed.clone());
                    Some(proposed)
                } else {
                    None
                };

            if reply.send(result).is_err() {
                error!("Failed to send ProcessSyncedValue reply");
            }
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
            if let Some(proposal) = state.undecided.get(&(height, lookup_round))
                && proposal.value.id() == value_id
            {
                let locally_proposed =
                    LocallyProposedValue::new(height, round, proposal.value.clone());
                for stream_msg in state.stream_proposal(&locally_proposed, valid_round) {
                    channels
                        .network
                        .send(NetworkMsg::PublishProposalPart(stream_msg))
                        .await?;
                }
            }
        }
    }

    Ok(())
}
