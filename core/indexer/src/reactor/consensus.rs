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

use prost::Message;

use crate::consensus::codec::{ProtobufCodec, encode_commit_certificate};
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

    // Parsed transaction cache: Txid → parsed indexer_types::Transaction.
    // Populated during validate_transaction (proposing or receiving proposals).
    // Consumed during execute_batch to avoid double-parsing.
    // Cleared after process_decided_batch completes for a batch's txids.
    pub parsed_tx_cache: HashMap<Txid, indexer_types::Transaction>,

    // Blocks waiting for consensus decision — pushed when new Bitcoin blocks arrive,
    // popped from the front when Value::Block decisions are finalized.
    pub pending_blocks: VecDeque<(u64, bitcoin::BlockHash)>,

    // Blocks received from the poller, keyed by height. Consumed when a
    // Value::Block decision is finalized.
    pub block_cache: HashMap<u64, indexer_types::Block>,

    // Observation channels (optional, for testing)
    pub observation: Option<ObservationChannels>,
}

pub struct ObservationChannels {
    pub decided_tx: mpsc::Sender<DecidedBatch>,
    pub finality_tx: mpsc::Sender<FinalityEvent>,
    pub state_tx: mpsc::Sender<StateEvent>,
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
            parsed_tx_cache: HashMap::new(),
            pending_blocks: VecDeque::new(),
            block_cache: HashMap::new(),
            observation: None,
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

        let data_part = match &value.value {
            Value::Batch {
                anchor_height,
                anchor_hash,
                txids,
                ..
            } => {
                hasher.update(anchor_height.to_be_bytes());
                hasher.update(anchor_hash.to_byte_array());
                for txid in txids {
                    hasher.update(txid.to_byte_array());
                }
                let txs = self
                    .tx_cache
                    .get(&value.value.id())
                    .cloned()
                    .unwrap_or_default();
                ProposalData::new_batch(*anchor_height, *anchor_hash, txs)
            }
            Value::Block { height, hash } => {
                hasher.update(height.to_be_bytes());
                hasher.update(hash.to_byte_array());
                ProposalData::new_block(*height, *hash)
            }
        };

        let hash = hasher.finalize();
        let signature = self.signing_provider.sign(&hash);

        let parts = vec![
            ProposalPart::Init(ProposalInit::new(
                value.height,
                value.round,
                pol_round,
                self.address,
            )),
            ProposalPart::Data(data_part),
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
        last_height: u64,
        last_hash: bitcoin::BlockHash,
    ) -> Value {
        // If blocks are pending, always propose the next one first
        if let Some(&(height, hash)) = self.pending_blocks.front() {
            return Value::new_block(height, hash);
        }

        // Collect candidate txids from the mempool
        let mempool_txids: Vec<Txid> = bitcoin_state.mempool.keys().copied().collect();

        // Filter out txids already in the system (batched or confirmed)
        let unbatched = executor.filter_unbatched_txids(&mempool_txids).await;
        let unbatched_set: HashSet<Txid> = unbatched.into_iter().collect();

        let mut txs = Vec::new();
        for tx in bitcoin_state.mempool.values() {
            let txid = tx.compute_txid();
            if !unbatched_set.contains(&txid) {
                continue;
            }
            // Skip validation if already parsed and cached
            if self.parsed_tx_cache.contains_key(&txid) {
                txs.push(tx.clone());
                continue;
            }
            if let Some(parsed) = executor.validate_transaction(tx).await {
                self.parsed_tx_cache.insert(txid, parsed);
                txs.push(tx.clone());
            }
        }
        let txids = txs.iter().map(|tx| tx.compute_txid()).collect();
        let value = Value::new_batch(last_height, last_hash, txids);
        self.tx_cache.insert(value.id(), txs);
        value
    }

    // --- Finality tracking ---

    pub fn record_decided_batch(&mut self, consensus_height: Height, value: &Value) {
        match value {
            Value::Batch {
                anchor_height,
                anchor_hash,
                txids,
                ..
            } => {
                let pending = PendingBatch {
                    consensus_height,
                    anchor_height: *anchor_height,
                    anchor_hash: *anchor_hash,
                    txids: txids.clone(),
                    deadline: anchor_height + FINALITY_WINDOW,
                };
                info!(
                    consensus_height = %consensus_height,
                    anchor = anchor_height,
                    deadline = pending.deadline,
                    txs = txids.len(),
                    "Tracking batch for finality"
                );
                self.pending_batches.push(pending);
            }
            Value::Block { height, hash } => {
                info!(
                    consensus_height = %consensus_height,
                    block_height = height,
                    block_hash = %hash,
                    "Block decided — no finality tracking needed"
                );
            }
        }
    }

    pub async fn check_finality(
        &mut self,
        executor: &impl Executor,
        last_height: u64,
    ) -> Vec<FinalityEvent> {
        let mut events = Vec::new();
        let tip = last_height;

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
        if let Some(obs) = &self.observation {
            for event in events {
                let _ = obs.finality_tx.try_send(event.clone());
            }
        }
    }

    pub fn emit_state_event(&self, event: StateEvent) {
        if let Some(obs) = &self.observation {
            let _ = obs.state_tx.try_send(event);
        }
    }

    /// Initiate a rollback: query decided batches from the rollback point,
    /// truncate executor state, populate the replay queue, and signal block replay.
    pub async fn initiate_rollback(
        &mut self,
        executor: &mut impl Executor,
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
            if !self.replay_excluded_txids.is_empty()
                && let Value::Batch { ref mut txids, .. } = value
            {
                txids.retain(|txid| !self.replay_excluded_txids.contains(txid));
            }
            return Some((height, value));
        }
        // Queue drained — clear excluded set
        self.replay_excluded_txids.clear();
        None
    }

    /// Run finality checks and execute any rollbacks.
    /// Returns the rollback anchor height if a rollback was initiated.
    pub async fn run_finality_checks(&mut self, executor: &mut impl Executor, last_height: u64) -> Option<u64> {
        let finality_events = self.check_finality(executor, last_height).await;
        let mut rollback_to = None;
        for event in &finality_events {
            if let FinalityEvent::Rollback {
                from_anchor,
                missing_txids,
                ..
            } = event
            {
                let excluded: HashSet<Txid> = missing_txids.iter().copied().collect();
                self.initiate_rollback(executor, *from_anchor, excluded)
                    .await;
                rollback_to = Some(*from_anchor);
            }
        }
        self.emit_finality_events(&finality_events);
        rollback_to
    }

    /// Execute a decided batch. Blocks are executed separately via Value::Block
    /// consensus decisions — no block draining or timeout race detection needed.
    pub async fn process_decided_batch(
        &mut self,
        executor: &mut impl Executor,
        _bitcoin_state: &mut BitcoinState,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        consensus_height: Height,
        certificate: &[u8],
        batch_txs: &[bitcoin::Transaction],
    ) {
        // Resolve batch txs to parsed form: check parsed_tx_cache first,
        // fall back to executor.parse_transaction for replay/sync path
        let parsed_txs: Vec<indexer_types::Transaction> = batch_txs
            .iter()
            .filter_map(|btx| {
                let txid = btx.compute_txid();
                if let Some(parsed) = self.parsed_tx_cache.remove(&txid) {
                    Some(parsed)
                } else {
                    executor.parse_transaction(btx)
                }
            })
            .collect();

        executor
            .execute_batch(
                anchor_height,
                anchor_hash,
                consensus_height,
                certificate,
                &parsed_txs,
                batch_txs,
            )
            .await;

        self.last_processed_anchor = anchor_height;

        self.emit_state_event(StateEvent::BatchApplied {
            consensus_height,
            anchor_height,
            txid_count: parsed_txs.len(),
            checkpoint: executor.checkpoint().await,
        });

        info!(
            anchor = anchor_height,
            consensus_height = %consensus_height,
            "Batch processing complete"
        );
    }
}

/// Validate a received proposal and accept it. Returns None if validation fails.
async fn validate_and_accept_proposal(
    state: &mut ConsensusState,
    executor: &mut impl Executor,
    data: &ProposalData,
    height: Height,
    round: Round,
) -> Option<ProposedValue<Ctx>> {
    let value = match data {
        ProposalData::Block { height, hash } => {
            // Block proposals need no tx validation
            Value::new_block(*height, *hash)
        }
        ProposalData::Batch {
            anchor_height,
            anchor_hash,
            transactions,
        } => {
            // Reject batch proposals when a block is pending
            if !state.pending_blocks.is_empty() {
                warn!("Rejecting batch proposal: block is pending");
                return None;
            }
            for tx in transactions {
                let txid = tx.compute_txid();
                if state.parsed_tx_cache.contains_key(&txid) {
                    continue;
                }
                if let Some(parsed) = executor.validate_transaction(tx).await {
                    state.parsed_tx_cache.insert(txid, parsed);
                } else {
                    warn!(
                        %txid,
                        "Rejecting proposal: transaction failed validation"
                    );
                    return None;
                }
            }
            let txids = data.txids();
            let value = Value::new_batch(*anchor_height, *anchor_hash, txids);
            state.tx_cache.insert(value.id(), transactions.clone());
            value
        }
    };

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

/// Handle a consensus message from the Malachite engine.
/// Handle a consensus message. Returns `Some(block)` if a `Value::Block` was
/// decided and the block should be executed by the reactor via `handle_block`.
pub async fn handle_consensus_msg(
    state: &mut ConsensusState,
    executor: &mut impl Executor,
    bitcoin_state: &mut BitcoinState,
    channels: &mut Channels<Ctx>,
    msg: AppMsg<Ctx>,
    node_index: usize,
    last_height: u64,
    last_hash: bitcoin::BlockHash,
) -> Result<Option<indexer_types::Block>> {
    let mut decided_block = None;
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
                let value = state
                    .make_value(executor, bitcoin_state, last_height, last_hash)
                    .await;
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
                            match data {
                                ProposalData::Block { .. } => {
                                    validate_and_accept_proposal(
                                        state, executor, data, height, round,
                                    )
                                    .await
                                }
                                ProposalData::Batch {
                                    anchor_height,
                                    anchor_hash,
                                    ..
                                } => {
                                    if *anchor_height > last_height {
                                        warn!(
                                            anchor = anchor_height,
                                            tip = last_height,
                                            "Rejecting proposal with unknown anchor height"
                                        );
                                        None
                                    } else if let Some(local_hash) =
                                        executor.block_hash_at_height(*anchor_height).await
                                    {
                                        if local_hash != *anchor_hash {
                                            warn!(
                                                anchor = anchor_height,
                                                proposed = %anchor_hash,
                                                local = %local_hash,
                                                "Rejecting proposal with mismatched anchor hash"
                                            );
                                            None
                                        } else {
                                            validate_and_accept_proposal(
                                                state, executor, data, height, round,
                                            )
                                            .await
                                        }
                                    } else {
                                        validate_and_accept_proposal(
                                            state, executor, data, height, round,
                                        )
                                        .await
                                    }
                                }
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
                if let Some(obs) = &state.observation {
                    let _ = obs.decided_tx.try_send(DecidedBatch {
                        node_index,
                        consensus_height: certificate.height,
                        value: proposal.value.clone(),
                    });
                }
                state.record_decided_batch(certificate.height, &proposal.value);

                match &proposal.value {
                    Value::Batch {
                        anchor_height,
                        anchor_hash,
                        ..
                    } => {
                        let full_txs = state
                            .tx_cache
                            .remove(&proposal.value.id())
                            .unwrap_or_default();

                        let cert_bytes = encode_commit_certificate(&certificate)
                            .map(|p| p.encode_to_vec())
                            .unwrap_or_default();

                        state
                            .process_decided_batch(
                                executor,
                                bitcoin_state,
                                *anchor_height,
                                *anchor_hash,
                                certificate.height,
                                &cert_bytes,
                                &full_txs,
                            )
                            .await;
                    }
                    Value::Block { height, hash } => {
                        state.pending_blocks.pop_front();
                        if let Some(block) = state.block_cache.remove(height) {
                            decided_block = Some(block);
                        } else {
                            warn!(
                                block_height = height,
                                block_hash = %hash,
                                "Block decided but not found in block_cache"
                            );
                        }
                    }
                }
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

    Ok(decided_block)
}
