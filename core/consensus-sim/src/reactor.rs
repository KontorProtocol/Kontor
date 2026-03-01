use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use anyhow::anyhow;
use bitcoin::hashes::Hash;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::DecidedBatch;
use crate::state_log::{StateLog, TxStatus};

use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::codec::Codec;
use malachitebft_app_channel::app::types::core::{Round, Validity};
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_app_channel::{AppMsg, Channels, NetworkMsg};
use malachitebft_core_types::{CommitCertificate, HeightParams, LinearTimeouts};
use malachitebft_engine::host::Next;

use indexer::bitcoin_follower::event::BitcoinEvent;
use indexer::consensus::codec::ProtobufCodec;
use indexer::consensus::signing::Ed25519Provider;
use indexer::consensus::{
    Address, Ctx, Genesis, Height, ProposalData, ProposalFin, ProposalInit, ProposalPart,
    ValidatorSet, Value,
};

pub const FINALITY_WINDOW: u64 = 6;

#[derive(Debug, Clone)]
pub struct PendingBatch {
    pub consensus_height: Height,
    pub anchor_height: u64,
    pub txids: Vec<[u8; 32]>,
    pub deadline: u64, // anchor_height + FINALITY_WINDOW
}

#[derive(Debug, Clone, PartialEq)]
pub enum FinalityEvent {
    BatchFinalized {
        consensus_height: Height,
        anchor_height: u64,
    },
    Rollback {
        from_anchor: u64,
        invalidated_batches: Vec<Height>,
        missing_txids: Vec<[u8; 32]>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum StateEvent {
    BlockProcessed {
        height: u64,
        unbatched_count: usize,
        checkpoint: [u8; 32],
    },
    BatchApplied {
        consensus_height: Height,
        anchor_height: u64,
        txid_count: usize,
        checkpoint: [u8; 32],
    },
    RollbackExecuted {
        to_anchor: u64,
        entries_removed: usize,
        checkpoint: [u8; 32],
    },
}

pub struct State {
    node_index: usize,
    signing_provider: Ed25519Provider,
    genesis: Genesis,
    address: Address,
    current_height: Height,
    current_round: Round,
    decided: BTreeMap<Height, (Value, CommitCertificate<Ctx>)>,
    undecided: BTreeMap<(Height, Round), ProposedValue<Ctx>>,

    // Bitcoin state
    mempool: HashSet<[u8; 32]>,
    chain_tip: u64,

    // Finality tracking
    pending_batches: Vec<PendingBatch>,
    confirmed_txids: HashMap<[u8; 32], u64>, // txid -> block height where first confirmed

    // State machine replication
    state_log: StateLog,
    block_history: BTreeMap<u64, Vec<[u8; 32]>>, // height -> txids in that block
    pending_blocks: VecDeque<u64>,                // heights received but not yet processed
    last_processed_anchor: u64,

    // Observation channels
    decided_tx: Option<mpsc::Sender<DecidedBatch>>,
    finality_tx: Option<mpsc::Sender<FinalityEvent>>,
    state_tx: Option<mpsc::Sender<StateEvent>>,
}

impl State {
    pub fn new(
        node_index: usize,
        signing_provider: Ed25519Provider,
        genesis: Genesis,
        address: Address,
        decided_tx: Option<mpsc::Sender<DecidedBatch>>,
        finality_tx: Option<mpsc::Sender<FinalityEvent>>,
        state_tx: Option<mpsc::Sender<StateEvent>>,
    ) -> Self {
        Self {
            node_index,
            signing_provider,
            genesis,
            address,
            current_height: Height::new(1),
            current_round: Round::new(0),
            decided: BTreeMap::new(),
            undecided: BTreeMap::new(),
            mempool: HashSet::new(),
            chain_tip: 0,
            pending_batches: Vec::new(),
            confirmed_txids: HashMap::new(),
            state_log: StateLog::new(),
            block_history: BTreeMap::new(),
            pending_blocks: VecDeque::new(),
            last_processed_anchor: 0,
            decided_tx,
            finality_tx,
            state_tx,
        }
    }

    fn validator_set(&self) -> ValidatorSet {
        self.genesis.validator_set.clone()
    }

    fn make_value(&mut self) -> Value {
        let txids: Vec<[u8; 32]> = self.mempool.iter().copied().collect();
        Value::new(self.chain_tip, txids)
    }

    /// Record a decided batch for finality tracking.
    fn record_decided_batch(&mut self, consensus_height: Height, value: &Value) {
        let pending = PendingBatch {
            consensus_height,
            anchor_height: value.anchor_height,
            txids: value.txids.clone(),
            deadline: value.anchor_height + FINALITY_WINDOW,
        };
        info!(
            consensus_height = %consensus_height,
            anchor = value.anchor_height,
            deadline = pending.deadline,
            txids = value.txids.len(),
            "Tracking batch for finality"
        );
        self.pending_batches.push(pending);
    }

    /// Record txids confirmed in a block for finality tracking.
    fn record_confirmed_block(&mut self, height: u64, txids: &[[u8; 32]]) {
        for txid in txids {
            self.confirmed_txids.entry(*txid).or_insert(height);
        }
    }

    /// Check all pending batches whose deadline <= chain_tip.
    fn check_finality(&mut self) -> Vec<FinalityEvent> {
        let mut events = Vec::new();
        let tip = self.chain_tip;

        // Partition: batches that have reached their deadline vs still pending
        let mut still_pending = Vec::new();
        let mut at_deadline = Vec::new();

        for batch in self.pending_batches.drain(..) {
            if batch.deadline <= tip {
                at_deadline.push(batch);
            } else {
                still_pending.push(batch);
            }
        }

        // Sort by anchor so we process earliest anchors first
        at_deadline.sort_by_key(|b| (b.anchor_height, b.consensus_height));

        for batch in &at_deadline {
            let missing: Vec<[u8; 32]> = batch
                .txids
                .iter()
                .filter(|txid| !self.confirmed_txids.contains_key(*txid))
                .copied()
                .collect();

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
                // Cascade: invalidate this batch and all still-pending batches
                // from this anchor forward
                let from_anchor = batch.anchor_height;
                let mut invalidated = vec![batch.consensus_height];

                // Pull out any still-pending batches at or after this anchor
                let mut surviving = Vec::new();
                for pending in still_pending.drain(..) {
                    if pending.anchor_height >= from_anchor {
                        invalidated.push(pending.consensus_height);
                    } else {
                        surviving.push(pending);
                    }
                }
                still_pending = surviving;

                // Also invalidate remaining at-deadline batches at or after this anchor
                // (they haven't been processed yet in this loop iteration)

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

                // After a rollback, remaining at-deadline batches from this anchor
                // forward are already invalidated — skip them by breaking.
                // Batches at earlier anchors in at_deadline were already processed.
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

    fn emit_state_event(&self, event: StateEvent) {
        if let Some(tx) = &self.state_tx {
            let _ = tx.try_send(event);
        }
    }

    /// Run finality checks and execute any rollbacks.
    /// `replay_up_to` is the exclusive upper bound for block replay after rollback.
    fn run_finality_checks(&mut self, replay_up_to: u64) {
        let finality_events = self.check_finality();
        for event in &finality_events {
            if let FinalityEvent::Rollback { from_anchor, .. } = event {
                let removed = self.rollback_state(*from_anchor);
                info!(from_anchor, removed, "Rollback executed: truncated state log");

                self.emit_state_event(StateEvent::RollbackExecuted {
                    to_anchor: *from_anchor,
                    entries_removed: removed,
                    checkpoint: self.state_log.checkpoint(),
                });

                let replay_heights: Vec<u64> = self
                    .block_history
                    .range(*from_anchor..)
                    .map(|(h, _)| *h)
                    .filter(|h| *h < replay_up_to)
                    .collect();
                for h in replay_heights {
                    if let Some(txids) = self.block_history.get(&h).cloned() {
                        for txid in &txids {
                            if self.validate_transaction(txid) {
                                self.execute_transaction(h, *txid, TxStatus::Confirmed);
                            }
                        }
                    }
                }

                self.last_processed_anchor = from_anchor.saturating_sub(1);
            }
        }
        self.emit_finality_events(&finality_events);
    }

    // --- Extension points: replace with real implementations in production ---

    /// Simulator: always true. Production: validate signatures, check WASM preconditions.
    fn validate_transaction(&self, _txid: &[u8; 32]) -> bool {
        true
    }

    /// Simulator: append to state log. Production: run WASM contract, write to DB.
    fn execute_transaction(&mut self, anchor_height: u64, txid: [u8; 32], status: TxStatus) {
        self.state_log.append_entry(anchor_height, txid, status);
    }

    /// Simulator: truncate state log. Production: DELETE FROM blocks WHERE height > ?.
    fn rollback_state(&mut self, to_anchor: u64) -> usize {
        self.state_log.rollback_to(to_anchor)
    }

    // --- End extension points ---

    /// Two-phase processing triggered when a batch is decided at anchor A:
    /// 1. Drain pending blocks up to (not including) A as unbatched
    /// 2. Apply batch (first), then block A's unbatched txs (deduplicating)
    ///
    /// Finality checks run separately on BlockInsert, not here.
    fn process_decided_batch(&mut self, anchor_height: u64, consensus_height: Height, batch_txids: &[[u8; 32]]) {
        // Phase 1: process queued blocks before this anchor
        while let Some(&next) = self.pending_blocks.front() {
            if next >= anchor_height {
                break;
            }
            self.pending_blocks.pop_front();
            let mut unbatched_count = 0;
            if let Some(block_txids) = self.block_history.get(&next).cloned() {
                for txid in &block_txids {
                    if self.validate_transaction(txid) {
                        self.execute_transaction(next, *txid, TxStatus::Confirmed);
                        unbatched_count += 1;
                    }
                }
            }
            self.emit_state_event(StateEvent::BlockProcessed {
                height: next,
                unbatched_count,
                checkpoint: self.state_log.checkpoint(),
            });
        }

        // Phase 2: apply batch txs first
        for txid in batch_txids {
            if self.validate_transaction(txid) {
                self.execute_transaction(anchor_height, *txid, TxStatus::Batched);
            }
        }

        // Phase 2b: apply unbatched txs from the anchor block (deduplicating against batch)
        let batch_set: HashSet<[u8; 32]> = batch_txids.iter().copied().collect();
        let mut unbatched_at_anchor = 0;
        if let Some(block_txids) = self.block_history.get(&anchor_height).cloned() {
            for txid in &block_txids {
                if !batch_set.contains(txid) && self.validate_transaction(txid) {
                    self.execute_transaction(anchor_height, *txid, TxStatus::Confirmed);
                    unbatched_at_anchor += 1;
                }
            }
        }

        // Remove anchor from pending_blocks if present
        self.pending_blocks.retain(|h| *h != anchor_height);
        self.last_processed_anchor = anchor_height;

        self.emit_state_event(StateEvent::BatchApplied {
            consensus_height,
            anchor_height,
            txid_count: batch_txids.len(),
            checkpoint: self.state_log.checkpoint(),
        });

        if unbatched_at_anchor > 0 {
            self.emit_state_event(StateEvent::BlockProcessed {
                height: anchor_height,
                unbatched_count: unbatched_at_anchor,
                checkpoint: self.state_log.checkpoint(),
            });
        }

        info!(
            anchor = anchor_height,
            consensus_height = %consensus_height,
            checkpoint = ?&self.state_log.checkpoint()[..4],
            "Three-phase processing complete"
        );
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
        for txid in &value.value.txids {
            hasher.update(txid);
        }

        let hash = hasher.finalize();
        let signature = self.signing_provider.sign(&hash);

        let parts = vec![
            ProposalPart::Init(ProposalInit::new(
                value.height,
                value.round,
                pol_round,
                self.address,
            )),
            ProposalPart::Data(ProposalData::new(
                value.value.anchor_height,
                value.value.txids.clone(),
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
}

/// Run the reactor loop, handling both consensus messages and bitcoin events.
pub async fn run(
    state: &mut State,
    channels: &mut Channels<Ctx>,
    bitcoin_rx: &mut mpsc::Receiver<BitcoinEvent>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Reactor cancelled");
                return Ok(());
            }
            Some(event) = bitcoin_rx.recv() => {
                handle_bitcoin_event(state, event);
            }
            Some(msg) = channels.consensus.recv() => {
                handle_consensus_msg(state, channels, msg).await?;
            }
            else => break,
        }
    }

    Err(anyhow!("All channels closed"))
}

fn handle_bitcoin_event(state: &mut State, event: BitcoinEvent) {
    match event {
        BitcoinEvent::BlockInsert { block, .. } => {
            state.chain_tip = block.height;
            let confirmed_txids: Vec<[u8; 32]> = block
                .transactions
                .iter()
                .map(|tx| tx.txid.to_byte_array())
                .collect();
            for txid in &confirmed_txids {
                state.mempool.remove(txid);
            }

            // Store block history for replay and queue for processing
            state.block_history.insert(block.height, confirmed_txids.clone());
            state.pending_blocks.push_back(block.height);

            // Prune old block history
            let prune_below = block.height.saturating_sub(FINALITY_WINDOW + 6);
            state.block_history.retain(|h, _| *h >= prune_below);

            info!(
                height = block.height,
                txs = block.transactions.len(),
                mempool = state.mempool.len(),
                "Block queued"
            );

            // Record confirmed txids for finality tracking
            state.record_confirmed_block(block.height, &confirmed_txids);

            // Finality deadlines are reached by block arrivals, not consensus decisions.
            // Check immediately so rollback/finalization isn't delayed until the next batch.
            if state.pending_batches.iter().any(|b| b.deadline <= state.chain_tip) {
                let replay_up_to = state.last_processed_anchor.saturating_add(1);
                state.run_finality_checks(replay_up_to);
            }
        }
        BitcoinEvent::MempoolInsert(tx) => {
            state.mempool.insert(tx.txid.to_byte_array());
            debug!(txid = %tx.txid, mempool = state.mempool.len(), "Mempool insert");
        }
        BitcoinEvent::MempoolRemove(txid) => {
            state.mempool.remove(&txid.to_byte_array());
            debug!(%txid, mempool = state.mempool.len(), "Mempool remove");
        }
        BitcoinEvent::MempoolSync(txs) => {
            state.mempool.clear();
            for tx in txs {
                state.mempool.insert(tx.txid.to_byte_array());
            }
            info!(mempool = state.mempool.len(), "Mempool sync");
        }
        BitcoinEvent::Rollback { to_height } => {
            info!(to_height, "Bitcoin rollback");
        }
    }
}

async fn handle_consensus_msg(
    state: &mut State,
    channels: &mut Channels<Ctx>,
    msg: AppMsg<Ctx>,
) -> anyhow::Result<()> {
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
                    LocallyProposedValue::new(
                        existing.height,
                        existing.round,
                        existing.value.clone(),
                    )
                } else {
                    let value = state.make_value();
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

                let proposed = match &part.content {
                    StreamContent::Data(ProposalPart::Data(data)) => {
                        if !state.undecided.contains_key(&(height, round)) {
                            let value = Value::new(data.anchor_height, data.txids.clone());
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
                        } else {
                            None
                        }
                    }
                    _ => None,
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
                            node_index: state.node_index,
                            consensus_height: certificate.height,
                            value: proposal.value.clone(),
                        });
                    }
                    state.record_decided_batch(certificate.height, &proposal.value);

                    // Three-phase processing: blocks → finality check → batch + unbatched
                    state.process_decided_batch(
                        proposal.value.anchor_height,
                        certificate.height,
                        &proposal.value.txids.clone(),
                    );

                    state
                        .decided
                        .insert(certificate.height, (proposal.value, certificate.clone()));
                }

                state.current_height = certificate.height.increment();
                state.current_round = Round::Nil;

                let next = Next::Start(state.current_height, state.height_params());

                if reply.send(next).is_err() {
                    error!("Failed to send Finalized reply");
                }
            }

            AppMsg::GetHistoryMinHeight { reply } => {
                let min = state
                    .decided
                    .keys()
                    .next()
                    .copied()
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
                    if let Some((value, cert)) = state.decided.get(&h)
                        && let Ok(encoded) = ProtobufCodec.encode(value)
                    {
                        values.push(RawDecidedValue {
                            certificate: cert.clone(),
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
