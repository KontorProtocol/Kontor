use std::collections::BTreeMap;

use anyhow::Result;
use bitcoin::hashes::Hash;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::codec::Codec;
use malachitebft_app_channel::app::types::core::{Round, Validity};
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_app_channel::{AppMsg, Channels, NetworkMsg};
use malachitebft_core_types::{CommitCertificate, HeightParams, LinearTimeouts};
use malachitebft_engine::host::Next;

use crate::consensus::codec::ProtobufCodec;
use crate::consensus::finality_types::*;
use crate::consensus::signing::Ed25519Provider;
use crate::consensus::{
    Address, Ctx, Genesis, Height, ProposalData, ProposalFin, ProposalInit, ProposalPart,
    ValidatorSet, Value,
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
    pub decided: BTreeMap<Height, (Value, CommitCertificate<Ctx>)>,
    pub undecided: BTreeMap<(Height, Round), ProposedValue<Ctx>>,

    // Finality tracking
    pub pending_batches: Vec<PendingBatch>,
    pub last_processed_anchor: u64,

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
            decided: BTreeMap::new(),
            undecided: BTreeMap::new(),
            pending_batches: Vec::new(),
            last_processed_anchor: 0,
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
        for tx in &value.value.transactions {
            hasher.update(tx.compute_txid().to_byte_array());
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
                value.value.transactions.clone(),
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

    fn make_value(&self, bitcoin_state: &BitcoinState) -> Value {
        let transactions: Vec<_> = bitcoin_state.mempool.values().cloned().collect();
        Value::new(bitcoin_state.chain_tip, transactions)
    }

    // --- Finality tracking ---

    pub fn record_decided_batch(&mut self, consensus_height: Height, value: &Value) {
        let pending = PendingBatch {
            consensus_height,
            anchor_height: value.anchor_height,
            transactions: value.transactions.clone(),
            deadline: value.anchor_height + FINALITY_WINDOW,
        };
        info!(
            consensus_height = %consensus_height,
            anchor = value.anchor_height,
            deadline = pending.deadline,
            txs = value.transactions.len(),
            "Tracking batch for finality"
        );
        self.pending_batches.push(pending);
    }

    pub fn check_finality(&mut self, bitcoin_state: &BitcoinState) -> Vec<FinalityEvent> {
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
            let missing: Vec<bitcoin::Txid> = batch
                .transactions
                .iter()
                .map(|tx| tx.compute_txid())
                .filter(|txid| !bitcoin_state.confirmed_txids.contains_key(txid))
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

    fn emit_state_event(&self, event: StateEvent) {
        if let Some(tx) = &self.state_tx {
            let _ = tx.try_send(event);
        }
    }

    /// Run finality checks and execute any rollbacks.
    pub async fn run_finality_checks(
        &mut self,
        executor: &mut impl Executor,
        bitcoin_state: &BitcoinState,
    ) {
        let finality_events = self.check_finality(bitcoin_state);
        for event in &finality_events {
            if let FinalityEvent::Rollback { from_anchor, .. } = event {
                let removed = executor.rollback_state(*from_anchor).await;
                info!(from_anchor, removed, "Rollback executed");

                self.emit_state_event(StateEvent::RollbackExecuted {
                    to_anchor: *from_anchor,
                    entries_removed: removed,
                    checkpoint: executor.checkpoint().await,
                });

                self.last_processed_anchor = from_anchor.saturating_sub(1);
            }
        }
        self.emit_finality_events(&finality_events);
    }

    /// Execute a decided batch, then flush the pending block if it's at the same height.
    pub async fn process_decided_batch(
        &mut self,
        executor: &mut impl Executor,
        bitcoin_state: &mut BitcoinState,
        anchor_height: u64,
        consensus_height: Height,
        batch_txs: &[bitcoin::Transaction],
    ) {
        executor.execute_batch(anchor_height, batch_txs).await;

        // If a block was buffered waiting for this batch, execute it now
        if let Some(block) = bitcoin_state.pending_block.take() {
            if block.height <= anchor_height {
                executor.execute_block(&block).await;
            } else {
                // Block is for a future height, put it back
                bitcoin_state.pending_block = Some(block);
            }
        }

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
                let value = state.make_value(bitcoin_state);
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
                            let value = Value::new(data.anchor_height, data.transactions.clone());
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

                state
                    .process_decided_batch(
                        executor,
                        bitcoin_state,
                        proposal.value.anchor_height,
                        certificate.height,
                        &proposal.value.transactions,
                    )
                    .await;

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
