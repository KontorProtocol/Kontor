use std::collections::{BTreeMap, HashSet, VecDeque};

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
use sha3::Digest;

use crate::consensus::codec::{
    ProtobufCodec, decode_commit_certificate, encode_commit_certificate,
};
use crate::consensus::finality_types::*;
use crate::consensus::signing::Ed25519Provider;
use crate::consensus::{
    Address, BatchTx, Ctx, Genesis, Height, ProposalData, ProposalFin, ProposalInit, ProposalPart,
    ValidatorSet, Value,
};
use crate::database::queries::{
    get_checkpoint_latest, get_transaction_by_txid, insert_batch, insert_transaction,
    insert_unconfirmed_batch_tx, select_batch, select_batches_from_anchor, select_block_at_height,
    select_block_latest, select_existing_txids, select_min_batch_height,
    select_unconfirmed_batch_txs,
};

use super::ReactorCaches;
use super::executor::Executor;

/// Result from processing a consensus message.
pub enum ConsensusResult {
    /// No action needed by the reactor.
    None,
    /// A block was decided — the reactor should execute it.
    Block(indexer_types::Block, DeferredDecision),
    /// A batch was decided and executed — the reactor should emit a websocket event.
    BatchProcessed { txids: Vec<String> },
}

pub struct DeferredDecision {
    pub consensus_height: Height,
    pub value: Value,
    pub certificate: Vec<u8>,
}

/// All consensus-related state for the reactor.
pub struct ConsensusState {
    pub conn: libsql::Connection,
    pub signing_provider: Ed25519Provider,
    pub genesis: Genesis,
    pub address: Address,
    pub current_height: Height,
    pub current_round: Round,
    pub undecided: BTreeMap<(Height, Round), ProposedValue<Ctx>>,

    // Finality tracking
    pub pending_batches: Vec<PendingBatch>,

    // Decided values waiting for block data or anchor block processing.
    // Used during sync (decisions arrive before blocks from poller) and
    // rollback replay (decisions replayed from DB while blocks redeliver).
    pub deferred_decisions: VecDeque<DeferredDecision>,
    pub replay_excluded_txids: HashSet<Txid>,

    // Blocks received from the poller, keyed by height. Consumed when a
    // Value::Block decision is finalized.
    pub pending_blocks: BTreeMap<u64, indexer_types::Block>,

    // Cached validator set — updated after each block decision.
    // Used by height_params() to provide Malachite with the current set.
    pub cached_validator_set: ValidatorSet,

    // Observation channels (optional, for testing)
    pub observation: Option<ObservationChannels>,

    // Consensus timeouts — defaults to LinearTimeouts::default() (3s propose).
    pub timeouts: LinearTimeouts,
}

pub struct ObservationChannels {
    pub decided_tx: mpsc::Sender<DecidedBatch>,
    pub finality_tx: mpsc::Sender<FinalityEvent>,
    pub state_tx: mpsc::Sender<StateEvent>,
}

impl ConsensusState {
    pub fn new(
        conn: libsql::Connection,
        signing_provider: Ed25519Provider,
        genesis: Genesis,
        address: Address,
    ) -> Self {
        let cached_validator_set = genesis.validator_set.clone();
        Self {
            conn,
            signing_provider,
            genesis,
            address,
            current_height: Height::new(1),
            current_round: Round::new(0),
            undecided: BTreeMap::new(),
            pending_batches: Vec::new(),
            deferred_decisions: VecDeque::new(),
            replay_excluded_txids: HashSet::new(),
            pending_blocks: BTreeMap::new(),
            cached_validator_set,
            observation: None,
            timeouts: LinearTimeouts::default(),
        }
    }

    /// Clear consensus state that is invalidated by a reorg rollback.
    /// Pending blocks, cached blocks, and in-flight batch data are all stale.
    pub fn clear_on_rollback(&mut self) {
        self.pending_blocks.clear();
        self.deferred_decisions.clear();
        self.replay_excluded_txids.clear();
        self.pending_batches.clear();
    }

    fn validator_set(&self) -> ValidatorSet {
        self.cached_validator_set.clone()
    }

    fn height_params(&self) -> HeightParams<Ctx> {
        HeightParams::new(self.validator_set(), self.timeouts, None)
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
        let mut hasher = sha3::Keccak256::new();
        hasher.update(value.height.as_u64().to_be_bytes());
        hasher.update(value.round.as_i64().to_be_bytes());

        let data_part = match &value.value {
            Value::Batch {
                anchor_height,
                anchor_hash,
                txs,
                ..
            } => {
                hasher.update(anchor_height.to_be_bytes());
                hasher.update(anchor_hash.to_byte_array());
                for tx in txs {
                    hasher.update(tx.txid().to_byte_array());
                }
                ProposalData::new_batch(*anchor_height, *anchor_hash, value.value.batch_raw_txs())
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
        caches: &ReactorCaches,
        last_height: u64,
        last_hash: bitcoin::BlockHash,
    ) -> Option<Value> {
        // If blocks are pending, always propose the next one first
        if let Some((&height, block)) = self.pending_blocks.first_key_value() {
            return Some(Value::new_block(height, block.hash));
        }

        // Collect candidate txids from the mempool
        let mempool_txids: Vec<Txid> = caches.mempool.keys().copied().collect();

        // Filter out txids already in the system (batched or confirmed)
        let txid_strs: Vec<String> = mempool_txids.iter().map(|t| t.to_string()).collect();
        let existing = select_existing_txids(&self.conn, &txid_strs)
            .await
            .unwrap_or_default();
        let unbatched_set: HashSet<Txid> = mempool_txids
            .into_iter()
            .filter(|t| !existing.contains(&t.to_string()))
            .collect();

        let mut txs = Vec::new();
        for tx in caches.mempool.values() {
            let txid = tx.compute_txid();
            if !unbatched_set.contains(&txid) {
                continue;
            }
            if executor.validate_transaction(tx).await.is_some() {
                txs.push(tx.clone());
            }
        }
        // Don't propose empty batches — avoids flooding consensus heights
        // and allows lagging nodes to catch up via sync
        if txs.is_empty() {
            return None;
        }

        let value = Value::new_batch_raw(last_height, last_hash, txs);
        Some(value)
    }

    // --- Finality tracking ---

    pub async fn check_finality(&mut self, last_height: u64) -> Vec<FinalityEvent> {
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
                let confirmed = match get_transaction_by_txid(&self.conn, &txid.to_string()).await {
                    Ok(Some(row)) => row.confirmed_height.is_some(),
                    _ => false,
                };
                if !confirmed {
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

    pub async fn get_checkpoint(&self) -> Option<[u8; 32]> {
        match get_checkpoint_latest(&self.conn).await {
            Ok(Some(row)) => {
                if let Ok(decoded) = hex::decode(&row.hash)
                    && decoded.len() == 32
                {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&decoded);
                    return Some(bytes);
                }
                None
            }
            _ => None,
        }
    }

    async fn get_decided_from_anchor(&self, from_anchor: u64) -> Vec<DeferredDecision> {
        let batches = match select_batches_from_anchor(&self.conn, from_anchor as i64).await {
            Ok(r) => r,
            Err(e) => {
                error!(%e, "Failed to query batches from anchor");
                return Vec::new();
            }
        };

        batches
            .into_iter()
            .filter_map(|b| {
                let anchor_hash = b.anchor_hash.parse::<bitcoin::BlockHash>().ok()?;
                let value = if b.is_block {
                    Value::new_block(b.anchor_height as u64, anchor_hash)
                } else {
                    let txids: Vec<Txid> = b.txids.iter().filter_map(|s| s.parse().ok()).collect();
                    Value::new_batch(b.anchor_height as u64, anchor_hash, txids)
                };
                Some(DeferredDecision {
                    consensus_height: Height::new(b.consensus_height as u64),
                    value,
                    certificate: b.certificate,
                })
            })
            .collect()
    }

    pub async fn block_hash_at_height(&self, height: u64) -> Option<bitcoin::BlockHash> {
        match select_block_at_height(&self.conn, height as i64).await {
            Ok(Some(row)) => Some(row.hash),
            _ => None,
        }
    }

    async fn load_raw_txs_if_unfinalized(
        &self,
        anchor_height: i64,
        consensus_height: i64,
    ) -> Option<Vec<bitcoin::Transaction>> {
        let tip = select_block_latest(&self.conn).await.ok().flatten()?;
        if (anchor_height as u64) + FINALITY_WINDOW <= tip.height as u64 {
            return None;
        }
        let raw_bytes = select_unconfirmed_batch_txs(&self.conn, consensus_height)
            .await
            .ok()?;
        let txs: Vec<bitcoin::Transaction> = raw_bytes
            .iter()
            .filter_map(|raw| bitcoin::consensus::deserialize(raw).ok())
            .collect();
        if txs.is_empty() { None } else { Some(txs) }
    }

    async fn get_decided(
        &self,
        height: Height,
    ) -> Option<(Value, crate::consensus::CommitCertificate<Ctx>)> {
        let consensus_height = height.as_u64() as i64;
        let b = select_batch(&self.conn, consensus_height)
            .await
            .ok()
            .flatten()?;

        let anchor_hash = b.anchor_hash.parse::<bitcoin::BlockHash>().ok()?;

        let value = if b.is_block {
            Value::new_block(b.anchor_height as u64, anchor_hash)
        } else {
            let txids: Vec<Txid> = b.txids.iter().filter_map(|s| s.parse().ok()).collect();
            let raw_txs = self
                .load_raw_txs_if_unfinalized(b.anchor_height, consensus_height)
                .await;
            let mut v = Value::new_batch(b.anchor_height as u64, anchor_hash, txids);
            if let Some(raw_txs) = raw_txs {
                v.set_raw_txs(raw_txs);
            }
            v
        };

        let proto =
            crate::consensus::proto::CommitCertificate::decode(b.certificate.as_slice()).ok()?;
        let certificate = decode_commit_certificate(proto).ok()?;

        Some((value, certificate))
    }

    async fn min_decided_height(&self) -> Option<Height> {
        select_min_batch_height(&self.conn)
            .await
            .ok()
            .flatten()
            .map(|h| Height::new(h as u64))
    }

    /// Prepare consensus state for rollback: query decided batches for replay,
    /// populate the replay queue, and clear pending batches. Does NOT truncate the DB —
    /// that is handled by the reactor's `rollback()` method.
    pub async fn initiate_rollback(
        &mut self,
        executor: &mut impl Executor,
        from_anchor: u64,
        excluded_txids: HashSet<Txid>,
    ) {
        let replay_batches = self.get_decided_from_anchor(from_anchor).await;

        info!(
            from_anchor,
            replay_batches = replay_batches.len(),
            excluded = excluded_txids.len(),
            "Initiating rollback"
        );

        self.deferred_decisions = replay_batches.into();
        self.replay_excluded_txids = excluded_txids;
        self.pending_batches
            .retain(|b| b.anchor_height < from_anchor);

        executor.replay_blocks_from(from_anchor).await;
    }

    /// Pop the next replay batch, filtering out excluded txids.
    /// Returns None when the queue is empty (back to normal Malachite flow).
    pub fn next_deferred_decision(&mut self) -> Option<DeferredDecision> {
        if let Some(mut decision) = self.deferred_decisions.pop_front() {
            if !self.replay_excluded_txids.is_empty()
                && let Value::Batch { ref mut txs, .. } = decision.value
            {
                txs.retain(|tx| !self.replay_excluded_txids.contains(&tx.txid()));
            }
            return Some(decision);
        }
        // Queue drained — clear excluded set
        self.replay_excluded_txids.clear();
        None
    }

    /// Run finality checks. Returns (rollback_anchor, excluded_txids) if a rollback is needed.
    /// The reactor is responsible for DB truncation and calling `initiate_rollback`.
    pub async fn run_finality_checks(&mut self, last_height: u64) -> Option<(u64, HashSet<Txid>)> {
        let finality_events = self.check_finality(last_height).await;
        let mut result = None;
        for event in &finality_events {
            if let FinalityEvent::Rollback {
                from_anchor,
                missing_txids,
                ..
            } = event
            {
                let excluded: HashSet<Txid> = missing_txids.iter().copied().collect();
                result = Some((*from_anchor, excluded));
            }
        }
        self.emit_finality_events(&finality_events);
        result
    }

    /// Execute a decided batch. Blocks are executed separately via Value::Block
    pub async fn process_decided_batch(
        &mut self,
        executor: &impl Executor,
        runtime: &mut crate::runtime::Runtime,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        consensus_height: Height,
        certificate: &[u8],
        batch_txs: &[bitcoin::Transaction],
    ) {
        let parsed_txs: Vec<indexer_types::Transaction> = batch_txs
            .iter()
            .filter_map(|btx| executor.parse_transaction(btx))
            .collect();

        // Track for finality — must happen once per batch execution
        let txids: Vec<Txid> = batch_txs.iter().map(|tx| tx.compute_txid()).collect();
        self.pending_batches.push(PendingBatch {
            consensus_height,
            anchor_height,
            anchor_hash,
            txids,
            deadline: anchor_height + FINALITY_WINDOW,
        });

        runtime
            .storage
            .savepoint()
            .await
            .expect("Failed to begin batch transaction");

        insert_batch(
            &self.conn,
            consensus_height.as_u64() as i64,
            anchor_height as i64,
            &anchor_hash.to_string(),
            certificate,
            false,
        )
        .await
        .expect("Failed to insert batch");

        // Store raw txs for replay/sync recovery
        for raw_tx in batch_txs {
            let txid = raw_tx.compute_txid();
            let serialized = bitcoin::consensus::serialize(raw_tx);
            let _ = insert_unconfirmed_batch_tx(
                &self.conn,
                &txid.to_string(),
                consensus_height.as_u64() as i64,
                &serialized,
            )
            .await;
        }

        for t in &parsed_txs {
            let tx_id = match insert_transaction(
                &self.conn,
                indexer_types::TransactionRow::builder()
                    .height(anchor_height as i64)
                    .batch_height(consensus_height.as_u64() as i64)
                    .txid(t.txid.to_string())
                    .build(),
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    error!("insert_transaction error: {e}");
                    continue;
                }
            };

            executor
                .execute_transaction(runtime, anchor_height as i64, tx_id, t)
                .await;
        }

        runtime
            .storage
            .commit()
            .await
            .expect("Failed to commit batch transaction");


        self.emit_state_event(StateEvent::BatchApplied {
            consensus_height,
            anchor_height,
            txid_count: parsed_txs.len(),
            checkpoint: self.get_checkpoint().await,
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
    executor: &impl Executor,
    data: &ProposalData,
    height: Height,
    round: Round,
) -> Option<ProposedValue<Ctx>> {
    let value = match data {
        ProposalData::Block { height, hash } => {
            if let Some(block) = state.pending_blocks.get(height) {
                if block.hash != *hash {
                    warn!(
                        block_height = height,
                        proposed = %hash,
                        local = %block.hash,
                        "Rejecting block proposal: hash mismatch"
                    );
                    return None;
                }
            } else {
                warn!(
                    block_height = height,
                    "Rejecting block proposal: block not yet received"
                );
                return None;
            }
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
                if executor.validate_transaction(tx).await.is_none() {
                    warn!(
                        txid = %tx.compute_txid(),
                        "Rejecting proposal: transaction failed validation"
                    );
                    return None;
                }
            }
            Value::new_batch_raw(*anchor_height, *anchor_hash, transactions.clone())
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

/// Handle a consensus message. Returns `Some(block)` if a `Value::Block` was
/// decided and the block should be executed by the reactor via `handle_block`.
pub async fn handle_consensus_msg(
    state: &mut ConsensusState,
    executor: &impl Executor,
    runtime: &mut crate::runtime::Runtime,
    caches: &mut ReactorCaches,
    channels: &mut Channels<Ctx>,
    msg: AppMsg<Ctx>,
    validator_index: Option<usize>,
    last_height: u64,
    last_hash: bitcoin::BlockHash,
) -> Result<ConsensusResult> {
    let mut result = ConsensusResult::None;
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

            if let Some(existing) = state.undecided.get(&(height, round)) {
                let proposal = LocallyProposedValue::new(
                    existing.height,
                    existing.round,
                    existing.value.clone(),
                );
                for stream_msg in state.stream_proposal(&proposal, Round::Nil) {
                    channels
                        .network
                        .send(NetworkMsg::PublishProposalPart(stream_msg))
                        .await?;
                }
                if reply.send(proposal).is_err() {
                    error!("Failed to send GetValue reply");
                }
            } else if let Some(value) = state
                .make_value(executor, caches, last_height, last_hash)
                .await
            {
                let proposed = ProposedValue {
                    height,
                    round,
                    valid_round: Round::Nil,
                    proposer: state.address,
                    value: value.clone(),
                    validity: Validity::Valid,
                };
                state.undecided.insert((height, round), proposed);
                let proposal = LocallyProposedValue::new(height, round, value);
                for stream_msg in state.stream_proposal(&proposal, Round::Nil) {
                    channels
                        .network
                        .send(NetworkMsg::PublishProposalPart(stream_msg))
                        .await?;
                }
                if reply.send(proposal).is_err() {
                    error!("Failed to send GetValue reply");
                }
            } else {
                // Nothing to propose — drop reply so Malachite times out the round
                info!(%height, %round, "Nothing to propose, skipping round");
                drop(reply);
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
                                    if *anchor_height != last_height {
                                        warn!(
                                            anchor = anchor_height,
                                            tip = last_height,
                                            "Rejecting proposal with stale or unknown anchor height"
                                        );
                                        None
                                    } else if let Some(local_hash) =
                                        state.block_hash_at_height(*anchor_height).await
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
                        validator_index,
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
                        // Resolve full txs: Raw entries used directly (live path),
                        // Id entries resolved via executor (sync path for finalized batches).
                        let mut full_txs = Vec::new();
                        for entry in txs {
                            match entry {
                                BatchTx::Raw(tx) => full_txs.push(tx.clone()),
                                BatchTx::Id(txid) => {
                                    if let Some(tx) = executor.resolve_transaction(txid).await {
                                        full_txs.push(tx);
                                    }
                                }
                            }
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
                            // Still record the batch for sync protocol
                            let _ = insert_batch(
                                &state.conn,
                                certificate.height.as_u64() as i64,
                                *anchor_height as i64,
                                &anchor_hash.to_string(),
                                &cert_bytes,
                                false,
                            )
                            .await;
                        } else if *anchor_height > last_height {
                            info!(
                                anchor = anchor_height,
                                last_height,
                                consensus_height = %certificate.height,
                                "Deferring batch — anchor block not yet processed"
                            );
                            state.deferred_decisions.push_back(DeferredDecision {
                                consensus_height: certificate.height,
                                value: proposal.value.clone(),
                                certificate: cert_bytes,
                            });
                        } else {
                            state
                                .process_decided_batch(
                                    executor,
                                    runtime,
                                    *anchor_height,
                                    *anchor_hash,
                                    certificate.height,
                                    &cert_bytes,
                                    &full_txs,
                                )
                                .await;
                            result = ConsensusResult::BatchProcessed {
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

                        // Remove from pending if present (may not be if we received
                        // the decision via sync before the block arrived from poller)
                        if let Some(block) = state.pending_blocks.remove(height) {
                            result = ConsensusResult::Block(
                                block,
                                DeferredDecision {
                                    consensus_height: certificate.height,
                                    value: proposal.value.clone(),
                                    certificate: cert_bytes.clone(),
                                },
                            );
                        } else {
                            // Only defer if this block height is relevant (not stale from
                            // a pre-rollback decision that arrived late)
                            let is_stale =
                                match select_block_at_height(&state.conn, *height as i64).await {
                                    Ok(Some(row)) => row.hash != *hash,
                                    _ => false,
                                };
                            if !is_stale {
                                info!(
                                    block_height = height,
                                    block_hash = %hash,
                                    "Block decided but not yet received — deferring"
                                );
                                state.deferred_decisions.push_back(DeferredDecision {
                                    consensus_height: certificate.height,
                                    value: proposal.value.clone(),
                                    certificate: cert_bytes.clone(),
                                });
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

            state.current_height = certificate.height.increment();
            state.current_round = Round::Nil;

            let next = Next::Start(state.current_height, state.height_params());

            if reply.send(next).is_err() {
                error!("Failed to send Finalized reply");
            }
        }

        AppMsg::GetHistoryMinHeight { reply } => {
            let min = state.min_decided_height().await.unwrap_or(Height::new(1));
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
                if let Some((value, cert)) = state.get_decided(h).await
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
            // Malachite verifies the ValueId from the certificate matches
            // the decoded Value's id() — this catches any tampered raw txs
            // since id() hashes the txids derived from each BatchTx variant.
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

    Ok(result)
}
