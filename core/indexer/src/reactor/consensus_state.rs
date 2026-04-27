use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::mempool_fee_index::MempoolFeeIndex;

use malachitebft_app_channel::Channels;
use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::core::Round;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_core_types::{HeightParams, LinearTimeouts};

use prost::Message;
use sha3::Digest;

use crate::consensus::codec::decode_commit_certificate;
use crate::consensus::finality_types::*;
use crate::consensus::signing::Ed25519Provider;
use crate::consensus::{
    Address, Ctx, Genesis, Height, ProposalData, ProposalFin, ProposalInit, ProposalPart,
    ValidatorSet, Value,
};
use crate::database::queries::{
    delete_batches_above_anchor, get_checkpoint_latest, get_transaction_by_txid,
    select_batches_from_anchor, select_batches_in_range, select_block_at_height,
    select_block_latest, select_existing_txids, select_latest_consensus_height,
    select_min_batch_height, select_unconfirmed_batch_txs,
};

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

/// A GetValue reply that we're holding until transactions arrive.
pub struct PendingProposal {
    pub height: Height,
    pub round: Round,
    pub reply: tokio::sync::oneshot::Sender<LocallyProposedValue<Ctx>>,
    pub timeout: Duration,
    pub created_at: Instant,
}

impl PendingProposal {
    /// Deadline at which we must propose (even an empty batch) before
    /// Malachite's propose timeout fires. Uses 80% of the propose timeout.
    pub fn hard_deadline(&self) -> Instant {
        self.created_at + self.timeout * 4 / 5
    }
}

/// All consensus-related state for the reactor.
pub struct ConsensusState {
    pub signing_provider: Ed25519Provider,
    pub address: Address,
    pub pending_transactions: HashMap<Txid, (bitcoin::Transaction, indexer_types::Transaction)>,
    /// Mempool-based fee estimator. Owned by ConsensusState; the reactor's
    /// mempool event loop mutates it directly, and `validate_transaction`
    /// borrows it via `&MempoolFeeIndex` from the call site.
    pub mempool_fee_index: MempoolFeeIndex,
    pub current_height: Height,
    pub current_round: Round,
    pub undecided: BTreeMap<(Height, Round), ProposedValue<Ctx>>,

    // Finality tracking
    pub unfinalized_batches: Vec<UnfinalizedBatch>,

    // Decided values waiting for block data or anchor block processing.
    // Used during sync (decisions arrive before blocks from poller) and
    // rollback replay (decisions replayed from DB while blocks redeliver).
    pub deferred_decisions: VecDeque<DeferredDecision>,

    // Blocks received from the poller, keyed by height. Consumed when a
    // Value::Block decision is finalized.
    pub pending_blocks: BTreeMap<u64, indexer_types::Block>,

    // Cached validator set — updated after each block decision.
    // Used by height_params() to provide Malachite with the current set.
    pub current_validator_set: ValidatorSet,

    // Observation channels (optional, for testing)
    pub observation: Option<ObservationChannels>,

    // Consensus timeouts — defaults to LinearTimeouts::default() (3s propose).
    pub timeouts: LinearTimeouts,

    // Held GetValue reply — waiting for pending_transactions to arrive.
    pub pending_proposal: Option<PendingProposal>,

    // Malachite engine channels and handle.
    pub channels: Channels<Ctx>,
    pub engine_handle: malachitebft_app_channel::EngineHandle,
    pub validator_index: Option<usize>,
}

pub struct ObservationChannels {
    pub decided_tx: mpsc::Sender<DecidedBatch>,
    pub finality_tx: mpsc::Sender<FinalityEvent>,
    pub state_tx: mpsc::Sender<StateEvent>,
}

impl ConsensusState {
    pub async fn new(
        conn: turso::Connection,
        signing_provider: Ed25519Provider,
        genesis: Genesis,
        address: Address,
        last_block_height: u64,
        channels: Channels<Ctx>,
        engine_handle: malachitebft_app_channel::EngineHandle,
        validator_index: Option<usize>,
        mempool_fee_index: MempoolFeeIndex,
    ) -> Self {
        let current_validator_set = genesis.validator_set;

        // Delete batch decisions that reference anchor heights above what we've
        // actually processed. These were committed to the batches table but never
        // executed before the node shut down.
        if let Ok(deleted) = delete_batches_above_anchor(&conn, last_block_height as i64).await
            && deleted > 0
        {
            info!(
                deleted,
                last_block_height, "Deleted unprocessed batches above last block height"
            );
        }

        let current_height = match select_latest_consensus_height(&conn).await {
            Ok(Some(h)) => {
                let resume = Height::new(h as u64 + 1);
                info!(%resume, "Resuming consensus from DB");
                resume
            }
            _ => Height::new(1),
        };
        Self {
            signing_provider,
            address,
            pending_transactions: std::collections::HashMap::new(),
            mempool_fee_index,
            current_height,
            current_round: Round::new(0),
            undecided: BTreeMap::new(),
            unfinalized_batches: Vec::new(),
            deferred_decisions: VecDeque::new(),
            pending_blocks: BTreeMap::new(),
            current_validator_set,
            observation: None,
            timeouts: LinearTimeouts::default(),
            pending_proposal: None,
            channels,
            engine_handle,
            validator_index,
        }
    }

    /// Clear consensus state that is invalidated by a reorg rollback.
    /// Pending blocks, cached blocks, and in-flight batch data are all stale.
    pub fn clear_on_rollback(&mut self) {
        self.pending_blocks.clear();
        self.deferred_decisions.clear();
        self.unfinalized_batches.clear();
        self.pending_proposal = None;
    }

    fn validator_set(&self) -> ValidatorSet {
        self.current_validator_set.clone()
    }

    pub(super) fn height_params(&self) -> HeightParams<Ctx> {
        HeightParams::new(self.validator_set(), self.timeouts, None)
    }

    fn stream_id(&self) -> StreamId {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.current_height.as_u64().to_be_bytes());
        bytes.extend_from_slice(
            &self
                .current_round
                .as_u32()
                .expect("stream_id called during active round, current_round must not be Nil")
                .to_be_bytes(),
        );
        StreamId::new(bytes.into())
    }

    pub(super) fn stream_proposal(
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

    // --- Finality tracking ---

    pub async fn check_finality(
        &mut self,
        conn: &turso::Connection,
        last_height: u64,
    ) -> Vec<FinalityEvent> {
        let mut events = Vec::new();
        let tip = last_height;

        let mut still_pending = Vec::new();
        let mut at_deadline = Vec::new();

        for batch in self.unfinalized_batches.drain(..) {
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
                let confirmed = match get_transaction_by_txid(conn, &txid.to_string()).await {
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

        self.unfinalized_batches = still_pending;
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

    pub async fn get_checkpoint(&self, conn: &turso::Connection) -> Option<[u8; 32]> {
        match get_checkpoint_latest(conn).await {
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

    pub(super) async fn get_decided_from_anchor(
        &self,
        conn: &turso::Connection,
        from_anchor: u64,
    ) -> Result<Vec<DeferredDecision>> {
        let batches = select_batches_from_anchor(conn, from_anchor as i64)
            .await
            .context("Failed to query batches from anchor")?;

        batches
            .into_iter()
            .map(|b| {
                let anchor_hash = b
                    .anchor_hash
                    .parse::<bitcoin::BlockHash>()
                    .context("Failed to parse anchor hash from DB")?;
                let value = if b.is_block {
                    Value::new_block(b.anchor_height as u64, anchor_hash)
                } else {
                    let txids: Vec<Txid> = b
                        .txids
                        .iter()
                        .map(|s| s.parse().context("Failed to parse txid from DB"))
                        .collect::<Result<Vec<_>>>()?;
                    Value::new_batch(b.anchor_height as u64, anchor_hash, txids)
                };
                Ok(DeferredDecision {
                    consensus_height: Height::new(b.consensus_height as u64),
                    value,
                    certificate: b.certificate,
                })
            })
            .collect()
    }

    pub async fn block_hash_at_height(
        &self,
        conn: &turso::Connection,
        height: u64,
    ) -> Option<bitcoin::BlockHash> {
        match select_block_at_height(conn, height as i64).await {
            Ok(Some(row)) => Some(row.hash),
            _ => None,
        }
    }

    async fn load_raw_txs_if_unfinalized(
        &self,
        conn: &turso::Connection,
        anchor_height: i64,
        consensus_height: i64,
    ) -> Result<Option<Vec<bitcoin::Transaction>>> {
        let tip = match select_block_latest(conn)
            .await
            .context("Failed to query latest block for finality check")?
        {
            Some(tip) => tip,
            None => return Ok(None),
        };
        if (anchor_height as u64) + FINALITY_WINDOW <= tip.height as u64 {
            return Ok(None);
        }
        let raw_bytes = select_unconfirmed_batch_txs(conn, consensus_height)
            .await
            .context("Failed to query unconfirmed batch txs")?;
        let txs: Vec<bitcoin::Transaction> = raw_bytes
            .iter()
            .map(|raw| {
                bitcoin::consensus::deserialize(raw)
                    .context("Failed to deserialize batch tx from DB")
            })
            .collect::<Result<Vec<_>>>()?;
        if txs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(txs))
        }
    }

    fn batch_to_decided(
        &self,
        b: &crate::database::types::BatchQueryResult,
    ) -> Result<(Value, crate::consensus::CommitCertificate<Ctx>)> {
        let anchor_hash = b
            .anchor_hash
            .parse::<bitcoin::BlockHash>()
            .context("Failed to parse anchor hash from DB")?;

        let value = if b.is_block {
            Value::new_block(b.anchor_height as u64, anchor_hash)
        } else {
            let txids: Vec<Txid> = b
                .txids
                .iter()
                .map(|s| s.parse().context("Failed to parse txid from DB"))
                .collect::<Result<Vec<_>>>()?;
            Value::new_batch(b.anchor_height as u64, anchor_hash, txids)
        };

        let proto = crate::consensus::proto::CommitCertificate::decode(b.certificate.as_slice())
            .context("Failed to decode commit certificate protobuf")?;
        let certificate =
            decode_commit_certificate(proto).context("Failed to decode commit certificate")?;

        Ok((value, certificate))
    }

    pub(super) async fn get_decided_range(
        &self,
        conn: &turso::Connection,
        start: Height,
        end: Height,
    ) -> Result<Vec<(Value, crate::consensus::CommitCertificate<Ctx>)>> {
        let batches = select_batches_in_range(conn, start.as_u64() as i64, end.as_u64() as i64)
            .await
            .context("Failed to query batches for sync range")?;

        let mut results = Vec::new();
        for b in &batches {
            let (mut value, cert) = self.batch_to_decided(b)?;

            if !b.is_block
                && let Some(raw_txs) = self
                    .load_raw_txs_if_unfinalized(conn, b.anchor_height, b.consensus_height)
                    .await?
            {
                value.set_raw_txs(raw_txs);
            }

            results.push((value, cert));
        }
        Ok(results)
    }

    pub(super) async fn min_decided_height(
        &self,
        conn: &turso::Connection,
    ) -> Result<Option<Height>> {
        Ok(select_min_batch_height(conn)
            .await
            .context("Failed to query min batch height")?
            .map(|h| Height::new(h as u64)))
    }

    /// Run finality checks. Returns (rollback_anchor, excluded_txids) if a rollback is needed.
    /// The reactor is responsible for DB truncation and calling `initiate_rollback`.
    pub async fn run_finality_checks(
        &mut self,
        conn: &turso::Connection,
        last_height: u64,
    ) -> Option<(u64, HashSet<Txid>)> {
        let finality_events = self.check_finality(conn, last_height).await;
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

    /// Validate batch-level rules. Returns a rejection reason if any rule fails.
    pub(super) async fn validate_batch(
        &self,
        conn: &turso::Connection,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        txids: &[String],
        last_height: u64,
        last_hash: bitcoin::BlockHash,
    ) -> Result<Option<&'static str>> {
        if !self.pending_blocks.is_empty() {
            return Ok(Some("block is pending"));
        }
        if self.deferred_decisions.iter().any(|d| d.value.is_block()) {
            return Ok(Some("deferred block decision waiting"));
        }
        if anchor_height != last_height {
            return Ok(Some("anchor height mismatch"));
        }
        if anchor_hash != last_hash {
            return Ok(Some("anchor hash mismatch"));
        }
        let existing = select_existing_txids(conn, txids)
            .await
            .context("Failed to query existing txids")?;
        if !existing.is_empty() {
            return Ok(Some("contains already-processed transactions"));
        }
        Ok(None)
    }
}
