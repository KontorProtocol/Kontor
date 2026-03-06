use std::collections::HashSet;

use tracing::{info, warn};

use crate::state_log::TxStatus;

use super::State;
use super::types::{FINALITY_WINDOW, FinalityEvent, PendingBatch, StateEvent};
use indexer::consensus::{Height, Value};

impl State {
    /// Record a decided batch for finality tracking.
    pub(super) fn record_decided_batch(&mut self, consensus_height: Height, value: &Value) {
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
    pub(super) fn record_confirmed_block(&mut self, height: u64, txids: &[[u8; 32]]) {
        for txid in txids {
            self.confirmed_txids.entry(*txid).or_insert(height);
        }
    }

    /// Check all pending batches whose deadline <= chain_tip.
    pub(super) fn check_finality(&mut self) -> Vec<FinalityEvent> {
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

    pub(super) fn emit_finality_events(&self, events: &[FinalityEvent]) {
        if let Some(tx) = &self.finality_tx {
            for event in events {
                let _ = tx.try_send(event.clone());
            }
        }
    }

    pub(super) fn emit_state_event(&self, event: StateEvent) {
        if let Some(tx) = &self.state_tx {
            let _ = tx.try_send(event);
        }
    }

    /// Run finality checks and execute any rollbacks.
    /// `replay_up_to` is the exclusive upper bound for block replay after rollback.
    pub(super) fn run_finality_checks(&mut self, replay_up_to: u64) {
        let finality_events = self.check_finality();
        for event in &finality_events {
            if let FinalityEvent::Rollback { from_anchor, .. } = event {
                let removed = self.rollback_state(*from_anchor);
                info!(
                    from_anchor,
                    removed, "Rollback executed: truncated state log"
                );

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
    pub(super) fn validate_transaction(&self, _txid: &[u8; 32]) -> bool {
        true
    }

    /// Simulator: append to state log. Production: run WASM contract, write to DB.
    pub(super) fn execute_transaction(
        &mut self,
        anchor_height: u64,
        txid: [u8; 32],
        status: TxStatus,
    ) {
        self.state_log.append_entry(anchor_height, txid, status);
    }

    /// Simulator: truncate state log. Production: DELETE FROM blocks WHERE height > ?.
    pub(super) fn rollback_state(&mut self, to_anchor: u64) -> usize {
        self.state_log.rollback_to(to_anchor)
    }

    // --- End extension points ---

    /// Two-phase processing triggered when a batch is decided at anchor A:
    /// 1. Drain pending blocks up to (not including) A as unbatched
    /// 2. Apply batch (first), then block A's unbatched txs (deduplicating)
    ///
    /// Finality checks run separately on BlockInsert, not here.
    pub(super) fn process_decided_batch(
        &mut self,
        anchor_height: u64,
        consensus_height: Height,
        batch_txids: &[[u8; 32]],
    ) {
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
}
