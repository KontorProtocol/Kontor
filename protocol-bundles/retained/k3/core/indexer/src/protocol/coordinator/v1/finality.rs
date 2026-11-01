use bitcoin::Txid;
use tracing::{info, warn};

use crate::consensus::Height;
use crate::consensus::finality_types::{BatchExclusion, FinalityEvent, UnfinalizedBatch};

/// Decide what an at-deadline set means, given each batch's unconfirmed txids.
/// Returns the events to emit and the batches that stay tracked.
///
/// `at_deadline` must be sorted by `(anchor_height, consensus_height)` and
/// `missing_per_batch` index-aligned with it. Split out as a pure function so the
/// partition — the part that decides whether nodes converge — is testable without
/// a database or a live `ConsensusState`.
pub(crate) fn build_finality_events(
    at_deadline: &[UnfinalizedBatch],
    missing_per_batch: &[Vec<Txid>],
    still_pending: Vec<UnfinalizedBatch>,
) -> (Vec<FinalityEvent>, Vec<UnfinalizedBatch>) {
    debug_assert_eq!(at_deadline.len(), missing_per_batch.len());
    let mut events = Vec::new();

    let Some(first_fail) = missing_per_batch.iter().position(|m| !m.is_empty()) else {
        for batch in at_deadline {
            info!(
                consensus_height = %batch.consensus_height,
                anchor = batch.anchor_height,
                "Batch finalized"
            );
            events.push(FinalityEvent::BatchFinalized {
                consensus_height: batch.consensus_height,
                anchor_height: batch.anchor_height,
            });
        }
        return (events, still_pending);
    };

    // Only batches anchored strictly BELOW the first failure's anchor finalize.
    // Everything anchored at or above it is replayed by this same rollback — the
    // truncation goes to `from_anchor - 1` and the replay reloads every batch
    // anchored at or above `from_anchor` — so they are invalidated whether or not
    // their own txids confirmed. Finalizing one would announce a batch that is
    // about to be torn out, and dropping it from tracking silently left
    // convergence to an implicit replay invariant (#426). The boundary is the
    // ANCHOR, not the index: a passing batch can share the failing batch's anchor
    // at a lower consensus height, sorting ahead of it while being torn out all
    // the same. It replays in full — no missing txids, so no exclusion rows.
    let from_anchor = at_deadline[first_fail].anchor_height;
    let finalize_end = at_deadline[..first_fail].partition_point(|b| b.anchor_height < from_anchor);
    for batch in &at_deadline[..finalize_end] {
        info!(
            consensus_height = %batch.consensus_height,
            anchor = batch.anchor_height,
            "Batch finalized"
        );
        events.push(FinalityEvent::BatchFinalized {
            consensus_height: batch.consensus_height,
            anchor_height: batch.anchor_height,
        });
    }

    let mut invalidated: Vec<Height> = at_deadline[finalize_end..]
        .iter()
        .map(|b| b.consensus_height)
        .collect();

    // The exclusion set must cover every batch the rollback replays, not just the
    // first to fail: the replay reloads each one with its FULL certified content
    // (`batch_txids` is append-only and the exclusion filter is in-memory), so a
    // batch left out re-executes, re-arms the identical deadline, and rolls back
    // again with the complementary set — a cycle that never converges.
    // Per DECISION, not flattened. Flattening loses which batch each txid failed in,
    // and that attribution is exactly what keeps the recorded exclusion scoped to the
    // height it belongs to instead of becoming a global ban on the txid.
    let missing: Vec<BatchExclusion> = at_deadline[first_fail..]
        .iter()
        .zip(&missing_per_batch[first_fail..])
        .filter(|(_, txids)| !txids.is_empty())
        .map(|(batch, txids)| BatchExclusion {
            consensus_height: batch.consensus_height,
            anchor_height: batch.anchor_height,
            txids: txids.clone(),
        })
        .collect();

    let mut surviving = Vec::new();
    for pending in still_pending {
        if pending.anchor_height >= from_anchor {
            invalidated.push(pending.consensus_height);
        } else {
            surviving.push(pending);
        }
    }

    warn!(
        from_anchor,
        invalidated = ?invalidated,
        missing = missing.iter().map(|m| m.txids.len()).sum::<usize>(),
        "Cascade invalidation triggered"
    );

    events.push(FinalityEvent::Rollback {
        from_anchor,
        invalidated_batches: invalidated,
        missing,
    });

    (events, surviving)
}
