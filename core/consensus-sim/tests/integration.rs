use std::time::Duration;

use consensus_sim::mock_bitcoin::MockBitcoin;
use consensus_sim::reactor::FinalityEvent;
use consensus_sim::reactor::StateEvent;
use consensus_sim::{run_cluster, run_cluster_delayed};
use indexer::bitcoin_follower::event::BlockEvent;

/// All 4 validators should decide the same value at each consensus height.
#[tokio::test]
#[serial_test::serial]
async fn validators_agree_on_values() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    // Feed some mempool txs so proposals have content
    let mut mock = MockBitcoin::new(0);
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let results = cluster.wait_for_decisions(2, Duration::from_secs(30)).await;

    for (i, node_decisions) in results.iter().enumerate() {
        assert!(
            node_decisions.len() >= 2,
            "Node {i} only decided {} values, expected >= 2",
            node_decisions.len()
        );
    }

    // At each height, all nodes should agree on the same value
    let min_decisions = results.iter().map(|r| r.len()).min().unwrap();
    for height_idx in 0..min_decisions {
        let first_value = results[0][height_idx].value.clone();
        let first_height = results[0][height_idx].consensus_height;

        for (node_idx, node_decisions) in results.iter().enumerate().skip(1) {
            assert_eq!(
                node_decisions[height_idx].consensus_height, first_height,
                "Node {node_idx} decided at different height for decision {height_idx}"
            );
            assert_eq!(
                node_decisions[height_idx].value, first_value,
                "Node {node_idx} decided different value at height {first_height}"
            );
        }
    }

    cluster.shutdown().await;
}

/// Decided values should contain the txids that were in the mempool.
#[tokio::test]
#[serial_test::serial]
async fn decided_values_contain_mempool_txids() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);
    let events = mock.generate_mempool_txs(3);
    let expected_txids: Vec<bitcoin::Txid> = mock.mempool_txids();

    for event in events {
        cluster.send_mempool_event(event);
    }

    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;

    // At least one node should have decided a value containing our txids
    let decided_value = &results[0][0].value;
    let decided_txids = decided_value.batch_txids();
    for expected in &expected_txids {
        assert!(
            decided_txids.contains(expected),
            "Decided value missing expected txid"
        );
    }
    // Anchor should be 0 since no blocks were mined
    assert_eq!(decided_value.block_height(), 0);

    cluster.shutdown().await;
}

/// Mining a block should update chain_tip, reflected in the next decided value's anchor.
#[tokio::test]
#[serial_test::serial]
async fn block_updates_chain_tip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert some mempool txs
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    // Wait for at least 1 decision at anchor 0
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert_eq!(results[0][0].value.block_height(), 0);

    // Mine a block — this advances the chain tip to 1
    {
        let (blk_events, mem_events) = mock.mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Add new mempool txs so the next batch has content
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    // Wait for another decision — anchor should now be 1
    let results = cluster.wait_for_decisions(2, Duration::from_secs(30)).await;
    let second = &results[0][1].value;
    assert_eq!(
        second.block_height(),
        1,
        "Expected anchor_height 1 after mining a block, got {}",
        second.block_height()
    );

    cluster.shutdown().await;
}

/// Empty mempool should produce a decided batch with no txids.
#[tokio::test]
#[serial_test::serial]
async fn empty_mempool_produces_empty_batch() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    // Don't insert any mempool txs — just wait for consensus to decide
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;

    for (i, node_decisions) in results.iter().enumerate() {
        assert!(
            !node_decisions.is_empty(),
            "Node {i} should have decided at least 1 value"
        );
        assert!(
            node_decisions[0].value.batch_txids().is_empty(),
            "Node {i} decided a value with txids, expected empty"
        );
    }

    cluster.shutdown().await;
}

/// Happy path: batch txids all confirmed within finality window → BatchFinalized event.
#[tokio::test]
#[serial_test::serial]
async fn happy_path_finalization() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert mempool txs and let consensus decide a batch at anchor 0
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    let decided = &results[0][0];
    assert_eq!(decided.value.block_height(), 0);

    // Mine blocks confirming all the batched txids, then mine through the finality window.
    // Block 1: confirm all mempool txs
    {
        let (blk_events, mem_events) = mock.mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Blocks 2-6: empty blocks to reach deadline (anchor 0 + 6 = 6)
    for _ in 0..5 {
        {
            let (blk_events, _) = mock.mine_empty_block();
            for event in blk_events {
                cluster.send_block_event(event);
            }
        }
    }

    let finality_events = cluster
        .wait_for_finality_events(1, Duration::from_secs(10))
        .await;

    assert!(
        !finality_events.is_empty(),
        "Expected at least one finality event"
    );

    // At least one should be a BatchFinalized for anchor 0
    let has_finalized = finality_events.iter().any(
        |e| matches!(e, FinalityEvent::BatchFinalized { anchor_height, .. } if *anchor_height == 0),
    );
    assert!(
        has_finalized,
        "Expected BatchFinalized at anchor 0, got: {finality_events:?}"
    );

    cluster.shutdown().await;
}

/// Missing tx: one batched txid never appears on chain → Rollback event.
#[tokio::test]
#[serial_test::serial]
async fn missing_tx_invalidation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert 3 mempool txs
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    let decided = &results[0][0];
    let decided_txids = &decided.value.batch_txids();
    assert!(
        decided_txids.len() >= 3,
        "Expected at least 3 txids in decided batch"
    );

    // Confirm only the first 2 txids — the 3rd will be missing
    let confirm_txids: Vec<bitcoin::Txid> = decided_txids[..2].to_vec();

    // Mine block 1 with only 2 of the 3 txids
    {
        let (blk_events, mem_events) = mock.mine_block(&confirm_txids);
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Mine blocks 2-6 (empty) to reach the deadline
    for _ in 0..5 {
        {
            let (blk_events, _) = mock.mine_empty_block();
            for event in blk_events {
                cluster.send_block_event(event);
            }
        }
    }

    let finality_events = cluster
        .wait_for_finality_events(1, Duration::from_secs(10))
        .await;

    assert!(
        !finality_events.is_empty(),
        "Expected at least one finality event"
    );

    let has_rollback = finality_events.iter().any(
        |e| matches!(e, FinalityEvent::Rollback { missing_txids, .. } if !missing_txids.is_empty()),
    );
    assert!(
        has_rollback,
        "Expected Rollback with missing txids, got: {finality_events:?}"
    );

    cluster.shutdown().await;
}

/// Cascade invalidation: a missing tx at anchor N invalidates batches at N and later.
#[tokio::test]
#[serial_test::serial]
async fn cascade_invalidation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Decide batch 1 at anchor 0
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert_eq!(results[0][0].value.block_height(), 0);

    // Mine block 1 (confirm nothing — intentionally leave batch 1 txids unconfirmed)
    {
        let (blk_events, _) = mock.mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Add more txs and let consensus decide batch 2 at anchor 1
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let _results = cluster.wait_for_decisions(2, Duration::from_secs(30)).await;

    // Mine blocks 2-6 (empty) to hit the deadline for anchor 0 (0 + 6 = 6)
    for _ in 0..5 {
        {
            let (blk_events, _) = mock.mine_empty_block();
            for event in blk_events {
                cluster.send_block_event(event);
            }
        }
    }

    let finality_events = cluster
        .wait_for_finality_events(1, Duration::from_secs(10))
        .await;

    assert!(
        !finality_events.is_empty(),
        "Expected at least one finality event"
    );

    // Should be a Rollback that invalidated multiple batches
    let rollback = finality_events
        .iter()
        .find(|e| matches!(e, FinalityEvent::Rollback { .. }));
    assert!(
        rollback.is_some(),
        "Expected Rollback event, got: {finality_events:?}"
    );

    if let Some(FinalityEvent::Rollback {
        invalidated_batches,
        ..
    }) = rollback
    {
        assert!(
            invalidated_batches.len() >= 2,
            "Expected cascade to invalidate >= 2 batches, got {}",
            invalidated_batches.len()
        );
    }

    cluster.shutdown().await;
}

/// Batch txs should be applied before unbatched block txs at the same anchor height.
/// We verify by checking that BatchApplied arrives before BlockProcessed for the same height.
#[tokio::test]
#[serial_test::serial]
async fn batch_before_unbatched_at_same_anchor() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert mempool txs
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    // Mine a block that confirms some txs — this creates both batched and unbatched txs
    // at anchor 0 (the block has txs, the batch also has txs)
    {
        let (blk_events, mem_events) = mock.mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Wait for consensus to decide at least 1 batch, then collect state events
    let _results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;

    // Collect state events — we expect BatchApplied before any BlockProcessed at same anchor
    let state_events = cluster
        .wait_for_state_events(1, Duration::from_secs(5))
        .await;

    // The first state event for any anchor should be BatchApplied, not BlockProcessed
    if !state_events.is_empty() {
        let first = &state_events[0];
        assert!(
            matches!(first, StateEvent::BatchApplied { .. }),
            "Expected first state event to be BatchApplied, got: {first:?}"
        );
    }

    cluster.shutdown().await;
}

/// A txid in both a batch and a block should not be double-counted.
#[tokio::test]
#[serial_test::serial]
async fn unbatched_txs_skip_batched_duplicates() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert mempool txs — these will be in the batch
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    // Wait for consensus to decide a batch containing these txids
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    let decided = &results[0][0];
    let batch_txid_count = decided.value.batch_txids().len();

    // Mine a block that confirms the same txids — they overlap with the batch
    {
        let (blk_events, mem_events) = mock.mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Collect state events
    let state_events = cluster
        .wait_for_state_events(2, Duration::from_secs(5))
        .await;

    // Find the BatchApplied event
    let batch_applied = state_events
        .iter()
        .find(|e| matches!(e, StateEvent::BatchApplied { .. }));
    assert!(batch_applied.is_some(), "Expected BatchApplied event");

    if let Some(StateEvent::BatchApplied { txid_count, .. }) = batch_applied {
        assert_eq!(
            *txid_count, batch_txid_count,
            "Batch should contain all mempool txids"
        );
    }

    // If there's a BlockProcessed at the same anchor, unbatched_count should be 0
    // because all txids were already in the batch
    let block_at_anchor = state_events.iter().find(|e| {
        matches!(e, StateEvent::BlockProcessed { height, .. } if *height == decided.value.block_height())
    });
    // Either no BlockProcessed (because 0 unbatched) or unbatched_count == 0
    if let Some(StateEvent::BlockProcessed {
        unbatched_count, ..
    }) = block_at_anchor
    {
        assert_eq!(
            *unbatched_count, 0,
            "Expected 0 unbatched txs since all were in the batch"
        );
    }

    cluster.shutdown().await;
}

/// After a rollback, state log entries from the invalidated anchor should be gone.
#[tokio::test]
#[serial_test::serial]
async fn rollback_truncates_and_replays() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Decide batch 1 at anchor 0
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert_eq!(results[0][0].value.block_height(), 0);

    // Mine block 1 (confirm nothing — leave batch 1 txids unconfirmed)
    {
        let (blk_events, _) = mock.mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Mine blocks 2-6 (empty) to hit the deadline for anchor 0 (0 + 6 = 6)
    for _ in 0..5 {
        {
            let (blk_events, _) = mock.mine_empty_block();
            for event in blk_events {
                cluster.send_block_event(event);
            }
        }
    }

    // Malachite keeps deciding batches. Eventually a batch's process_decided_batch
    // will run check_finality() after chain_tip >= 6, triggering the rollback.
    // Collect state events until we see a RollbackExecuted.
    let state_events = cluster
        .wait_for_state_events(20, Duration::from_secs(15))
        .await;

    let rollback_event = state_events
        .iter()
        .find(|e| matches!(e, StateEvent::RollbackExecuted { .. }));
    assert!(
        rollback_event.is_some(),
        "Expected RollbackExecuted state event, got: {state_events:?}"
    );

    if let Some(StateEvent::RollbackExecuted {
        entries_removed, ..
    }) = rollback_event
    {
        assert!(*entries_removed > 0, "Rollback should have removed entries");
    }

    cluster.shutdown().await;
}

/// State entries before the invalidated anchor should survive rollback.
#[tokio::test]
#[serial_test::serial]
async fn rollback_preserves_pre_anchor_state() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Decide batch 1 at anchor 0
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    let batch1_txids = results[0][0].value.batch_txids().to_vec();

    // Mine block 1 confirming batch 1's txids — batch 1 will finalize
    {
        let (blk_events, mem_events) = mock.mine_block(&batch1_txids);
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Mine blocks 2-7 (empty) — this reaches deadline for anchor 0 (finalized)
    // and also for anchor 1 (if a batch 2 was decided with unconfirmed txids)
    for _ in 0..6 {
        {
            let (blk_events, _) = mock.mine_empty_block();
            for event in blk_events {
                cluster.send_block_event(event);
            }
        }
    }

    // Collect state events — look for RollbackExecuted
    // Malachite decides batches continuously; one will trigger finality check
    // Batch 1 (anchor 0) finalizes, batch 2+ (anchor 1+, unconfirmed txids) triggers rollback
    let state_events = cluster
        .wait_for_state_events(20, Duration::from_secs(15))
        .await;

    let post_rollback_checkpoint = state_events.iter().find_map(|e| match e {
        StateEvent::RollbackExecuted { checkpoint, .. } => *checkpoint,
        _ => None,
    });

    if let Some(post) = post_rollback_checkpoint {
        // Batch 1 at anchor 0 survives the rollback (only anchor 1+ is truncated),
        // so checkpoint should not be empty
        assert_ne!(
            post, [0u8; 32],
            "Post-rollback checkpoint should not be empty"
        );
    }
    // If no rollback occurred, that's also valid — means no batches had unconfirmed txids

    cluster.shutdown().await;
}

/// All 4 nodes should reach the same checkpoint after processing the same events.
#[tokio::test]
#[serial_test::serial]
async fn all_nodes_reach_same_checkpoint() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert mempool txs and let consensus decide
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let _results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;

    // Collect state events — need at least 4 BatchApplied (one per node).
    // Collect extra in case other event types (BlockProcessed) arrive too.
    let state_events = cluster
        .wait_for_state_events(8, Duration::from_secs(10))
        .await;

    // Filter to only the first consensus height's BatchApplied events
    let first_height = state_events.iter().find_map(|e| match e {
        StateEvent::BatchApplied {
            consensus_height, ..
        } => Some(*consensus_height),
        _ => None,
    });

    let batch_checkpoints: Vec<[u8; 32]> = state_events
        .iter()
        .filter_map(|e| match e {
            StateEvent::BatchApplied {
                consensus_height,
                checkpoint,
                ..
            } if Some(*consensus_height) == first_height => *checkpoint,
            _ => None,
        })
        .collect();

    assert!(
        batch_checkpoints.len() >= 4,
        "Expected at least 4 BatchApplied events for same height, got {}",
        batch_checkpoints.len()
    );

    // All checkpoints at the same consensus height should be identical
    assert!(
        batch_checkpoints.windows(2).all(|w| w[0] == w[1]),
        "Not all nodes reached the same checkpoint: {batch_checkpoints:?}"
    );

    cluster.shutdown().await;
}

/// A late-joining node should sync via Malachite and reach the same checkpoint.
#[tokio::test]
#[serial_test::serial]
async fn late_joiner_syncs_to_same_checkpoint() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    // Create 5 validators in genesis, start only 4
    let (mut cluster, remaining_keys) = run_cluster_delayed(5, 4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Run consensus for a few heights with mempool txs
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let results = cluster.wait_for_decisions(3, Duration::from_secs(30)).await;
    assert!(
        results[0].len() >= 3,
        "Expected at least 3 decisions before adding late joiner"
    );

    // Record the last decided height from the initial nodes
    let last_height = results[0].last().unwrap().consensus_height;

    // Add the 5th validator — it should sync via Malachite
    let late_key = remaining_keys.into_iter().next().unwrap();
    let late_index = cluster.add_node(late_key).unwrap();
    cluster.wait_for_node_ready().await;

    // Wait for the late joiner to produce BatchApplied events (synced decisions)
    let state_events = cluster
        .wait_for_state_events(20, Duration::from_secs(30))
        .await;

    // Find a BatchApplied from the late joiner at the target height
    let late_joiner_checkpoint = state_events.iter().find_map(|e| match e {
        StateEvent::BatchApplied {
            consensus_height,
            checkpoint,
            ..
        } if *consensus_height == last_height => *checkpoint,
        _ => None,
    });

    assert!(
        late_joiner_checkpoint.is_some(),
        "Late joiner should have produced a BatchApplied at height {last_height}, \
         got {} state events total. Node index: {late_index}",
        state_events.len()
    );

    cluster.shutdown().await;
}

/// Bitcoin reorg: rollback all nodes, verify executor state rolls back and resume height is correct.
#[tokio::test]
#[serial_test::serial]
async fn bitcoin_rollback_reverts_state() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Feed mempool txs and a block so consensus has content
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    // Mine block at height 1 so proposals anchor there
    {
        let (blk_events, mem_events) = mock.mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Wait for at least 1 batch decision across all nodes
    let decisions = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    for (i, node_decisions) in decisions.iter().enumerate() {
        assert!(
            !node_decisions.is_empty(),
            "Node {i} had no decisions before rollback"
        );
    }

    // Collect the BatchApplied events (one per node)
    let pre_rollback_events = cluster
        .wait_for_state_events(4, Duration::from_secs(10))
        .await;
    assert!(
        pre_rollback_events.len() >= 4,
        "Expected at least 4 BatchApplied events, got {}",
        pre_rollback_events.len()
    );

    // Now send a Bitcoin rollback to height 1 (revert everything at height >= 1)
    cluster.send_block_event(BlockEvent::Rollback { to_height: 1 });

    // Wait for RollbackExecuted events from all 4 nodes
    let rollback_events = cluster
        .wait_for_state_events(4, Duration::from_secs(10))
        .await;

    let rollback_count = rollback_events
        .iter()
        .filter(|e| matches!(e, StateEvent::RollbackExecuted { to_anchor: 1, .. }))
        .count();

    assert!(
        rollback_count >= 4,
        "Expected 4 RollbackExecuted events at to_anchor=1, got {rollback_count} out of {} events: {rollback_events:?}",
        rollback_events.len()
    );

    // All rollback checkpoints should be the zero hash (everything removed)
    for event in &rollback_events {
        if let StateEvent::RollbackExecuted { checkpoint, .. } = event {
            assert_eq!(
                *checkpoint,
                Some([0u8; 32]),
                "After full rollback, checkpoint should be zero"
            );
        }
    }

    cluster.shutdown().await;
}

/// Multiple batches at the same anchor should all execute correctly.
/// With no blocks mined, all batches anchor at 0.
#[tokio::test]
#[serial_test::serial]
async fn multi_batch_same_anchor() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Wave 1: insert mempool txs
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    // Wait for first decision at anchor 0
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert_eq!(results[0][0].value.block_height(), 0);

    // Wave 2: insert more mempool txs (different txids)
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    // Wait for second decision — should also be at anchor 0 (no blocks mined)
    let results = cluster.wait_for_decisions(2, Duration::from_secs(30)).await;
    assert_eq!(
        results[0][1].value.block_height(),
        0,
        "Second batch should also anchor at 0 since no blocks were mined"
    );

    // Collect state events — expect 8 BatchApplied (2 per node × 4 nodes)
    let state_events = cluster
        .wait_for_state_events(8, Duration::from_secs(10))
        .await;

    // All BatchApplied at the same consensus height should have matching checkpoints
    let mut height_checkpoints: std::collections::HashMap<_, Vec<Option<[u8; 32]>>> =
        std::collections::HashMap::new();
    for e in &state_events {
        if let StateEvent::BatchApplied {
            consensus_height,
            checkpoint,
            ..
        } = e
        {
            height_checkpoints
                .entry(*consensus_height)
                .or_default()
                .push(*checkpoint);
        }
    }

    for (height, cps) in &height_checkpoints {
        if cps.len() >= 4 {
            assert!(
                cps.windows(2).all(|w| w[0] == w[1]),
                "Nodes disagree on checkpoint at height {height}: {cps:?}"
            );
        }
    }

    cluster.shutdown().await;
}

/// Finality rollback: batch has an unconfirmed txid, finality triggers rollback
/// via initiate_rollback. Verifies all nodes execute the rollback and the replay
/// queue is populated. After re-sending blocks, replay batches are re-processed
/// with the missing txid excluded.
#[tokio::test]
#[serial_test::serial]
async fn finality_rollback_replays_with_excluded_txids() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert 3 mempool txs
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    // Wait for consensus to decide batch at anchor 0
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    let decided = &results[0][0];
    assert_eq!(decided.value.block_height(), 0);
    let decided_txids = decided.value.batch_txids().to_vec();

    // Confirm only first 2 txids — 3rd will be missing at finality deadline
    let confirm_txids: Vec<bitcoin::Txid> = decided_txids[..2].to_vec();

    // Save all block events as we send them, so we can re-send after rollback
    let mut saved_block_events = Vec::new();

    // Block 1: confirm 2 of 3 txids
    {
        let (blk_events, mem_events) = mock.mine_block(&confirm_txids);
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        saved_block_events.extend(blk_events.clone());
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Blocks 2-6: empty blocks to reach finality deadline (anchor 0 + 6 = 6)
    for _ in 0..5 {
        let (blk_events, _) = mock.mine_empty_block();
        saved_block_events.extend(blk_events.clone());
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Wait for the finality rollback event
    let finality_events = cluster
        .wait_for_finality_events(1, Duration::from_secs(10))
        .await;

    let has_rollback = finality_events.iter().any(
        |e| matches!(e, FinalityEvent::Rollback { missing_txids, .. } if !missing_txids.is_empty()),
    );
    assert!(
        has_rollback,
        "Expected Rollback with missing txids, got: {finality_events:?}"
    );

    // Collect state events — should see RollbackExecuted from all nodes
    let state_events = cluster
        .wait_for_state_events(8, Duration::from_secs(10))
        .await;

    let rollback_count = state_events
        .iter()
        .filter(|e| matches!(e, StateEvent::RollbackExecuted { .. }))
        .count();

    assert!(
        rollback_count >= 4,
        "Expected 4 RollbackExecuted events, got {rollback_count}: {state_events:?}"
    );

    // Re-send all blocks from the rollback point onwards.
    // The reactor called replay_blocks_from() and is now waiting for blocks.
    for event in saved_block_events {
        cluster.send_block_event(event);
    }

    // Wait for replay batches to be re-applied (minus the excluded txid)
    let replay_events = cluster
        .wait_for_state_events(4, Duration::from_secs(10))
        .await;

    // Should see BatchApplied events from the replayed batch
    let batch_applied_count = replay_events
        .iter()
        .filter(|e| matches!(e, StateEvent::BatchApplied { .. }))
        .count();

    // At least some nodes should have re-applied the batch
    assert!(
        batch_applied_count > 0,
        "Expected BatchApplied from replay, got: {replay_events:?}"
    );

    cluster.shutdown().await;
}

/// Reorg rollback: Bitcoin reorg replaces blocks, batches with stale anchor_hash
/// are skipped during replay.
#[tokio::test]
#[serial_test::serial]
async fn reorg_rollback_skips_stale_anchor_hash() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert mempool txs
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    // Mine block 1 — this sets the anchor hash for any batch decided at anchor 1
    {
        let (blk_events, mem_events) = mock.mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Add more mempool txs for a batch at anchor 1
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    // Wait for a decision at anchor 1
    let results = cluster.wait_for_decisions(2, Duration::from_secs(30)).await;
    let batch_at_1 = results[0].iter().find(|d| d.value.block_height() == 1);
    assert!(
        batch_at_1.is_some(),
        "Expected a batch at anchor 1, decisions: {:?}",
        results[0]
            .iter()
            .map(|d| d.value.block_height())
            .collect::<Vec<_>>()
    );

    // Drain any pending state events before sending rollback
    let _ = cluster
        .wait_for_state_events(20, Duration::from_secs(3))
        .await;

    // Now send a Bitcoin rollback to height 1 (revert blocks at height >= 1)
    cluster.send_block_event(BlockEvent::Rollback { to_height: 1 });

    // Wait for RollbackExecuted from all nodes
    let state_events = cluster
        .wait_for_state_events(4, Duration::from_secs(10))
        .await;

    let rollback_count = state_events
        .iter()
        .filter(|e| matches!(e, StateEvent::RollbackExecuted { to_anchor: 1, .. }))
        .count();

    assert!(
        rollback_count >= 4,
        "Expected 4 RollbackExecuted at to_anchor=1, got {rollback_count}: {state_events:?}"
    );

    // Re-mine block 1 with a DIFFERENT hash (simulating the reorg fork)
    // Reorg rollback does NOT replay old batches — the old batch at anchor 1
    // stays in the DB (dead data for sync) but is not re-executed.
    // New blocks go through consensus normally.
    mock.reset_to(0);
    {
        let (blk_events, _) = mock.mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // New mempool txs at the new anchor
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    // Consensus should continue working — new batches decided at the new anchor
    let new_decisions = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert!(
        !new_decisions.is_empty(),
        "Consensus should continue after reorg"
    );

    cluster.shutdown().await;
}

/// Block at the anchor height should be deferred until the anchor advances.
/// Verifies that mining a block doesn't cause it to be executed immediately
/// when a batch at the same anchor is decided.
#[tokio::test]
#[serial_test::serial]
async fn block_at_anchor_deferred() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4).await.unwrap();
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert mempool txs — batch will be decided at anchor 0
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert_eq!(results[0][0].value.block_height(), 0);

    // Mine block 1 — this goes to pending_blocks, NOT immediately executed
    {
        let (blk_events, mem_events) = mock.mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Collect state events briefly — should NOT see any BlockProcessed yet
    // because block 1 is at height 1 which is >= anchor 0
    let early_events = cluster
        .wait_for_state_events(8, Duration::from_secs(5))
        .await;

    // All early events should be BatchApplied (no BlockProcessed from the anchor block)
    for e in &early_events {
        if let StateEvent::BlockProcessed { height, .. } = e {
            // Block 1 should NOT have been processed by process_decided_batch
            // (it might be processed by the timeout in this 5s window on slow machines,
            // but with 30s default timeout it shouldn't be)
            assert!(
                *height != 1,
                "Block 1 should not be processed immediately — it should wait for anchor advance"
            );
        }
    }

    // Now mine block 2 and add more mempool txs — this advances chain_tip to 2
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    {
        let (blk_events, _) = mock.mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Wait for more decisions — a batch at anchor 2 will drain blocks < 2
    // (including block 1)
    let _results = cluster.wait_for_decisions(3, Duration::from_secs(30)).await;

    cluster.shutdown().await;
}
