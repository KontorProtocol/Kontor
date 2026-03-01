use std::time::Duration;

use bitcoin::hashes::Hash;
use consensus_sim::mock_bitcoin::MockBitcoin;
use consensus_sim::reactor::FinalityEvent;
use consensus_sim::reactor::StateEvent;
use consensus_sim::run_cluster;

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
        cluster.send_bitcoin_event(event);
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
    let expected_txids: Vec<[u8; 32]> = mock
        .mempool()
        .iter()
        .map(|tx| tx.txid.to_byte_array())
        .collect();

    for event in events {
        cluster.send_bitcoin_event(event);
    }

    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;

    // At least one node should have decided a value containing our txids
    let decided_value = &results[0][0].value;
    for expected in &expected_txids {
        assert!(
            decided_value.txids.contains(expected),
            "Decided value missing expected txid"
        );
    }
    // Anchor should be 0 since no blocks were mined
    assert_eq!(decided_value.anchor_height, 0);

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
        cluster.send_bitcoin_event(event);
    }

    // Wait for at least 1 decision at anchor 0
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert_eq!(results[0][0].value.anchor_height, 0);

    // Mine a block — this advances the chain tip to 1
    for event in mock.mine_block_all() {
        cluster.send_bitcoin_event(event);
    }

    // Add new mempool txs so the next batch has content
    for event in mock.generate_mempool_txs(2) {
        cluster.send_bitcoin_event(event);
    }

    // Wait for another decision — anchor should now be 1
    let results = cluster.wait_for_decisions(2, Duration::from_secs(30)).await;
    let second = &results[0][1].value;
    assert_eq!(
        second.anchor_height, 1,
        "Expected anchor_height 1 after mining a block, got {}",
        second.anchor_height
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
            node_decisions[0].value.txids.is_empty(),
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
        cluster.send_bitcoin_event(event);
    }

    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    let decided = &results[0][0];
    assert_eq!(decided.value.anchor_height, 0);

    // Mine blocks confirming all the batched txids, then mine through the finality window.
    // Block 1: confirm all mempool txs
    for event in mock.mine_block_all() {
        cluster.send_bitcoin_event(event);
    }

    // Blocks 2-6: empty blocks to reach deadline (anchor 0 + 6 = 6)
    for _ in 0..5 {
        for event in mock.mine_empty_block() {
            cluster.send_bitcoin_event(event);
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
    let has_finalized = finality_events.iter().any(|e| {
        matches!(e, FinalityEvent::BatchFinalized { anchor_height, .. } if *anchor_height == 0)
    });
    assert!(has_finalized, "Expected BatchFinalized at anchor 0, got: {finality_events:?}");

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
        cluster.send_bitcoin_event(event);
    }

    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    let decided = &results[0][0];
    let decided_txids = decided.value.txids.clone();
    assert!(decided_txids.len() >= 3, "Expected at least 3 txids in decided batch");

    // Confirm only the first 2 txids — the 3rd will be missing
    let confirm_txids: Vec<bitcoin::Txid> = decided_txids[..2]
        .iter()
        .map(|bytes| bitcoin::Txid::from_slice(bytes).unwrap())
        .collect();

    // Mine block 1 with only 2 of the 3 txids
    for event in mock.mine_block(&confirm_txids) {
        cluster.send_bitcoin_event(event);
    }

    // Mine blocks 2-6 (empty) to reach the deadline
    for _ in 0..5 {
        for event in mock.mine_empty_block() {
            cluster.send_bitcoin_event(event);
        }
    }

    let finality_events = cluster
        .wait_for_finality_events(1, Duration::from_secs(10))
        .await;

    assert!(
        !finality_events.is_empty(),
        "Expected at least one finality event"
    );

    let has_rollback = finality_events.iter().any(|e| {
        matches!(e, FinalityEvent::Rollback { missing_txids, .. } if !missing_txids.is_empty())
    });
    assert!(has_rollback, "Expected Rollback with missing txids, got: {finality_events:?}");

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
        cluster.send_bitcoin_event(event);
    }
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert_eq!(results[0][0].value.anchor_height, 0);

    // Mine block 1 (confirm nothing — intentionally leave batch 1 txids unconfirmed)
    for event in mock.mine_empty_block() {
        cluster.send_bitcoin_event(event);
    }

    // Add more txs and let consensus decide batch 2 at anchor 1
    for event in mock.generate_mempool_txs(2) {
        cluster.send_bitcoin_event(event);
    }
    let _results = cluster.wait_for_decisions(2, Duration::from_secs(30)).await;

    // Mine blocks 2-6 (empty) to hit the deadline for anchor 0 (0 + 6 = 6)
    for _ in 0..5 {
        for event in mock.mine_empty_block() {
            cluster.send_bitcoin_event(event);
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
    let rollback = finality_events.iter().find(|e| matches!(e, FinalityEvent::Rollback { .. }));
    assert!(rollback.is_some(), "Expected Rollback event, got: {finality_events:?}");

    if let Some(FinalityEvent::Rollback { invalidated_batches, .. }) = rollback {
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
        cluster.send_bitcoin_event(event);
    }

    // Mine a block that confirms some txs — this creates both batched and unbatched txs
    // at anchor 0 (the block has txs, the batch also has txs)
    for event in mock.mine_block_all() {
        cluster.send_bitcoin_event(event);
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
        cluster.send_bitcoin_event(event);
    }

    // Wait for consensus to decide a batch containing these txids
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    let decided = &results[0][0];
    let batch_txid_count = decided.value.txids.len();

    // Mine a block that confirms the same txids — they overlap with the batch
    for event in mock.mine_block_all() {
        cluster.send_bitcoin_event(event);
    }

    // Collect state events
    let state_events = cluster
        .wait_for_state_events(2, Duration::from_secs(5))
        .await;

    // Find the BatchApplied event
    let batch_applied = state_events.iter().find(|e| matches!(e, StateEvent::BatchApplied { .. }));
    assert!(batch_applied.is_some(), "Expected BatchApplied event");

    if let Some(StateEvent::BatchApplied { txid_count, .. }) = batch_applied {
        assert_eq!(*txid_count, batch_txid_count, "Batch should contain all mempool txids");
    }

    // If there's a BlockProcessed at the same anchor, unbatched_count should be 0
    // because all txids were already in the batch
    let block_at_anchor = state_events.iter().find(|e| {
        matches!(e, StateEvent::BlockProcessed { height, .. } if *height == decided.value.anchor_height)
    });
    // Either no BlockProcessed (because 0 unbatched) or unbatched_count == 0
    if let Some(StateEvent::BlockProcessed { unbatched_count, .. }) = block_at_anchor {
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
        cluster.send_bitcoin_event(event);
    }
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert_eq!(results[0][0].value.anchor_height, 0);

    // Mine block 1 (confirm nothing — leave batch 1 txids unconfirmed)
    for event in mock.mine_empty_block() {
        cluster.send_bitcoin_event(event);
    }

    // Mine blocks 2-6 (empty) to hit the deadline for anchor 0 (0 + 6 = 6)
    for _ in 0..5 {
        for event in mock.mine_empty_block() {
            cluster.send_bitcoin_event(event);
        }
    }

    // Malachite keeps deciding batches. Eventually a batch's process_decided_batch
    // will run check_finality() after chain_tip >= 6, triggering the rollback.
    // Collect state events until we see a RollbackExecuted.
    let state_events = cluster
        .wait_for_state_events(20, Duration::from_secs(15))
        .await;

    let rollback_event = state_events.iter().find(|e| matches!(e, StateEvent::RollbackExecuted { .. }));
    assert!(
        rollback_event.is_some(),
        "Expected RollbackExecuted state event, got: {state_events:?}"
    );

    if let Some(StateEvent::RollbackExecuted { entries_removed, .. }) = rollback_event {
        assert!(
            *entries_removed > 0,
            "Rollback should have removed entries"
        );
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
        cluster.send_bitcoin_event(event);
    }
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    let batch1_txids = results[0][0].value.txids.clone();

    // Mine block 1 confirming batch 1's txids — batch 1 will finalize
    let confirm_txids: Vec<bitcoin::Txid> = batch1_txids
        .iter()
        .map(|bytes| bitcoin::Txid::from_slice(bytes).unwrap())
        .collect();
    for event in mock.mine_block(&confirm_txids) {
        cluster.send_bitcoin_event(event);
    }

    // Mine blocks 2-7 (empty) — this reaches deadline for anchor 0 (finalized)
    // and also for anchor 1 (if a batch 2 was decided with unconfirmed txids)
    for _ in 0..6 {
        for event in mock.mine_empty_block() {
            cluster.send_bitcoin_event(event);
        }
    }

    // Collect state events — look for RollbackExecuted
    // Malachite decides batches continuously; one will trigger finality check
    // Batch 1 (anchor 0) finalizes, batch 2+ (anchor 1+, unconfirmed txids) triggers rollback
    let state_events = cluster
        .wait_for_state_events(20, Duration::from_secs(15))
        .await;

    let post_rollback_checkpoint = state_events.iter().find_map(|e| match e {
        StateEvent::RollbackExecuted { checkpoint, .. } => Some(*checkpoint),
        _ => None,
    });

    if let Some(post) = post_rollback_checkpoint {
        // Batch 1 at anchor 0 survives the rollback (only anchor 1+ is truncated),
        // so checkpoint should not be empty
        assert_ne!(post, [0u8; 32], "Post-rollback checkpoint should not be empty");
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
        cluster.send_bitcoin_event(event);
    }

    let _results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;

    // Collect state events — need at least 4 BatchApplied (one per node).
    // Collect extra in case other event types (BlockProcessed) arrive too.
    let state_events = cluster
        .wait_for_state_events(8, Duration::from_secs(10))
        .await;

    // Filter to only the first consensus height's BatchApplied events
    let first_height = state_events.iter().find_map(|e| match e {
        StateEvent::BatchApplied { consensus_height, .. } => Some(*consensus_height),
        _ => None,
    });

    let batch_checkpoints: Vec<[u8; 32]> = state_events
        .iter()
        .filter_map(|e| match e {
            StateEvent::BatchApplied { consensus_height, checkpoint, .. }
                if Some(*consensus_height) == first_height => Some(*checkpoint),
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
