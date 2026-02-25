use std::time::Duration;

use bitcoin::hashes::Hash;
use consensus_sim::mock_bitcoin::MockBitcoin;
use consensus_sim::reactor::FinalityEvent;
use consensus_sim::run_cluster;

/// All 4 validators should decide the same value at each consensus height.
#[tokio::test]
async fn validators_agree_on_values() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4, 28000).await.unwrap();

    // Let P2P mesh establish before feeding events
    tokio::time::sleep(Duration::from_secs(3)).await;

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
async fn decided_values_contain_mempool_txids() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4, 28100).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;

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
async fn block_updates_chain_tip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4, 28200).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;

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
async fn empty_mempool_produces_empty_batch() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4, 28300).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;

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
async fn happy_path_finalization() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4, 28400).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;

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
async fn missing_tx_invalidation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4, 28500).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;

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
async fn cascade_invalidation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = run_cluster(4, 28600).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;

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
