use std::time::Duration;

use consensus_sim::mock_bitcoin::MockBitcoin;
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

    // Wait for at least 2 decided values from each node
    let results = cluster.wait_for_decisions(2, Duration::from_secs(30)).await;

    // All nodes should have decided at least 2 values
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
