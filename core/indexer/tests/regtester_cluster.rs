use anyhow::Result;
use indexer::reg_tester::RegTesterCluster;
use indexer::runtime::ContractAddress;
use testlib::*;

interface!(name = "counter", path = "../../test-contracts/counter/wit");

/// Basic cluster test: start 4 validators, publish a counter contract,
/// increment via consensus batch, verify all nodes agree on state.
#[tokio::test]
#[serial_test::serial]
async fn cluster_counter_increment_via_consensus() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let cluster = RegTesterCluster::setup(4).await?;

    // Load counter contract bytes
    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    // Create funded identity (identity + issuance, each mines a block)
    let (mut rt, mut ident) = cluster.funded_identity().await?;
    let result = rt
        .instruction(
            &mut ident,
            indexer_types::Inst::Publish {
                gas_limit: 10_000,
                name: "counter".to_string(),
                bytes: contract_bytes,
            },
        )
        .await?;
    let contract: ContractAddress = result
        .result
        .contract
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // Wait for all nodes to see counter at 0
    cluster
        .poll_all_nodes(&contract, "get()", "0", 120, &[])
        .await?;

    // Checkpoints should match after publish
    cluster.assert_checkpoints_match().await?;

    // Send an increment transaction to mempool (don't mine)
    let contract_addr = indexer_types::ContractAddress {
        name: contract.name.clone(),
        height: contract.height,
        tx_index: contract.tx_index,
    };
    rt.send_instruction(
        &mut ident,
        indexer_types::Inst::Call {
            gas_limit: 10_000,
            contract: contract_addr,
            expr: counter::wave::increment_call_expr(),
        },
    )
    .await?;

    // Poll until all nodes show counter = 1 (batch decided + executed)
    cluster
        .poll_all_nodes(&contract, "get()", "1", 120, &[])
        .await?;

    // Checkpoints should still match after batch execution
    let post_batch_checkpoints = cluster.assert_checkpoints_match().await?;

    // Get current height, then mine a block containing the batched tx
    let pre_mine_height = cluster.nodes[0].index().await?.height;
    cluster.mine(1).await?;

    // Wait for all nodes to process the new block
    cluster
        .poll_all_nodes_height(pre_mine_height + 1, 120, &[])
        .await?;

    // Counter should still be 1 (dedup: tx already executed via batch)
    cluster
        .poll_all_nodes(&contract, "get()", "1", 120, &[])
        .await?;

    // Checkpoints should remain the same (dedup produces identical state)
    let post_mine_checkpoints = cluster.assert_checkpoints_match().await?;
    assert_eq!(
        post_batch_checkpoints, post_mine_checkpoints,
        "Checkpoints changed after mining block with already-batched tx"
    );

    cluster.teardown().await?;
    Ok(())
}

/// Multi-batch convergence: submit 5 increments in rapid succession,
/// verify all nodes converge, then mine to confirm and verify dedup.
#[tokio::test]
#[serial_test::serial]
async fn cluster_multi_batch_convergence() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let cluster = RegTesterCluster::setup(4).await?;

    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    let (mut rt, mut ident) = cluster.funded_identity().await?;
    let result = rt
        .instruction(
            &mut ident,
            indexer_types::Inst::Publish {
                gas_limit: 10_000,
                name: "counter".to_string(),
                bytes: contract_bytes,
            },
        )
        .await?;
    let contract: ContractAddress = result
        .result
        .contract
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    cluster
        .poll_all_nodes(&contract, "get()", "0", 120, &[])
        .await?;

    // Submit 5 increments, waiting for each to be batched by consensus before sending the next
    let contract_addr = indexer_types::ContractAddress {
        name: contract.name.clone(),
        height: contract.height,
        tx_index: contract.tx_index,
    };
    let initial_consensus_height = cluster.nodes[0]
        .index()
        .await?
        .consensus_height
        .unwrap_or(0);
    for i in 0..5 {
        rt.send_instruction(
            &mut ident,
            indexer_types::Inst::Call {
                gas_limit: 10_000,
                contract: contract_addr.clone(),
                expr: counter::wave::increment_call_expr(),
            },
        )
        .await?;

        // Wait for all nodes to process this batch
        cluster
            .poll_all_nodes_consensus_height(initial_consensus_height + i + 1, 120, &[])
            .await?;
    }

    // All nodes should show counter = 5
    cluster
        .poll_all_nodes(&contract, "get()", "5", 120, &[])
        .await?;

    // All nodes should agree on checkpoints
    let post_batch_checkpoints = cluster.assert_checkpoints_match().await?;

    // Mine a block to confirm all batched txs
    let pre_mine_height = cluster.nodes[0].index().await?.height;
    cluster.mine(1).await?;
    cluster
        .poll_all_nodes_height(pre_mine_height + 1, 120, &[])
        .await?;

    // Counter should still be 5 (dedup)
    cluster
        .poll_all_nodes(&contract, "get()", "5", 120, &[])
        .await?;

    // Checkpoints should be unchanged (dedup produces identical state)
    let post_mine_checkpoints = cluster.assert_checkpoints_match().await?;
    assert_eq!(
        post_batch_checkpoints, post_mine_checkpoints,
        "Checkpoints changed after mining block with already-batched txs"
    );

    cluster.teardown().await?;
    Ok(())
}

/// Node restart: kill a node, continue batching on remaining 3,
/// restart the killed node, verify it catches up via sync.
#[tokio::test]
#[serial_test::serial]
async fn cluster_node_restart_recovery() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let mut cluster = RegTesterCluster::setup(4).await?;

    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    let (mut rt, mut ident) = cluster.funded_identity().await?;
    let result = rt
        .instruction(
            &mut ident,
            indexer_types::Inst::Publish {
                gas_limit: 10_000,
                name: "counter".to_string(),
                bytes: contract_bytes,
            },
        )
        .await?;
    let contract: ContractAddress = result
        .result
        .contract
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    cluster
        .poll_all_nodes(&contract, "get()", "0", 120, &[])
        .await?;

    // Batch 2 increments while all 4 nodes are up
    let contract_addr = indexer_types::ContractAddress {
        name: contract.name.clone(),
        height: contract.height,
        tx_index: contract.tx_index,
    };
    let initial_consensus_height = cluster.nodes[0]
        .index()
        .await?
        .consensus_height
        .unwrap_or(0);
    for i in 0..2 {
        rt.send_instruction(
            &mut ident,
            indexer_types::Inst::Call {
                gas_limit: 10_000,
                contract: contract_addr.clone(),
                expr: counter::wave::increment_call_expr(),
            },
        )
        .await?;
        cluster
            .poll_all_nodes_consensus_height(initial_consensus_height + i + 1, 120, &[])
            .await?;
    }
    cluster
        .poll_all_nodes(&contract, "get()", "2", 120, &[])
        .await?;

    // Kill node 3
    cluster.kill_node(3).await?;

    // Batch 2 more increments on remaining 3 nodes (still have quorum: 3/4 > 2/3)
    for _ in 0..2 {
        rt.send_instruction(
            &mut ident,
            indexer_types::Inst::Call {
                gas_limit: 10_000,
                contract: contract_addr.clone(),
                expr: counter::wave::increment_call_expr(),
            },
        )
        .await?;
    }

    // Wait for the 3 remaining nodes to show counter = 4 (skip dead node 3)
    cluster
        .poll_all_nodes(&contract, "get()", "4", 120, &[3])
        .await?;

    // Restart node 3
    cluster.start_node(3).await?;

    // Wait for ALL nodes (including restarted) to show counter = 4
    cluster
        .poll_all_nodes(&contract, "get()", "4", 120, &[])
        .await?;

    // All nodes (including restarted) should agree on checkpoints
    cluster.assert_checkpoints_match().await?;

    cluster.teardown().await?;
    Ok(())
}

/// Late joiner: start 3 of 4 validators, process batches + blocks,
/// then start the 4th from scratch. It syncs via Malachite and converges.
#[tokio::test]
#[serial_test::serial]
async fn cluster_late_joiner_sync() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    // 4 validators in genesis, only 3 started
    let mut cluster = RegTesterCluster::setup_with(4, 3).await?;

    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    let (mut rt, mut ident) = cluster.funded_identity().await?;
    let result = rt
        .instruction(
            &mut ident,
            indexer_types::Inst::Publish {
                gas_limit: 10_000,
                name: "counter".to_string(),
                bytes: contract_bytes,
            },
        )
        .await?;
    let contract: ContractAddress = result
        .result
        .contract
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // Wait for 3 active nodes to see counter = 0
    cluster
        .poll_all_nodes(&contract, "get()", "0", 120, &[])
        .await?;

    // Batch 3 increments on the 3 active nodes
    let contract_addr = indexer_types::ContractAddress {
        name: contract.name.clone(),
        height: contract.height,
        tx_index: contract.tx_index,
    };
    let initial_consensus_height = cluster.nodes[0]
        .index()
        .await?
        .consensus_height
        .unwrap_or(0);
    for i in 0..3 {
        rt.send_instruction(
            &mut ident,
            indexer_types::Inst::Call {
                gas_limit: 10_000,
                contract: contract_addr.clone(),
                expr: counter::wave::increment_call_expr(),
            },
        )
        .await?;
        cluster
            .poll_all_nodes_consensus_height(initial_consensus_height + i + 1, 120, &[])
            .await?;
    }
    cluster
        .poll_all_nodes(&contract, "get()", "3", 120, &[])
        .await?;

    // Mine a block to confirm the batched txs
    cluster.mine(1).await?;
    let pre_join_height = cluster.nodes[0].index().await?.height;
    cluster
        .poll_all_nodes_height(pre_join_height, 120, &[])
        .await?;

    // Start the 4th node (late joiner — fresh DB, never started)
    cluster.start_node(3).await?;

    // Wait for the late joiner to sync and reach the same state
    cluster
        .poll_all_nodes(&contract, "get()", "3", 120, &[])
        .await?;

    // All 4 nodes should agree on checkpoints
    cluster.assert_checkpoints_match().await?;

    cluster.teardown().await?;
    Ok(())
}
