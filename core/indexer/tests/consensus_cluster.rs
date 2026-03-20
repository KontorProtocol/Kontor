use anyhow::Result;
use indexer::reg_tester::RegTesterCluster;
use indexer::runtime::ContractAddress;
use testlib::*;

interface!(name = "counter", path = "../../test-contracts/counter/wit");

/// Poll all nodes until they all return the expected value for a view call,
/// or time out after `timeout_secs`.
async fn poll_all_nodes(
    cluster: &RegTesterCluster,
    contract: &ContractAddress,
    expr: &str,
    expected: &str,
    timeout_secs: u64,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        let mut all_match = true;
        for node in &cluster.nodes {
            match node.view(contract, expr).await? {
                indexer_types::ViewResult::Ok { value } if value == expected => {}
                _ => {
                    all_match = false;
                    break;
                }
            }
        }
        if all_match {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            for (i, node) in cluster.nodes.iter().enumerate() {
                let value = node.view(contract, expr).await?;
                eprintln!("Node {i}: {value:?}");
            }
            anyhow::bail!("Timed out waiting for all nodes to return {expected} for {expr}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Poll all nodes until they all reach at least the expected height.
async fn poll_all_nodes_height(
    cluster: &RegTesterCluster,
    expected_height: i64,
    timeout_secs: u64,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        let mut all_reached = true;
        for node in &cluster.nodes {
            let info = node.index().await?;
            if info.height < expected_height {
                all_reached = false;
                break;
            }
        }
        if all_reached {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            for (i, node) in cluster.nodes.iter().enumerate() {
                let info = node.index().await?;
                eprintln!("Node {i} height: {}", info.height);
            }
            anyhow::bail!("Timed out waiting for all nodes to reach height {expected_height}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Assert all nodes have matching non-empty checkpoints. Returns the checkpoint value.
async fn assert_checkpoints_match(cluster: &RegTesterCluster) -> Result<String> {
    let mut checkpoints = Vec::new();
    for (i, node) in cluster.nodes.iter().enumerate() {
        let info = node.index().await?;
        let checkpoint = info
            .checkpoint
            .unwrap_or_else(|| panic!("Node {i} should have a checkpoint"));
        checkpoints.push(checkpoint);
    }
    let first = &checkpoints[0];
    for (i, cp) in checkpoints.iter().enumerate().skip(1) {
        assert_eq!(cp, first, "Node {i} checkpoint mismatch with node 0");
    }
    Ok(checkpoints.into_iter().next().unwrap())
}

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
    poll_all_nodes(&cluster, &contract, "get()", "0", 30).await?;

    // Checkpoints should match after publish
    assert_checkpoints_match(&cluster).await?;

    // Build an increment transaction and send to mempool (don't mine)
    let contract_addr = indexer_types::ContractAddress {
        name: contract.name.clone(),
        height: contract.height,
        tx_index: contract.tx_index,
    };
    let (_compose_res, commit_hex, reveal_hex) = rt
        .compose_instruction(
            &mut ident,
            indexer_types::Inst::Call {
                gas_limit: 10_000,
                contract: contract_addr,
                expr: counter::wave::increment_call_expr(),
            },
        )
        .await?;
    rt.send_to_mempool(&[commit_hex, reveal_hex]).await?;

    // Poll until all nodes show counter = 1 (batch decided + executed)
    poll_all_nodes(&cluster, &contract, "get()", "1", 30).await?;

    // Checkpoints should still match after batch execution
    let post_batch_checkpoints = assert_checkpoints_match(&cluster).await?;

    // Get current height, then mine a block containing the batched tx
    let pre_mine_height = cluster.nodes[0].index().await?.height;
    cluster.mine(1).await?;

    // Wait for all nodes to process the new block
    poll_all_nodes_height(&cluster, pre_mine_height + 1, 30).await?;

    // Counter should still be 1 (dedup: tx already executed via batch)
    poll_all_nodes(&cluster, &contract, "get()", "1", 10).await?;

    // Checkpoints should remain the same (dedup produces identical state)
    let post_mine_checkpoints = assert_checkpoints_match(&cluster).await?;
    assert_eq!(
        post_batch_checkpoints, post_mine_checkpoints,
        "Checkpoints changed after mining block with already-batched tx"
    );

    cluster.teardown().await?;
    Ok(())
}
