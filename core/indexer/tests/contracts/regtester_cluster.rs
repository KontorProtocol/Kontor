use anyhow::Result;
use indexer::reg_tester::RegTesterCluster;
use indexer::runtime::ContractAddress;
use testlib::*;

interface!(name = "counter", path = "../../test-contracts/counter/wit");
interface!(
    name = "staking",
    path = "../../native-contracts/staking/wit"
);

fn counter_is(expected: u64) -> impl Fn(&str) -> bool {
    move |value| counter::wave::get_parse_return_expr(value) == expected
}

fn active_count_is(expected: u64) -> impl Fn(&str) -> bool {
    move |value| staking::wave::get_active_count_parse_return_expr(value) == expected
}

/// Basic cluster test: start 4 validators, publish a counter contract,
/// increment via consensus batch, verify all nodes agree on state.
#[tokio::test]

async fn cluster_counter_increment_via_consensus() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let cluster = RegTesterCluster::setup(4, 5, 0).await?;

    // Load counter contract bytes
    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    // Create funded identity (identity + issuance, each mines a block)
    let (mut rt, mut ident) = cluster.identity().await?;
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
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(0),
        )
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
            nonce: None,
            expr: counter::wave::increment_call_expr(),
        },
    )
    .await?;

    // Poll until all nodes show counter = 1 (batch decided + executed)
    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(1),
        )
        .await?;

    // Checkpoints should still match after batch execution
    let post_batch_checkpoints = cluster.assert_checkpoints_match().await?;

    // Get current height, then mine a block containing the batched tx
    let pre_mine_height = cluster.client(0).index().await?.height;
    cluster.mine(1).await?;

    // Wait for all nodes to process the new block
    cluster
        .poll_all_nodes_height(pre_mine_height + 1, 120)
        .await?;

    // Counter should still be 1 (dedup: tx already executed via batch)
    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(1),
        )
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

async fn cluster_multi_batch_convergence() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let cluster = RegTesterCluster::setup(4, 5, 0).await?;

    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    let (mut rt, mut ident) = cluster.identity().await?;
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
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(0),
        )
        .await?;

    // Submit 5 increments, waiting for each to be batched by consensus before sending the next
    let contract_addr = indexer_types::ContractAddress {
        name: contract.name.clone(),
        height: contract.height,
        tx_index: contract.tx_index,
    };
    let initial_consensus_height = cluster
        .client(0)
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
                nonce: None,
                expr: counter::wave::increment_call_expr(),
            },
        )
        .await?;

        // Wait for all nodes to process this batch
        cluster
            .poll_all_nodes_consensus_height(initial_consensus_height + i + 1, 120)
            .await?;
    }

    // All nodes should show counter = 5
    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(5),
        )
        .await?;

    // All nodes should agree on checkpoints
    let post_batch_checkpoints = cluster.assert_checkpoints_match().await?;

    // Mine a block to confirm all batched txs
    let pre_mine_height = cluster.client(0).index().await?.height;
    cluster.mine(1).await?;
    cluster
        .poll_all_nodes_height(pre_mine_height + 1, 120)
        .await?;

    // Counter should still be 5 (dedup)
    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(5),
        )
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

async fn cluster_node_restart_recovery() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let mut cluster = RegTesterCluster::setup(4, 5, 0).await?;

    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    let (mut rt, mut ident) = cluster.identity().await?;
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
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(0),
        )
        .await?;

    // Batch 2 increments while all 4 nodes are up
    let contract_addr = indexer_types::ContractAddress {
        name: contract.name.clone(),
        height: contract.height,
        tx_index: contract.tx_index,
    };
    let initial_consensus_height = cluster
        .client(0)
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
                nonce: None,
                expr: counter::wave::increment_call_expr(),
            },
        )
        .await?;
        cluster
            .poll_all_nodes_consensus_height(initial_consensus_height + i + 1, 120)
            .await?;
    }
    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(2),
        )
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
                nonce: None,
                expr: counter::wave::increment_call_expr(),
            },
        )
        .await?;
    }

    // Wait for the 3 remaining nodes to show counter = 4 (node 3 is killed)
    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(4),
        )
        .await?;

    // Restart node 3
    cluster.start_node(3).await?;

    // Wait for ALL nodes (including restarted) to show counter = 4
    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(4),
        )
        .await?;

    // All nodes (including restarted) should agree on checkpoints
    cluster.assert_checkpoints_match().await?;

    cluster.teardown().await?;
    Ok(())
}

/// Late joiner: start 3 of 4 validators, process batches + blocks,
/// then start the 4th from scratch. It syncs via Malachite and converges.
#[tokio::test]

async fn cluster_late_joiner_sync() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    // 4 validators in genesis, only 3 started
    let mut cluster = RegTesterCluster::setup_with(4, 4, 3, 1, 0).await?;

    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    let (mut rt, mut ident) = cluster.identity().await?;
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
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(0),
        )
        .await?;

    // Batch 3 increments on the 3 active nodes
    let contract_addr = indexer_types::ContractAddress {
        name: contract.name.clone(),
        height: contract.height,
        tx_index: contract.tx_index,
    };
    let initial_consensus_height = cluster
        .client(0)
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
                nonce: None,
                expr: counter::wave::increment_call_expr(),
            },
        )
        .await?;
        cluster
            .poll_all_nodes_consensus_height(initial_consensus_height + i + 1, 120)
            .await?;
    }
    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(3),
        )
        .await?;

    // Mine a block to confirm the batched txs
    let pre_mine_height = cluster.client(0).index().await?.height;
    cluster.mine(1).await?;
    cluster
        .poll_all_nodes_height(pre_mine_height + 1, 120)
        .await?;

    // Start the 4th node (late joiner — fresh DB, never started)
    cluster.start_node(3).await?;

    // Wait for the late joiner to sync and reach the same state
    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(3),
        )
        .await?;

    // All 4 nodes should agree on checkpoints
    cluster.assert_checkpoints_match().await?;

    cluster.teardown().await?;
    Ok(())
}

/// Validator lifecycle: register a new validator, activate it, verify participation,
/// then unstake and verify deactivation.
#[tokio::test]

async fn cluster_validator_lifecycle() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    // 5 keys, 4 in genesis, 4 started
    let mut cluster = RegTesterCluster::setup_with(5, 4, 4, 1, 0).await?;

    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    let (mut rt, mut ident) = cluster.identity().await?;
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
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(0),
        )
        .await?;

    let staking_addr = indexer_types::ContractAddress {
        name: "staking".to_string(),
        height: 0,
        tx_index: 0,
    };
    let staking_contract = ContractAddress {
        name: "staking".to_string(),
        height: 0,
        tx_index: 0,
    };

    // Verify 4 active validators initially
    cluster
        .poll_all_nodes_view(
            &staking_contract,
            &staking::wave::get_active_count_call_expr(),
            120,
            active_count_is(4),
        )
        .await?;

    // Start the 5th node first — it observes as Role::None until activated
    eprintln!("Starting 5th node (as observer)...");
    cluster.start_node(4).await?;
    eprintln!("5th node started and API available");

    // Register 5th validator using its ed25519 key
    eprintln!("Registering 5th validator...");
    let ed25519_pubkey = cluster.node_configs[4]
        .ed25519_key
        .public_key()
        .as_bytes()
        .to_vec();
    rt.instruction(
        &mut ident,
        indexer_types::Inst::Call {
            gas_limit: 10_000,
            contract: staking_addr.clone(),
            nonce: None,
            expr: staking::wave::register_validator_call_expr(
                ed25519_pubkey,
                5u64.try_into().unwrap(),
            ),
        },
    )
    .await?;

    // Mine past ACTIVATION_DELAY (12 blocks)
    let pre_height = cluster.client(0).index().await?.height;
    eprintln!("Pre-mine height: {pre_height}");
    cluster.mine(13).await?;
    cluster.poll_all_nodes_height(pre_height + 13, 120).await?;
    eprintln!("All nodes reached height {}", pre_height + 13);

    // Verify 5 active validators on all nodes (including the 5th)
    cluster
        .poll_all_nodes_view(
            &staking_contract,
            &staking::wave::get_active_count_call_expr(),
            120,
            active_count_is(5),
        )
        .await?;
    eprintln!("All 5 nodes see 5 active validators");

    // Increment counter and verify all 5 nodes agree
    let counter_addr = indexer_types::ContractAddress {
        name: contract.name.clone(),
        height: contract.height,
        tx_index: contract.tx_index,
    };
    rt.instruction(
        &mut ident,
        indexer_types::Inst::Call {
            gas_limit: 10_000,
            contract: counter_addr.clone(),
            nonce: None,
            expr: counter::wave::increment_call_expr(),
        },
    )
    .await?;

    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(1),
        )
        .await?;
    cluster.assert_checkpoints_match().await?;

    // --- Prove the 5th node is actively voting ---
    // Kill one original validator. With 5-node set, need 4/5 (80%) for quorum.
    // If the 5th isn't voting, only 3/5 (60%) < 66.7% — consensus stalls.
    // If consensus continues, the 5th must be voting.
    eprintln!("Killing node 3 to prove 5th node is voting...");
    cluster.kill_node(3).await?;

    rt.send_instruction(
        &mut ident,
        indexer_types::Inst::Call {
            gas_limit: 10_000,
            contract: counter_addr.clone(),
            nonce: None,
            expr: counter::wave::increment_call_expr(),
        },
    )
    .await?;

    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(2),
        )
        .await?;
    eprintln!("Consensus continued with 5th node voting — confirmed active validator");

    // Restart node 3 for the unstake phase
    cluster.start_node(3).await?;
    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(2),
        )
        .await?;
    cluster.assert_checkpoints_match().await?;
    eprintln!("Node 3 restarted and caught up");

    // --- Unstake the 5th validator ---
    rt.instruction(
        &mut ident,
        indexer_types::Inst::Call {
            gas_limit: 10_000,
            contract: staking_addr.clone(),
            nonce: None,
            expr: staking::wave::begin_unstake_call_expr(),
        },
    )
    .await?;

    // Mine past ACTIVATION_DELAY
    let pre_height = cluster.client(0).index().await?.height;
    cluster.mine(13).await?;
    cluster.poll_all_nodes_height(pre_height + 13, 120).await?;

    // Verify back to 4 active validators
    cluster
        .poll_all_nodes_view(
            &staking_contract,
            &staking::wave::get_active_count_call_expr(),
            120,
            active_count_is(4),
        )
        .await?;

    // Kill the deactivated node
    cluster.kill_node(4).await?;

    // Consensus continues — increment counter again
    rt.send_instruction(
        &mut ident,
        indexer_types::Inst::Call {
            gas_limit: 10_000,
            contract: counter_addr,
            nonce: None,
            expr: counter::wave::increment_call_expr(),
        },
    )
    .await?;

    cluster
        .poll_all_nodes_view(
            &contract,
            &counter::wave::get_call_expr(),
            120,
            counter_is(3),
        )
        .await?;
    cluster.assert_checkpoints_match().await?;

    cluster.teardown().await?;
    Ok(())
}
