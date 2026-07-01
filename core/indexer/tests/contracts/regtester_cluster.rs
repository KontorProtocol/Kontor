use anyhow::Result;
use indexer::reg_tester::{RegTesterCluster, default_kontor_bin};
use indexer::runtime::ContractAddress;
use indexer_types::{Inst, InstKind};
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

/// Consensus batch lifecycle on ONE 4-node cluster — consolidated from three
/// former standalone tests (basic batched increment, multi-batch convergence,
/// node restart recovery) to cut the number of concurrent clusters CI spins up,
/// the dominant driver of macOS-runner contention. The three scenarios run in
/// sequence on a single chain; the PHASE banners mark where a failure occurred.
/// No coverage is lost — every assertion from the originals is preserved here.
#[tokio::test]
async fn cluster_consensus_lifecycle() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let mut cluster = RegTesterCluster::setup(4, 5, 0).await?;

    // Publish the counter once; every phase increments this same contract on the
    // one chain (funded identity: identity + issuance each mine a block).
    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");
    let (mut rt, mut ident) = cluster.identity().await?;
    let result = rt
        .instruction(
            &mut ident,
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Publish {
                    name: "counter".to_string(),
                    bytes: contract_bytes,
                    provenance: sample_provenance(),
                },
            },
        )
        .await?;
    let contract: ContractAddress = result
        .result
        .contract
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    let contract_addr = indexer_types::ContractAddress {
        name: contract.name.clone(),
        height: contract.height,
        tx_index: contract.tx_index,
    };
    let get = counter::wave::get_call_expr();

    // One running counter shared across phases (the chain is never reset), so each
    // assertion tracks the accumulated value and phase order stays explicit.
    let mut expected: u64 = 0;
    cluster
        .poll_all_nodes_view(&contract, &get, 120, counter_is(expected))
        .await?;
    cluster.assert_checkpoints_match().await?;

    // ===== PHASE 1: single batched increment + block-level dedup =====
    eprintln!(
        "===== [cluster_consensus_lifecycle] PHASE 1: single batched increment + dedup ====="
    );
    rt.send_instruction(
        &mut ident,
        Inst {
            gas_limit: 10_000,
            kind: InstKind::Call {
                contract: contract_addr.clone(),
                expr: counter::wave::increment_call_expr(),
            },
        },
    )
    .await?;
    expected += 1;
    // Batch decided + executed → every node reads the new value.
    cluster
        .poll_all_nodes_view(&contract, &get, 120, counter_is(expected))
        .await?;
    let post_batch_checkpoints = cluster.assert_checkpoints_match().await?;

    // Mine the block confirming the already-batched tx; dedup ⇒ no state change.
    let pre_mine_height = cluster.client(0).index().await?.height;
    cluster.mine(1).await?;
    cluster
        .poll_all_nodes_height(pre_mine_height + 1, 120)
        .await?;
    cluster
        .poll_all_nodes_view(&contract, &get, 120, counter_is(expected))
        .await?;
    let post_mine_checkpoints = cluster.assert_checkpoints_match().await?;
    assert_eq!(
        post_batch_checkpoints, post_mine_checkpoints,
        "Checkpoints changed after mining a block with an already-batched tx"
    );

    // ===== PHASE 2: rapid multi-batch convergence + block dedup =====
    eprintln!("===== [cluster_consensus_lifecycle] PHASE 2: multi-batch convergence + dedup =====");
    // Recapture the consensus height — phase 1 already advanced it.
    let phase2_base = cluster
        .client(0)
        .index()
        .await?
        .consensus_height
        .unwrap_or(0);
    // Five increments in succession, each waiting for its own batch before the next.
    for i in 0..5 {
        rt.send_instruction(
            &mut ident,
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Call {
                    contract: contract_addr.clone(),
                    expr: counter::wave::increment_call_expr(),
                },
            },
        )
        .await?;
        cluster
            .poll_all_nodes_consensus_height(phase2_base + i + 1, 120)
            .await?;
    }
    expected += 5;
    cluster
        .poll_all_nodes_view(&contract, &get, 120, counter_is(expected))
        .await?;
    let post_multibatch_checkpoints = cluster.assert_checkpoints_match().await?;

    let pre_mine_height = cluster.client(0).index().await?.height;
    cluster.mine(1).await?;
    cluster
        .poll_all_nodes_height(pre_mine_height + 1, 120)
        .await?;
    cluster
        .poll_all_nodes_view(&contract, &get, 120, counter_is(expected))
        .await?;
    let post_multibatch_mine_checkpoints = cluster.assert_checkpoints_match().await?;
    assert_eq!(
        post_multibatch_checkpoints, post_multibatch_mine_checkpoints,
        "Checkpoints changed after mining a block with already-batched txs"
    );

    // ===== PHASE 3: node kill / restart catch-up via sync =====
    eprintln!("===== [cluster_consensus_lifecycle] PHASE 3: node kill / restart catch-up =====");
    // Two increments with all 4 nodes up.
    let phase3_base = cluster
        .client(0)
        .index()
        .await?
        .consensus_height
        .unwrap_or(0);
    for i in 0..2 {
        rt.send_instruction(
            &mut ident,
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Call {
                    contract: contract_addr.clone(),
                    expr: counter::wave::increment_call_expr(),
                },
            },
        )
        .await?;
        cluster
            .poll_all_nodes_consensus_height(phase3_base + i + 1, 120)
            .await?;
    }
    expected += 2;
    cluster
        .poll_all_nodes_view(&contract, &get, 120, counter_is(expected))
        .await?;

    // Kill node 3; the remaining 3 keep quorum (3/4 > 2/3) and keep batching.
    cluster.kill_node(3).await?;
    for _ in 0..2 {
        rt.send_instruction(
            &mut ident,
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Call {
                    contract: contract_addr.clone(),
                    expr: counter::wave::increment_call_expr(),
                },
            },
        )
        .await?;
    }
    expected += 2;
    // The 3 live nodes converge (poll_all_nodes_view skips the killed node).
    cluster
        .poll_all_nodes_view(&contract, &get, 120, counter_is(expected))
        .await?;

    // Restart node 3; it must sync to the current value and re-agree on checkpoints.
    cluster.start_node(3).await?;
    cluster
        .poll_all_nodes_view(&contract, &get, 120, counter_is(expected))
        .await?;
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
    let mut cluster =
        RegTesterCluster::setup_with(4, 4, 3, 1, 0, None, &default_kontor_bin()).await?;

    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    let (mut rt, mut ident) = cluster.identity().await?;
    let result = rt
        .instruction(
            &mut ident,
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Publish {
                    name: "counter".to_string(),
                    bytes: contract_bytes,
                    provenance: sample_provenance(),
                },
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
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Call {
                    contract: contract_addr.clone(),
                    expr: counter::wave::increment_call_expr(),
                },
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
    let mut cluster =
        RegTesterCluster::setup_with(5, 4, 4, 1, 0, None, &default_kontor_bin()).await?;

    let contracts = ContractReader::new("../../test-contracts").await?;
    let contract_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    let (mut rt, mut ident) = cluster.identity().await?;
    let result = rt
        .instruction(
            &mut ident,
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Publish {
                    name: "counter".to_string(),
                    bytes: contract_bytes,
                    provenance: sample_provenance(),
                },
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
        Inst {
            gas_limit: 10_000,
            kind: InstKind::Call {
                contract: staking_addr.clone(),
                expr: staking::wave::register_validator_call_expr(
                    ed25519_pubkey,
                    5u64.try_into().unwrap(),
                ),
            },
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
        Inst {
            gas_limit: 10_000,
            kind: InstKind::Call {
                contract: counter_addr.clone(),
                expr: counter::wave::increment_call_expr(),
            },
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
        Inst {
            gas_limit: 10_000,
            kind: InstKind::Call {
                contract: counter_addr.clone(),
                expr: counter::wave::increment_call_expr(),
            },
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
        Inst {
            gas_limit: 10_000,
            kind: InstKind::Call {
                contract: staking_addr.clone(),
                expr: staking::wave::begin_unstake_call_expr(),
            },
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
        Inst {
            gas_limit: 10_000,
            kind: InstKind::Call {
                contract: counter_addr,
                expr: counter::wave::increment_call_expr(),
            },
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
