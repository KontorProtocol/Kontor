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
    cluster.poll_all_nodes(&contract, "get()", "0", 120).await?;

    // Checkpoints should match after publish
    cluster.assert_checkpoints_match().await?;

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
    cluster.poll_all_nodes(&contract, "get()", "1", 120).await?;

    // Checkpoints should still match after batch execution
    let post_batch_checkpoints = cluster.assert_checkpoints_match().await?;

    // Get current height, then mine a block containing the batched tx
    let pre_mine_height = cluster.nodes[0].index().await?.height;
    cluster.mine(1).await?;

    // Wait for all nodes to process the new block
    cluster
        .poll_all_nodes_height(pre_mine_height + 1, 120)
        .await?;

    // Counter should still be 1 (dedup: tx already executed via batch)
    cluster.poll_all_nodes(&contract, "get()", "1", 120).await?;

    // Checkpoints should remain the same (dedup produces identical state)
    let post_mine_checkpoints = cluster.assert_checkpoints_match().await?;
    assert_eq!(
        post_batch_checkpoints, post_mine_checkpoints,
        "Checkpoints changed after mining block with already-batched tx"
    );

    cluster.teardown().await?;
    Ok(())
}
