use std::time::Duration;

use anyhow::{Result, bail};

use super::ReactorCluster;
use crate::bitcoin_follower::event::BlockEvent;
use crate::consensus::signing::PrivateKey;
use crate::database::Reader;
use crate::database::queries::{get_contract_id_from_address, get_contract_signer_id};
use crate::reactor::build_validator_set;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::GenesisValidator;
use crate::runtime::numerics::{add_decimal, div_decimal, mul_decimal, sub_decimal};
use crate::runtime::staking::{address, api as staking};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Runtime};
use crate::test_utils::test_runtime_with_genesis;

#[derive(Debug, PartialEq)]
struct Rewards {
    supply: Decimal,
    escrow: Decimal,
    stakes: Vec<Decimal>,
    total_stake: Decimal,
}

async fn snapshot(cluster: &ReactorCluster, node: usize, height: u64) -> Result<Rewards> {
    let (dir, name) = &cluster.node_dirs[node];
    let reader = Reader::new(dir.path(), name).await?;
    let conn = reader.connection().await?;
    let mut runtime = Runtime::new_read_only(
        cluster.engine.clone(),
        Runtime::new_linkers(&cluster.engine)?,
        cluster.component_cache.clone(),
        (*conn).clone(),
    )
    .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if staking::last_reward_height(&mut runtime).await? == Some(height) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("node {node} did not settle rewards at height {height}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        token::last_emission_height(&mut runtime).await?,
        Some(height)
    );
    let contract_id = get_contract_id_from_address(&conn, &address())
        .await?
        .unwrap();
    let signer_id = get_contract_signer_id(&conn, contract_id).await?.unwrap();
    for pool in [HolderRef::OrderingPool, HolderRef::StoragePool] {
        assert_eq!(
            token::balance(&mut runtime, pool)
                .await?
                .unwrap_or_default(),
            Decimal::default()
        );
    }
    let mut rows = conn.query(
        "SELECT count(*) FROM contract_state WHERE height > 0 AND (depositor IS NOT NULL OR deposited_gas IS NOT NULL)", (),
    ).await?;
    assert_eq!(rows.next().await?.unwrap().get::<u64>(0)?, 0);
    Ok(Rewards {
        supply: token::total_supply(&mut runtime).await?,
        escrow: token::balance(&mut runtime, HolderRef::SignerId(signer_id))
            .await?
            .unwrap(),
        stakes: staking::get_active_set(&mut runtime)
            .await?
            .into_iter()
            .map(|v| v.stake)
            .collect(),
        total_stake: staking::get_staking_info(&mut runtime).await?.total_stake,
    })
}

#[tokio::test]
async fn prod_reactor_ordering_rewards_survive_rollback_restart_and_late_join() -> Result<()> {
    let mut cluster = ReactorCluster::start_with(4, 3).await?;
    cluster.wait_for_ready().await;
    cluster.mine_empty_and_send();
    let block = cluster.wait_for_block(1, Duration::from_secs(60)).await;
    ReactorCluster::assert_checkpoints_match(&block, 1, 3);
    let first = snapshot(&cluster, 0, 1).await?;
    let initial = Decimal::from("400");
    // LiteExecutor's shared test signer is prefunded at genesis; emission samples
    // all circulating supply, not just escrowed stake.
    let paid = sub_decimal(first.escrow, initial)?;
    let initial_supply = sub_decimal(first.supply, paid)?;
    let expected = div_decimal(
        div_decimal(
            div_decimal(
                mul_decimal(initial_supply, Decimal::from("5"))?,
                Decimal::from("100"),
            )?,
            Decimal::from("52560"),
        )?,
        Decimal::from("10"),
    )?;
    assert_eq!(paid, expected);
    assert!(paid > Decimal::default());
    assert_eq!(first.total_stake, first.escrow);
    let mut sum = Decimal::default();
    for stake in &first.stakes {
        assert!(*stake > Decimal::from("100"));
        sum = add_decimal(sum, *stake)?;
    }
    assert_eq!(sum, first.escrow);
    assert_eq!(snapshot(&cluster, 1, 1).await?, first);
    cluster.mine_empty_and_send();
    cluster.wait_for_block(2, Duration::from_secs(60)).await;
    let second = snapshot(&cluster, 0, 2).await?;
    cluster.mock_bitcoin().reset_to(1);
    cluster.send_block_event(BlockEvent::Rollback { to_height: 1 });
    cluster.wait_for_rollback(1, Duration::from_secs(60)).await;
    assert_eq!(snapshot(&cluster, 0, 1).await?, first);
    cluster.mine_empty_and_send();
    cluster.wait_for_block(2, Duration::from_secs(60)).await;
    assert_eq!(snapshot(&cluster, 0, 2).await?, second);
    cluster.restart_node(1).await;
    assert_eq!(snapshot(&cluster, 1, 2).await?, second);
    assert_eq!(cluster.add_node().await?, 3);
    for event in cluster.mock_bitcoin().get_all_block_events() {
        cluster.block_txs[3].try_send(event)?;
    }
    assert_eq!(snapshot(&cluster, 3, 2).await?, second);
    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn compounded_rewards_cross_voting_power_boundary_and_rollback() -> Result<()> {
    let key = PrivateKey::from([1; 32]);
    let (mut runtime, _dir, _name) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100.9999999"),
    }])
    .await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    runtime.set_context(1, None, None, None).await;
    assert_eq!(
        build_validator_set(&mut runtime)
            .await?
            .total_voting_power(),
        100
    );
    runtime.storage.savepoint().await?;
    let emission = token::mint_emission(&mut runtime, &core, true).await??;
    staking::distribute_ordering_reward(&mut runtime, &core, emission.ordering_minted).await??;
    assert_eq!(
        build_validator_set(&mut runtime)
            .await?
            .total_voting_power(),
        101
    );
    runtime.storage.rollback().await?;
    assert_eq!(
        build_validator_set(&mut runtime)
            .await?
            .total_voting_power(),
        100
    );
    Ok(())
}
