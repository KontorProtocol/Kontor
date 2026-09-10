use std::slice::from_ref;

use anyhow::Result;
use indexer_types::Block;
use tempfile::TempDir;
use tokio::sync::{mpsc, watch};

use super::consensus_state::DeferredDecision;
use super::engine::EngineConfig;
use super::executor::NoopExecutor;
use super::mempool_fee_index::MempoolFeeIndex;
use super::{PruneConfig, Reactor, stake_to_voting_power, start_consensus};
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Height, Value};
use crate::database::queries::{
    get_checkpoint_latest, get_contract_id_from_address, get_contract_signer_id,
};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::filestorage::address as filestorage_address;
use crate::runtime::filestorage::api::{self as filestorage, ChallengeStatus};
use crate::runtime::filestorage::settlement_tests::{StorageFixture, at_height};
use crate::runtime::numerics::{add_decimal, mul_decimal, sub_decimal};
use crate::runtime::staking::{address, api as staking};
use crate::runtime::token::api as token;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, GenesisValidator, Runtime, Storage};
use crate::stopper::Shutdown;
use crate::test_utils::{new_mock_block_hash, test_runtime_with_genesis};

async fn reactor(runtime: Runtime, dir: &TempDir) -> Result<Reactor<NoopExecutor>> {
    let mut runtime = runtime;
    let consensus = start_consensus(
        EngineConfig {
            private_key: PrivateKey::from([17; 32]),
            listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
            persistent_peers: Vec::new(),
            data_dir: dir.path().to_path_buf(),
            consensus_enabled: false,
            discovery_enabled: false,
        },
        &mut runtime,
        None,
        None,
        1,
        MempoolFeeIndex::new(None),
    )
    .await?;
    let shutdown = Shutdown::new();
    let (_block_tx, block_rx) = mpsc::channel(1);
    let (_mempool_tx, mempool_rx) = mpsc::channel(1);
    let (addr_tx, _addr_rx) = watch::channel(None);
    Ok(Reactor::new(
        NoopExecutor,
        runtime,
        block_rx,
        mempool_rx,
        shutdown.signal(),
        None,
        None,
        None,
        consensus,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        2015,
        Some(new_mock_block_hash(2015)),
        addr_tx,
    ))
}

async fn block(reactor: &mut Reactor<NoopExecutor>, height: u64) -> Result<()> {
    let block = Block {
        height,
        hash: new_mock_block_hash(height as u32),
        prev_hash: new_mock_block_hash((height - 1) as u32),
        transactions: Vec::new(),
    };
    let decision = DeferredDecision {
        consensus_height: Height::new(height - 2015),
        value: Value::new_block(height, block.hash),
        certificate: Vec::new(),
        certified_txs: None,
    };
    reactor.handle_block(block, &decision).await
}

async fn escrow(runtime: &mut Runtime) -> Result<Decimal> {
    let conn = runtime.get_storage_conn();
    let id = get_contract_id_from_address(&conn, &address())
        .await?
        .unwrap();
    let signer = get_contract_signer_id(&conn, id).await?.unwrap();
    Ok(token::balance(runtime, HolderRef::SignerId(signer))
        .await?
        .unwrap())
}

async fn storage_escrow(runtime: &mut Runtime) -> Result<Decimal> {
    let conn = runtime.get_storage_conn();
    let id = get_contract_id_from_address(&conn, &filestorage_address())
        .await?
        .unwrap();
    let signer = get_contract_signer_id(&conn, id).await?.unwrap();
    Ok(token::balance(runtime, HolderRef::SignerId(signer))
        .await?
        .unwrap_or_default())
}

#[tokio::test]
async fn block_penalties_converge_and_survive_rollback_and_runtime_reopen() -> Result<()> {
    let pubkeys: Vec<_> = (0..3).map(|_| random_x_only_pubkey()).collect();
    let validator = GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    };
    let mut checkpoints = Vec::new();
    for _ in 0..2 {
        let (mut runtime, dir, _name) = test_runtime_with_genesis(from_ref(&validator)).await?;
        let fixture = StorageFixture::new(&mut runtime, 2, &pubkeys).await?;
        let bond = add_decimal(fixture.requirements[0], fixture.requirements[1])?;
        fixture.join(&mut runtime, bond).await?;
        let expired = fixture.challenge(&mut runtime, 0, 0).await?;
        let future = fixture.challenge(&mut runtime, 1, 2000).await?;
        let id = fixture.hosts[0].0;
        let supply = token::total_supply(&mut runtime).await?;
        let before_escrow = escrow(&mut runtime).await?;
        at_height(&mut runtime, 2015).await?;
        let mut reactor = reactor(runtime, &dir).await?;
        block(&mut reactor, 2016).await?;
        let rt = &mut reactor.runtime;
        let paid = sub_decimal(
            staking::get_staking_info(rt).await?.total_stake,
            validator.stake,
        )?;
        let storage_paid = storage_escrow(rt).await?;
        let earned_before_exhaustion = filestorage::reward_balance(rt, id).await??;
        assert!(earned_before_exhaustion > Decimal::default());
        assert_eq!(
            token::total_supply(rt).await?,
            sub_decimal(add_decimal(add_decimal(supply, paid)?, storage_paid)?, bond)?
        );
        assert_eq!(
            escrow(rt).await?,
            sub_decimal(add_decimal(before_escrow, paid)?, bond)?
        );
        assert_eq!(
            staking::get_stake(rt, &id.to_string())
                .await?
                .unwrap()
                .stake,
            Decimal::default()
        );
        for challenge in [&expired, &future] {
            assert_eq!(
                filestorage::get_challenge(rt, challenge)
                    .await?
                    .unwrap()
                    .status,
                ChallengeStatus::Settled
            );
        }
        assert!(!filestorage::has_storage_obligations(rt, id).await?);
        assert_eq!(
            filestorage::get_node_reservation(rt, id).await?,
            Decimal::default()
        );
        let checkpoint = get_checkpoint_latest(&rt.get_storage_conn())
            .await?
            .unwrap()
            .hash;
        checkpoints.push(checkpoint.clone());

        reactor.rollback(2015).await?;
        let rt = &mut reactor.runtime;
        assert_eq!(
            staking::get_stake(rt, &id.to_string())
                .await?
                .unwrap()
                .stake,
            bond
        );
        assert_eq!(filestorage::get_node_reservation(rt, id).await?, bond);
        assert_eq!(
            filestorage::get_challenge(rt, &expired)
                .await?
                .unwrap()
                .status,
            ChallengeStatus::Active
        );
        assert_eq!(token::total_supply(rt).await?, supply);
        assert_eq!(storage_escrow(rt).await?, Decimal::default());
        assert_eq!(
            filestorage::reward_balance(rt, id).await??,
            Decimal::default()
        );
        block(&mut reactor, 2016).await?;
        assert_eq!(
            get_checkpoint_latest(&reactor.db_conn())
                .await?
                .unwrap()
                .hash,
            checkpoint
        );

        // A fresh runtime must derive settlement/cleanup solely from persisted state.
        let rt = &reactor.runtime;
        reactor.runtime = Runtime::new_with(
            rt.engine.clone(),
            Runtime::new_linkers(&rt.engine)?,
            rt.component_cache.clone(),
            Storage::builder()
                .height(2016)
                .conn(rt.get_storage_conn())
                .build(),
        )
        .await?;
        let supply_before_claim = token::total_supply(&mut reactor.runtime).await?;
        let burner_before_claim = token::balance(&mut reactor.runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        assert_eq!(
            filestorage::claim_rewards(&mut reactor.runtime, &fixture.hosts[0].1).await??,
            earned_before_exhaustion
        );
        let fees = sub_decimal(
            token::balance(&mut reactor.runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default(),
            burner_before_claim,
        )?;
        assert_eq!(
            token::total_supply(&mut reactor.runtime).await?,
            sub_decimal(supply_before_claim, fees)?
        );
        let topup = Decimal::from("10");
        staking::add_stake(&mut reactor.runtime, &fixture.hosts[0].1, topup).await??;
        block(&mut reactor, 2017).await?;
        assert_eq!(
            staking::get_stake(&mut reactor.runtime, &id.to_string())
                .await?
                .unwrap()
                .stake,
            topup
        );
    }
    assert_eq!(checkpoints[0], checkpoints[1]);
    Ok(())
}

#[tokio::test]
async fn exhausting_last_validator_commits_the_penalty_before_halting() -> Result<()> {
    let pubkeys: Vec<_> = (0..3).map(|_| random_x_only_pubkey()).collect();
    let validator = GenesisValidator {
        x_only_pubkey: pubkeys[0].clone(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("1"),
    };
    let (mut runtime, dir, _name) = test_runtime_with_genesis(&[validator]).await?;
    let fixture = StorageFixture::new(&mut runtime, 1, &pubkeys).await?;
    let required = fixture.requirements[0];
    fixture.join(&mut runtime, required).await?;
    let challenge = fixture.challenge(&mut runtime, 0, 0).await?;
    let supply = token::total_supply(&mut runtime).await?;
    let before_escrow = escrow(&mut runtime).await?;
    let bonded = add_decimal(required, Decimal::from("1"))?;
    at_height(&mut runtime, 2015).await?;
    let mut reactor = reactor(runtime, &dir).await?;
    let error = block(&mut reactor, 2016).await.unwrap_err();
    assert!(format!("{error:#}").contains("validator set is empty"));
    assert_eq!(reactor.last_height, 2016);
    let rt = &mut reactor.runtime;
    assert!(staking::get_active_set(rt).await?.is_empty());
    // This block's ordering reward was credited and then burned with the bond.
    let storage_paid = storage_escrow(rt).await?;
    assert_eq!(
        token::total_supply(rt).await?,
        sub_decimal(add_decimal(supply, storage_paid)?, bonded)?
    );
    assert!(filestorage::reward_balance(rt, fixture.hosts[0].0).await?? > Decimal::default());
    assert_eq!(escrow(rt).await?, sub_decimal(before_escrow, bonded)?);
    assert_eq!(
        token::balance(rt, HolderRef::OrderingPool)
            .await?
            .unwrap_or_default(),
        Decimal::default()
    );
    assert_eq!(
        filestorage::get_challenge(rt, &challenge)
            .await?
            .unwrap()
            .status,
        ChallengeStatus::Settled
    );
    assert!(!filestorage::has_storage_obligations(rt, fixture.hosts[0].0).await?);
    Ok(())
}

#[test]
fn fractional_balances_cannot_enter_consensus_as_zero_power() {
    for stake in ["0", "0.5", "0.999999999999999999"] {
        assert!(stake_to_voting_power(Decimal::from(stake)).is_err());
    }
    assert_eq!(stake_to_voting_power(Decimal::from("1")).unwrap(), 1);
    assert_eq!(stake_to_voting_power(Decimal::from("1.9")).unwrap(), 1);
}

#[tokio::test]
async fn fractional_last_validator_leaves_consensus_but_keeps_storage_obligations() -> Result<()> {
    let pubkeys: Vec<_> = (0..3).map(|_| random_x_only_pubkey()).collect();
    let validator = GenesisValidator {
        x_only_pubkey: pubkeys[0].clone(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("1"),
    };
    let (mut runtime, dir, _name) = test_runtime_with_genesis(&[validator]).await?;
    let fixture = StorageFixture::new(&mut runtime, 1, &pubkeys).await?;
    let required = fixture.requirements[0];
    let penalty = mul_decimal(required, Decimal::from("30"))?;
    fixture
        .join(&mut runtime, sub_decimal(penalty, Decimal::from("0.5"))?)
        .await?;
    let challenge = fixture.challenge(&mut runtime, 0, 0).await?;
    let node = fixture.hosts[0].0;
    let bonded = staking::get_stake(&mut runtime, &node.to_string())
        .await?
        .unwrap()
        .stake;
    at_height(&mut runtime, 2015).await?;
    let mut reactor = reactor(runtime, &dir).await?;
    let error = block(&mut reactor, 2016).await.unwrap_err();
    assert!(format!("{error:#}").contains("validator set is empty"));
    assert_eq!(reactor.last_height, 2016);
    let rt = &mut reactor.runtime;
    let remaining = staking::get_stake(rt, &node.to_string())
        .await?
        .unwrap()
        .stake;
    assert!(remaining > Decimal::default() && remaining < Decimal::from("1"));
    assert!(staking::get_active_set(rt).await?.is_empty());
    assert_eq!(
        staking::get_staking_info(rt).await?.total_stake,
        Decimal::default()
    );
    assert!(filestorage::has_storage_obligations(rt, node).await?);
    assert!(filestorage::is_node_in_agreement(rt, &fixture.agreements[0], node).await?);
    assert!(!filestorage::is_bond_cleanup_pending(rt, node).await?);
    assert_eq!(filestorage::get_node_reservation(rt, node).await?, required);
    assert_eq!(
        filestorage::get_challenge(rt, &challenge)
            .await?
            .unwrap()
            .status,
        ChallengeStatus::Settled
    );
    reactor.rollback(2015).await?;
    assert_eq!(
        staking::get_staking_info(&mut reactor.runtime)
            .await?
            .total_stake,
        bonded
    );
    assert_eq!(
        staking::get_active_set(&mut reactor.runtime).await?.len(),
        1
    );
    Ok(())
}
