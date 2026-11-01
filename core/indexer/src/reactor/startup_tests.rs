use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Result, anyhow};
use malachitebft_app_channel::AppMsg;
use malachitebft_core_types::Round;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, sleep, timeout};

use super::certified_fixture;
use super::engine::EngineConfig;
use super::executor::NoopExecutor;
use super::mempool_fee_index::MempoolFeeIndex;
use super::{PruneConfig, Reactor, create_executor_session, run, start_linked_consensus};
use crate::bitcoin_client::Client;
use crate::consensus::Height;
use crate::consensus::signing::PrivateKey;
use crate::database::Writer;
use crate::database::native_contracts::NATIVE_CONTRACTS;
use crate::logging;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::ownership::OwnerService;
use crate::runtime::{BlockingGate, Decimal, GenesisValidator};
use crate::stopper::Shutdown;
use crate::test_utils::{new_test_db, test_genesis};
use bitcoin::Network;

#[tokio::test]
async fn shutdown_during_owned_genesis_keeps_writer_until_publication_stops() -> Result<()> {
    let (reader, writer, (dir, name)) = new_test_db().await?;
    let conn = writer.connection();
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: PrivateKey::from([77; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let gate = Arc::new(BlockingGate::default());
    let owner = OwnerService::new();
    owner.set_startup_compile_gate(gate.clone());
    let mut driver = owner.take_driver().expect("test owner has a driver");
    let shutdown = Shutdown::new();
    let (_block_tx, block_rx) = mpsc::channel(1);
    let (_mempool_tx, mempool_rx) = mpsc::channel(1);
    let (addr_tx, _addr_rx) = watch::channel(None);
    let mut reactor = run(
        1,
        shutdown.signal(),
        owner.clone(),
        writer,
        block_rx,
        mempool_rx,
        None,
        None,
        None,
        EngineConfig {
            private_key: PrivateKey::from([77; 32]),
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            persistent_peers: Vec::new(),
            data_dir: dir.path().to_path_buf(),
            consensus_enabled: true,
            discovery: Default::default(),
        },
        Client::new("".to_string(), "".to_string(), "".to_string())?,
        genesis.clone(),
        None,
        1_000,
        None,
        addr_tx,
        bitcoin::Network::Regtest,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
    );
    let entered = timeout(Duration::from_secs(30), async {
        while !gate.entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let live_roots = owner.active_roots().await;
    shutdown.cancel();
    owner.shutdown();
    let retained = timeout(Duration::from_millis(100), &mut reactor)
        .await
        .is_err();
    gate.release();
    entered?;
    assert_eq!(live_roots, 1);
    assert!(
        retained,
        "reactor released its writer while genesis work was live"
    );
    let outcome = timeout(Duration::from_secs(60), reactor).await??;
    if let Err(error) = &outcome {
        assert!(
            format!("{error:#}").contains("operation-owner node admission closed")
                || format!("{error:#}").contains("operation-owner root capacity closed"),
            "unexpected startup failure: {error:#}"
        );
    }
    assert!(conn.is_autocommit());
    {
        let reader_conn = reader.connection().await?;
        let mut rows = reader_conn
            .query("SELECT id, name FROM contracts ORDER BY id", ())
            .await?;
        let mut published = 0;
        while let Some(row) = rows.next().await? {
            let (name, _) = NATIVE_CONTRACTS
                .get(published)
                .expect("shutdown published beyond the native set");
            assert_eq!(row.get::<i64>(0)?, published as i64 + 1);
            assert_eq!(row.get::<String>(1)?, *name);
            published += 1;
        }
        assert!(published > 0, "active native publication was lost");
        if outcome.is_ok() {
            assert_eq!(published, NATIVE_CONTRACTS.len());
        } else {
            assert!(published < NATIVE_CONTRACTS.len());
        }
        let mut rows = reader_conn
            .query(
                "SELECT (SELECT COUNT(*) FROM contract_provenance WHERE contract_id > ?1)
                  + (SELECT COUNT(*) FROM contract_state WHERE contract_id > ?1)
                  + (SELECT COUNT(*) FROM contract_results WHERE contract_id > ?1)",
                [published as i64],
            )
            .await?;
        assert_eq!(
            rows.next().await?.expect("orphan count").get::<i64>(0)?,
            0,
            "unfinished native publication left durable rows"
        );
    }
    assert_eq!(owner.active_roots().await, 0);
    assert_eq!(owner.quarantined_roots().await, 0);
    assert!(!owner.is_fatal());
    timeout(Duration::from_secs(2), &mut driver).await???;

    // Shutdown closes new admissions after the active publication drains. A
    // fresh owner must complete the native suffix from the committed prefix.
    let resumed_writer = Writer::new(dir.path(), &name).await?;
    let resumed_owner = OwnerService::new();
    let mut resumed_driver = resumed_owner
        .take_driver()
        .expect("resumed owner has a driver");
    let (_, resumed_runtime, _, _) = create_executor_session(
        1,
        &resumed_writer,
        &resumed_owner,
        Client::new("".to_string(), "".to_string(), "".to_string())?,
        &genesis,
        bitcoin::Network::Regtest,
    )
    .await?;
    assert!(resumed_runtime.conn.is_autocommit());
    let reader_conn = reader.connection().await?;
    let mut rows = reader_conn
        .query("SELECT COUNT(*) FROM contracts", ())
        .await?;
    assert_eq!(
        rows.next().await?.expect("contract count").get::<i64>(0)?,
        NATIVE_CONTRACTS.len() as i64
    );
    assert_eq!(resumed_owner.active_roots().await, 0);
    resumed_owner.shutdown();
    timeout(Duration::from_secs(2), &mut resumed_driver).await???;
    Ok(())
}

#[tokio::test]
async fn delayed_get_value_preserves_the_round_proposal_deadline() -> Result<()> {
    logging::setup();
    let key = PrivateKey::from([19; 32]);
    let (_, writer, (dir, _name)) = new_test_db().await?;
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let owner = OwnerService::new();
    let (_, session, last_height, last_hash) = create_executor_session(
        1,
        &writer,
        &owner,
        Client::new(String::new(), String::new(), String::new())?,
        &genesis,
        Network::Regtest,
    )
    .await?;
    let mut consensus = start_linked_consensus(
        EngineConfig {
            private_key: key,
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            persistent_peers: Vec::new(),
            data_dir: dir.path().to_path_buf(),
            consensus_enabled: true,
            discovery: Default::default(),
        },
        &session,
        &owner,
        Network::Regtest,
        None,
        None,
        last_height,
        MempoolFeeIndex::new(None),
    )
    .await?;
    consensus.timeouts.propose = Duration::from_secs(10);
    let shutdown = Shutdown::new();
    let (_block_tx, block_rx) = mpsc::channel(1);
    let (_mempool_tx, mempool_rx) = mpsc::channel(1);
    let (addr_tx, _addr_rx) = watch::channel(None);
    let mut reactor = Reactor::from_session(
        NoopExecutor,
        session,
        Network::Regtest,
        owner,
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
        last_height,
        last_hash,
        addr_tx,
    );
    // Certify and apply the first block before testing the empty-batch deadline.
    // A batch before this block is no longer a legal startup proposal.
    reactor
        .consensus
        .pending_blocks
        .insert(1, certified_fixture::empty_block(1));
    let target_height = Height::new(2);
    let result = timeout(Duration::from_secs(30), async {
        let mut tick = interval(Duration::from_millis(10));
        loop {
            tokio::select! {
                msg = reactor.consensus.channels.consensus.recv() => {
                    let msg = msg.ok_or_else(|| anyhow!("consensus channel closed"))?;
                    match &msg {
                        AppMsg::GetValue { height, round, .. } if *height == target_height && *round == Round::new(0) => {
                            // The engine's propose timer keeps running while the
                            // application is busy and has not handled this request.
                            sleep(Duration::from_secs(5)).await;
                        }
                        AppMsg::StartedRound { height, round, .. } if *height == target_height && *round != Round::new(0) => {
                            return Err(anyhow!("delayed proposal missed round zero"));
                        }
                        AppMsg::Decided { certificate, .. } if certificate.height == target_height => {
                            assert_eq!(certificate.round, Round::new(0));
                            reactor.handle_consensus_msg(msg).await?;
                            return Ok(());
                        }
                        _ => {}
                    }
                    reactor.handle_consensus_msg(msg).await?;
                    reactor.advance().await?;
                }
                _ = tick.tick() => {
                    reactor.try_fulfill_pending_proposal().await?;
                }
            }
        }
    })
    .await;
    reactor
        .consensus
        .engine_handle
        .actor
        .get_cell()
        .stop_and_wait(None, Some(Duration::from_secs(5)))
        .await?;
    result?
}
