use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::Network;
use malachitebft_app_channel::AppMsg;
use malachitebft_app_channel::app::engine::host::SyncedValueOutcome;
use malachitebft_app_channel::app::types::codec::Codec;
use malachitebft_core_types::Round;
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

use super::certified_fixture;
use super::engine::{EngineConfig, NodeCoordinator, ValidatorStart};
use super::executor::RuntimeExecutor;
use super::mempool_fee_index::MempoolFeeIndex;
use super::message::Message;
use super::{PruneConfig, Reactor, create_executor_session, start_linked_consensus};
use crate::bitcoin_client::Client;
use crate::consensus::codec::ProtobufCodec;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Height, Value};
use crate::database::certified_history::{self, proposals};
use crate::database::connection::new_connection;
use crate::runtime::ownership::OwnerService;
use crate::runtime::{Decimal, GenesisParameters, GenesisValidator};
use crate::stopper::Shutdown;
use crate::test_utils::test_genesis;

async fn managed_reactor(
    directory: &Path,
    genesis: &GenesisParameters,
    key: PrivateKey,
    start: ValidatorStart,
) -> Result<(Reactor<RuntimeExecutor>, Arc<NodeCoordinator>)> {
    let config = EngineConfig {
        private_key: key,
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        persistent_peers: Vec::new(),
        data_dir: directory.to_path_buf(),
        consensus_enabled: true,
        validator_start: start,
        discovery: Default::default(),
    };
    let (coordinator, _reader, writer) = NodeCoordinator::open_database(
        &config,
        "certified-fixture.db",
        Network::Regtest,
        1,
        genesis,
    )
    .await?;
    let service = OwnerService::new();
    let (executor, session, height, hash) = create_executor_session(
        1,
        &writer,
        &service,
        Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?,
        genesis,
        Network::Regtest,
    )
    .await?;
    let consensus = start_linked_consensus(
        config,
        Some(&coordinator),
        &session,
        &service,
        Network::Regtest,
        None,
        None,
        height,
        MempoolFeeIndex::new(None),
    )
    .await?;
    let (_, blocks) = mpsc::channel(1);
    let (_, mempool) = mpsc::channel(1);
    let (address, _) = watch::channel(None);
    let reactor = Reactor::from_session(
        executor,
        session,
        Network::Regtest,
        service,
        blocks,
        mempool,
        Shutdown::new().signal(),
        None,
        None,
        None,
        consensus,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        height,
        hash,
        address,
    );
    Ok((reactor, coordinator))
}

#[tokio::test]
async fn engine_replays_decision_without_peers_after_application_restart() -> Result<()> {
    let key = PrivateKey::from([17; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let directory = TempDir::new()?;
    let (mut reactor, coordinator) = managed_reactor(
        directory.path(),
        &genesis,
        key.clone(),
        ValidatorStart::Bootstrap,
    )
    .await?;
    reactor
        .consensus
        .pending_blocks
        .insert(1, certified_fixture::empty_block(1));
    // Stop at a real engine decision before the application receives it. The
    // restarted engine must recover without peers or fabricated sync callbacks.
    let decision = timeout(Duration::from_secs(30), async {
        loop {
            let message = reactor
                .consensus
                .engine
                .next()
                .await?
                .context("engine stopped")?;
            if matches!(&message, Message::Application(AppMsg::Decided { .. })) {
                break Ok::<_, anyhow::Error>(message);
            }
            reactor.handle_consensus_msg(message).await?;
        }
    })
    .await??;
    let Message::Application(AppMsg::Decided { certificate, .. }) = &decision else {
        unreachable!()
    };
    let expected_id = certificate.value_id;
    let context = reactor.consensus.protocol_context;
    assert_eq!(
        certified_history::frontier(&reactor.db_conn())
            .await?
            .authenticated_height,
        0
    );
    assert!(
        proposals::exact(&reactor.db_conn(), Height::new(1), expected_id, context)
            .await?
            .is_some()
    );
    assert!(
        reactor
            .consensus
            .engine
            .stop(Duration::from_secs(5))
            .await?
    );
    drop(decision);
    drop(reactor);
    drop(coordinator);

    let wal = directory.path().join("consensus-validator.wal");
    let displaced = directory.path().join("temporarily-displaced.wal");
    fs::rename(&wal, &displaced)?;
    let refusal = managed_reactor(
        directory.path(),
        &genesis,
        key.clone(),
        ValidatorStart::Resume,
    )
    .await
    .err()
    .context("resume accepted a missing unfinished validator WAL")?;
    assert!(format!("{refusal:#}").contains("unfinished signed height lacks its WAL"));
    fs::rename(&displaced, &wal)?;

    let (mut reactor, _coordinator) =
        managed_reactor(directory.path(), &genesis, key, ValidatorStart::Resume).await?;
    let mut redelivered = 0;
    timeout(Duration::from_secs(30), async {
        loop {
            let message = reactor.consensus.engine.next().await?.context("restarted engine stopped")?;
            if let Message::Application(AppMsg::Decided { certificate, .. }) = &message {
                assert_eq!(certificate.value_id, expected_id);
                redelivered += 1;
            }
            if matches!(&message, Message::Application(AppMsg::StartedRound { height, .. }) if *height == Height::new(2)) {
                break;
            }
            reactor.handle_consensus_msg(message).await?;
            reactor.advance().await?;
        }
        Ok::<_, anyhow::Error>(())
    }).await??;
    assert_eq!(redelivered, 1);
    let conn = reactor.db_conn();
    assert_eq!(certified_history::frontier(&conn).await?.closed_height, 1);
    assert_eq!(
        conn.query("SELECT COUNT(*) FROM certified_decisions", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<i64>(0)?,
        1
    );
    assert!(
        proposals::exact(&conn, Height::new(1), expected_id, context)
            .await?
            .is_none()
    );
    assert!(
        reactor
            .consensus
            .engine
            .stop(Duration::from_secs(5))
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn failed_local_persistence_does_not_release_proposal_reply() -> Result<()> {
    let key = PrivateKey::from([17; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let directory = TempDir::new()?;
    let mut reactor = certified_fixture::reactor(directory.path(), &genesis, key, 1).await?;
    reactor.consensus.current_round = Round::new(0);
    reactor.consensus.current_proposer = Some(reactor.consensus.address);
    reactor
        .consensus
        .pending_blocks
        .insert(1, certified_fixture::empty_block(1));
    reactor.db_conn().execute_batch("CREATE TRIGGER interrupt_proposal BEFORE INSERT ON consensus_proposal_inputs BEGIN SELECT RAISE(ABORT, 'injected proposal failure'); END").await?;
    let (reply, received) = oneshot::channel();
    assert!(
        reactor
            .handle_get_value(
                Height::new(1),
                Round::new(0),
                Duration::from_secs(10),
                reply
            )
            .await
            .is_err()
    );
    assert!(received.await.is_err());
    assert!(
        proposals::normal(
            &reactor.db_conn(),
            Height::new(1),
            Round::new(0),
            reactor.consensus.protocol_context
        )
        .await?
        .is_none()
    );
    assert!(
        reactor
            .consensus
            .engine
            .stop(Duration::from_secs(5))
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn synced_bodies_are_durable_without_claiming_normal_round_slots() -> Result<()> {
    let key = PrivateKey::from([17; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let directory = TempDir::new()?;
    let mut reactor = certified_fixture::reactor(directory.path(), &genesis, key, 1).await?;
    let context = reactor.consensus.protocol_context;
    let height = Height::new(1);
    let round = Round::new(0);
    let block = certified_fixture::empty_block(1);
    let normal = Value::from_input(block.exact_input(context)?)?;
    let other_block = certified_fixture::block(1, block.prev_hash, 11, Vec::new());
    let synced = Value::from_input(other_block.exact_input(context)?)?;
    for value in [&synced, &synced] {
        let (reply, received) = oneshot::channel();
        reactor
            .handle_consensus_msg(AppMsg::ProcessSyncedValue {
                height,
                round,
                proposer: reactor.consensus.address,
                value_bytes: ProtobufCodec.encode(value)?,
                reply,
            })
            .await?;
        assert!(
            matches!(received.await?, SyncedValueOutcome::Verdict(proposal) if proposal.value == synced)
        );
        assert!(!proposals::has_normal(&reactor.db_conn(), height, round).await?);
    }
    certified_fixture::proposal(&mut reactor, normal.clone(), height, round).await?;
    let (reply, received) = oneshot::channel();
    reactor
        .handle_consensus_msg(AppMsg::ProcessSyncedValue {
            height,
            round,
            proposer: reactor.consensus.address,
            value_bytes: ProtobufCodec.encode(&synced)?,
            reply,
        })
        .await?;
    assert!(matches!(received.await?, SyncedValueOutcome::Verdict(_)));
    assert_eq!(
        proposals::normal(&reactor.db_conn(), height, round, context)
            .await?
            .unwrap()
            .value,
        normal
    );
    for (request_height, bytes, transient) in [
        (Height::new(2), ProtobufCodec.encode(&synced)?, true),
        (height, vec![0xff].into(), false),
    ] {
        let (reply, received) = oneshot::channel();
        reactor
            .handle_consensus_msg(AppMsg::ProcessSyncedValue {
                height: request_height,
                round,
                proposer: reactor.consensus.address,
                value_bytes: bytes,
                reply,
            })
            .await?;
        assert!(matches!(
            (received.await?, transient),
            (SyncedValueOutcome::LocalTransientError, true)
                | (SyncedValueOutcome::PeerFault, false)
        ));
    }
    let conn = reactor.db_conn();
    assert_eq!(
        conn.query("SELECT COUNT(*) FROM consensus_proposal_inputs", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get::<i64>(0)?,
        2
    );
    assert!(
        reactor
            .consensus
            .engine
            .stop(Duration::from_secs(5))
            .await?
    );
    drop(reactor);
    let conn = new_connection(directory.path(), "certified-fixture.db").await?;
    assert_eq!(
        proposals::exact(&conn, height, synced.id(), context).await?,
        Some(synced)
    );
    Ok(())
}
