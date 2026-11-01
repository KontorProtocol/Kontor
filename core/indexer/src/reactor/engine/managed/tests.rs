use std::fs;

use malachitebft_app_channel::AppMsg;
use tempfile::TempDir;
use tokio::time::timeout;

use super::*;
use crate::bitcoin_client::Client;
use crate::database::certified_history;
use crate::protocol::coordinator::baseline::Baseline;
use crate::protocol::coordinator::genesis::{configured_chain, envelope};
use crate::reactor::mempool_fee_index::MempoolFeeIndex;
use crate::reactor::message::Message;
use crate::reactor::{create_executor_session, start_linked_consensus};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::ownership::OwnerService;
use crate::runtime::{Decimal, GenesisValidator};
use crate::test_utils::test_genesis;

fn engine_config(dir: &TempDir) -> EngineConfig {
    EngineConfig {
        private_key: PrivateKey::from([37; 32]),
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        persistent_peers: vec![],
        data_dir: dir.path().to_path_buf(),
        consensus_enabled: true,
        discovery: Default::default(),
    }
}

#[tokio::test]
async fn admission_precedes_authority_and_exclusive_ownership_precedes_writer() -> Result<()> {
    let dir = TempDir::new()?;
    let config = engine_config(&dir);
    let genesis = test_genesis(&[]);
    let (coordinator, reader, writer) =
        NodeCoordinator::open_database(&config, "state.db", Network::Regtest, 1, &genesis).await?;
    let first = coordinator
        .prepared
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .ownership
        .clone();
    assert_eq!(first.generation(), 1);
    let network_key = first.network_key();
    assert!(
        NodeCoordinator::open_database(&config, "must-not-exist.db", Network::Regtest, 1, &genesis)
            .await
            .is_err()
    );
    assert!(!dir.path().join("must-not-exist.db").exists());
    drop((first, coordinator, reader, writer));
    let (coordinator, reader, writer) =
        NodeCoordinator::open_database(&config, "state.db", Network::Regtest, 1, &genesis).await?;
    let second = coordinator
        .prepared
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .ownership
        .clone();
    assert_eq!(second.generation(), 2);
    assert_eq!(second.network_key(), network_key);
    drop((second, coordinator, reader, writer));

    let unsupported = TempDir::new()?;
    let writer = Writer::new(unsupported.path(), "state.db").await?;
    let conn = writer.connection();
    let chain = configured_chain(Network::Regtest, 1, &envelope(&genesis))?;
    certified_history::initialize(&conn).await?;
    certified_history::begin_baseline(&conn, &Baseline::current(chain)?, 1).await?;
    let before = certified_history::frontier(&conn).await?;
    let mut config = config;
    config.data_dir = unsupported.path().to_path_buf();
    assert!(
        NodeCoordinator::open_database(&config, "state.db", Network::Regtest, 1, &genesis)
            .await
            .is_err()
    );
    assert!(!unsupported.path().join("consensus-authority").exists());
    assert_eq!(certified_history::frontier(&conn).await?, before);
    Ok(())
}

#[tokio::test]
async fn admitted_node_starts_managed_engine_and_reuses_owner_after_join() -> Result<()> {
    let dir = TempDir::new()?;
    let config = engine_config(&dir);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: random_x_only_pubkey(),
        ed25519_pubkey: config.private_key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let (coordinator, _reader, writer) =
        NodeCoordinator::open_database(&config, "state.db", Network::Regtest, 1, &genesis).await?;
    let service = OwnerService::new();
    let (_, session, height, _) = create_executor_session(
        1,
        &writer,
        &service,
        Client::new(String::new(), String::new(), String::new())?,
        &genesis,
        Network::Regtest,
    )
    .await?;
    let mut state = start_linked_consensus(
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
    let ready = timeout(Duration::from_secs(15), state.engine.next())
        .await
        .context("initial managed engine readiness timed out")??;
    let Some(Message::Application(AppMsg::ConsensusReady { reply })) = ready else {
        anyhow::bail!("managed node did not become ready");
    };
    reply
        .send((state.current_height, state.height_params()))
        .map_err(|_| anyhow::anyhow!("ready reply closed"))?;
    let started = timeout(Duration::from_secs(15), state.engine.next())
        .await
        .context("initial managed engine did not start a round")??;
    let Some(Message::Application(AppMsg::StartedRound { reply_value, .. })) = started else {
        anyhow::bail!("managed node did not start a round");
    };
    reply_value
        .send(vec![])
        .map_err(|_| anyhow::anyhow!("started-round reply closed"))?;
    assert!(state.engine.listen_address().await?.is_some());
    assert!(coordinator.owner.reserve(None).is_err());
    let next_height = state.current_height;
    let next_params = state.height_params();
    assert!(state.engine.stop(Duration::from_secs(10)).await?);
    drop(state);

    let next_config = engine_config(&dir);
    let mut next = coordinator.start(&next_config, coordinator.context)?;
    let ready = timeout(Duration::from_secs(15), next.engine.next())
        .await
        .context("restarted managed engine readiness timed out")??;
    let Some(Message::Application(AppMsg::ConsensusReady { reply })) = ready else {
        anyhow::bail!("restarted managed node did not become ready");
    };
    reply
        .send((next_height, next_params))
        .map_err(|_| anyhow::anyhow!("restart ready reply closed"))?;
    let started = timeout(Duration::from_secs(15), next.engine.next())
        .await
        .context("restarted managed engine did not start a round")??;
    let Some(Message::Application(AppMsg::StartedRound { reply_value, .. })) = started else {
        anyhow::bail!("restarted managed node did not start a round");
    };
    reply_value
        .send(vec![])
        .map_err(|_| anyhow::anyhow!("restarted-round reply closed"))?;
    assert!(next.engine.stop(Duration::from_secs(10)).await?);
    drop(next);
    let reservation = coordinator.owner.reserve(None)?;
    assert_eq!(reservation.generation(), 3);
    assert!(
        fs::metadata(dir.path().join(format!(
            "consensus-{}.wal",
            hex::encode(coordinator.context.era)
        )))
        .is_ok()
    );
    service.shutdown();
    Ok(())
}
