use crate::reactor::engine::ValidatorStart;
use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use malachitebft_app_channel::AppMsg;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::time::timeout;

use super::NodeCoordinator;
use crate::bitcoin_client::Client;
use crate::consensus::signing::PrivateKey;
use crate::database::certified_history;
use crate::protocol::coordinator::baseline::Baseline;
use crate::reactor::engine::EngineConfig;
use crate::reactor::mempool_fee_index::MempoolFeeIndex;
use crate::reactor::message::Message;
use crate::reactor::{create_executor_session, start_linked_consensus};
use crate::runtime::ownership::OwnerService;
use crate::runtime::{Decimal, GenesisParameters, GenesisValidator};

fn configuration(dir: &TempDir) -> EngineConfig {
    EngineConfig {
        private_key: PrivateKey::from([7; 32]),
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        persistent_peers: vec![],
        data_dir: dir.path().to_path_buf(),
        consensus_enabled: true,
        validator_start: ValidatorStart::Bootstrap,
        discovery: Default::default(),
    }
}

pub(crate) async fn run() -> Result<Value> {
    let dir = TempDir::new()?;
    let config = configuration(&dir);
    let genesis = GenesisParameters {
        sigma_min: Decimal::from("1"),
        validators: vec![GenesisValidator {
            x_only_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .into(),
            ed25519_pubkey: config.private_key.public_key().as_bytes().to_vec(),
            stake: Decimal::from("100.9999999"),
        }],
    };
    let (coordinator, _reader, writer) =
        NodeCoordinator::open_database(&config, "state.db", Network::Regtest, 100, &genesis)
            .await?;
    let service = OwnerService::new();
    let result = async {
        let (_, session, height, _) = create_executor_session(
            100,
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
        let listener = state
            .engine
            .listen_address()
            .await?
            .context("managed listener missing")?;
        ensure!(
            coordinator.owner.reserve(None).is_err(),
            "running engine lost generation ownership"
        );
        let mut next_config = configuration(&dir);
        next_config.validator_start = ValidatorStart::Resume;
        next_config.listen_addr = listener.clone();
        ensure!(
            NodeCoordinator::open_database(
                &next_config,
                "competing.db",
                Network::Regtest,
                100,
                &genesis
            )
            .await
            .is_err(),
            "competing node acquired writer authority"
        );
        ensure!(
            !dir.path().join("competing.db").exists(),
            "competing writer initialized a database"
        );
        let frontier = certified_history::frontier(&session.conn).await?;
        let next_height = state.current_height;
        let next_params = state.height_params();
        ensure!(
            state.engine.stop(Duration::from_secs(10)).await?,
            "first engine did not join"
        );
        drop(state);

        let mut next = coordinator.start(&next_config, &session.conn).await?;
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
        ensure!(
            next.engine.listen_address().await? == Some(listener),
            "restart changed the listener"
        );
        ensure!(
            certified_history::frontier(&session.conn).await? == frontier,
            "restart changed certified history"
        );
        ensure!(
            next.engine.stop(Duration::from_secs(10)).await?,
            "restarted engine did not join"
        );
        drop(next);
        let reservation = coordinator.owner.reserve(None)?;
        ensure!(
            reservation.generation() == 3,
            "restart did not consume exactly two generations"
        );
        ensure!(fs::metadata(dir.path().join("consensus-validator.wal")).is_ok());
        let baseline = Baseline::for_node(coordinator.genesis.chain)?;
        Ok(json!({
            "chain": hex::encode(coordinator.genesis.chain.0),
            "protocol": hex::encode(coordinator.genesis.protocol.0),
            "era": hex::encode(coordinator.genesis.era),
            "executor_definition": hex::encode(baseline.manifest.executor.0),
            "rounds_started": 2, "engines_joined": 2, "next_generation": reservation.generation(),
            "same_listener": true, "same_era_wal": true, "database_remained_available": true,
            "competing_writer_rejected": true
        }))
    }
    .await;
    service.shutdown();
    result
}
