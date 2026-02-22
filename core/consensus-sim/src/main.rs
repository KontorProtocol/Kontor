use eyre::Result;
use tracing::info;

use malachitebft_app_channel::app::config::*;
use malachitebft_app_channel::app::types::core::VotingPower;
use malachitebft_app_channel::app::types::Keypair;
use malachitebft_app_channel::{
    ConsensusContext, NetworkContext, NetworkIdentity, RequestContext, SyncContext, WalContext,
};
use malachitebft_test::codec::proto::ProtobufCodec;
use malachitebft_test::{
    Address, Ed25519Provider, Genesis, PrivateKey, TestContext, Validator, ValidatorSet,
};

use indexer::consensus::app::{self, State};

/// Minimal config implementing NodeConfig for start_engine.
#[derive(Clone, Debug, Default)]
struct SimConfig {
    moniker: String,
    consensus: ConsensusConfig,
    value_sync: ValueSyncConfig,
}

impl NodeConfig for SimConfig {
    fn moniker(&self) -> &str {
        &self.moniker
    }
    fn consensus(&self) -> &ConsensusConfig {
        &self.consensus
    }
    fn consensus_mut(&mut self) -> &mut ConsensusConfig {
        &mut self.consensus
    }
    fn value_sync(&self) -> &ValueSyncConfig {
        &self.value_sync
    }
    fn value_sync_mut(&mut self) -> &mut ValueSyncConfig {
        &mut self.value_sync
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().unwrap()),
        )
        .init();

    let mut rng = rand::thread_rng();
    let private_key = PrivateKey::generate(&mut rng);
    let public_key = private_key.public_key();
    let address = Address::from_public_key(&public_key);
    let keypair = Keypair::ed25519_from_bytes(private_key.inner().to_bytes())?;

    info!(%address, "Starting single-validator consensus simulator");

    let validator = Validator::new(public_key, 1 as VotingPower);
    let validator_set = ValidatorSet::new(vec![validator]);
    let genesis = Genesis { validator_set };

    let ctx = TestContext::new();

    let wal_dir = tempfile::tempdir()?;
    let wal_path = wal_dir.path().join("consensus.wal");

    let config = SimConfig {
        moniker: "sim-node-0".to_string(),
        consensus: ConsensusConfig {
            enabled: true,
            value_payload: ValuePayload::ProposalAndParts,
            p2p: P2pConfig {
                listen_addr: TransportProtocol::Tcp.multiaddr("127.0.0.1", 27000),
                persistent_peers: vec![],
                ..Default::default()
            },
            ..Default::default()
        },
        value_sync: ValueSyncConfig::default(),
    };

    let identity = NetworkIdentity::new(
        config.moniker.clone(),
        keypair,
        Some(address.to_string()),
    );

    // Need separate providers — Ed25519Provider doesn't impl Clone
    let engine_provider = Ed25519Provider::new(private_key.clone());
    let app_provider = Ed25519Provider::new(private_key);

    let (mut channels, _engine_handle) = malachitebft_app_channel::start_engine(
        ctx,
        config,
        WalContext::new(wal_path, ProtobufCodec),
        NetworkContext::new(identity, ProtobufCodec),
        ConsensusContext::new(address, engine_provider),
        SyncContext::new(ProtobufCodec),
        RequestContext::new(100),
    )
    .await?;

    info!("Engine started, entering app loop");

    let mut state = State::new(app_provider, genesis, address);
    app::run(&mut state, &mut channels)
        .await
        .map_err(|e| eyre::eyre!("{e}"))?;

    Ok(())
}
