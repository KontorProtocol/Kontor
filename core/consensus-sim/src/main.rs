use clap::Parser;
use eyre::Result;
use tracing::{Instrument, info};

use malachitebft_app_channel::app::config::*;
use malachitebft_app_channel::app::types::Keypair;
use malachitebft_app_channel::app::types::core::VotingPower;
use malachitebft_app_channel::{
    ConsensusContext, NetworkContext, NetworkIdentity, RequestContext, SyncContext, WalContext,
};

use indexer::consensus::codec::ProtobufCodec;
use indexer::consensus::signing::{Ed25519Provider, PrivateKey};
use indexer::consensus::{Address, Ctx, Genesis, Validator, ValidatorSet};

use indexer::consensus::app::{self, State};

const CONSENSUS_BASE_PORT: usize = 27000;

#[derive(Parser)]
#[command(name = "consensus-sim")]
struct Args {
    /// Number of validators to run
    #[arg(long, default_value_t = 1)]
    validators: usize,
}

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

fn make_config(index: usize, total: usize) -> SimConfig {
    let persistent_peers: Vec<_> = (0..total)
        .filter(|j| *j != index)
        .map(|j| TransportProtocol::Tcp.multiaddr("127.0.0.1", CONSENSUS_BASE_PORT + j))
        .collect();

    SimConfig {
        moniker: format!("sim-node-{index}"),
        consensus: ConsensusConfig {
            enabled: true,
            value_payload: ValuePayload::ProposalAndParts,
            p2p: P2pConfig {
                listen_addr: TransportProtocol::Tcp
                    .multiaddr("127.0.0.1", CONSENSUS_BASE_PORT + index),
                persistent_peers,
                ..Default::default()
            },
            ..Default::default()
        },
        value_sync: ValueSyncConfig::default(),
    }
}

async fn run_node(
    index: usize,
    private_key: PrivateKey,
    genesis: Genesis,
    config: SimConfig,
) -> Result<()> {
    let public_key = private_key.public_key();
    let address = Address::from_public_key(&public_key);
    let keypair = Keypair::ed25519_from_bytes(private_key.inner().to_bytes())?;

    info!(%address, "Starting validator");

    let ctx = Ctx::new();
    let wal_dir = tempfile::tempdir()?;
    let wal_path = wal_dir.path().join("consensus.wal");

    let identity = NetworkIdentity::new(config.moniker.clone(), keypair, Some(address.to_string()));

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

    info!(node = index, "Engine started, entering app loop");

    let mut state = State::new(app_provider, genesis, address);
    app::run(&mut state, &mut channels)
        .await
        .map_err(|e| eyre::eyre!("{e}"))?;

    drop(wal_dir);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    let n = args.validators;

    let mut rng = rand::thread_rng();
    let private_keys: Vec<PrivateKey> = (0..n).map(|_| PrivateKey::generate(&mut rng)).collect();

    let validators: Vec<Validator> = private_keys
        .iter()
        .map(|pk| Validator::new(pk.public_key(), 1 as VotingPower))
        .collect();

    let validator_set = ValidatorSet::new(validators);
    let genesis = Genesis { validator_set };

    info!(validators = n, "Starting consensus simulator");

    let mut join_set = tokio::task::JoinSet::new();

    for (i, private_key) in private_keys.into_iter().enumerate() {
        let genesis = genesis.clone();
        let config = make_config(i, n);
        join_set.spawn(
            async move {
                if let Err(e) = run_node(i, private_key, genesis, config).await {
                    tracing::error!(node = i, error = %e, "Node exited with error");
                }
            }
            .instrument(tracing::info_span!("validator", id = i)),
        );
    }

    while let Some(result) = join_set.join_next().await {
        if let Err(e) = result {
            tracing::error!(error = %e, "Node task panicked");
        }
    }

    Ok(())
}
