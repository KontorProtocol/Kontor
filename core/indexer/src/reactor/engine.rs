use std::path::PathBuf;

use anyhow::{Context, Result};

use malachitebft_app_channel::app::config::*;
use malachitebft_app_channel::app::net::Multiaddr;
use malachitebft_app_channel::app::types::Keypair;
use malachitebft_app_channel::{
    Channels, ConsensusContext, EngineHandle, NetworkContext, NetworkIdentity, RequestContext,
    SyncContext, WalContext,
};

use crate::consensus::codec::ProtobufCodec;
use crate::consensus::signing::{Ed25519Provider, PrivateKey};
use crate::consensus::{Address, Ctx};

pub struct EngineConfig {
    pub private_key: PrivateKey,
    pub listen_addr: String,
    pub persistent_peers: Vec<String>,
    pub data_dir: PathBuf,
}

/// NodeConfig implementation for Malachite engine.
#[derive(Clone, Debug, Default)]
struct MalachiteNodeConfig {
    moniker: String,
    consensus: ConsensusConfig,
    value_sync: ValueSyncConfig,
}

impl NodeConfig for MalachiteNodeConfig {
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

pub struct EngineOutput {
    pub channels: Channels<Ctx>,
    pub signing_provider: Ed25519Provider,
    pub address: Address,
    pub _handle: EngineHandle,
}

/// Start the Malachite consensus engine and return channels + metadata.
pub async fn start(config: EngineConfig) -> Result<EngineOutput> {
    let public_key = config.private_key.public_key();
    let address = Address::from_public_key(&public_key);
    let keypair = Keypair::ed25519_from_bytes(config.private_key.inner().to_bytes())
        .context("Failed to create Ed25519 keypair from private key")?;

    let listen_addr: Multiaddr = config
        .listen_addr
        .parse()
        .context("Failed to parse consensus listen address")?;
    let persistent_peers: Vec<Multiaddr> = config
        .persistent_peers
        .iter()
        .map(|s| s.parse())
        .collect::<Result<_, _>>()
        .context("Failed to parse persistent peer address")?;

    let node_config = MalachiteNodeConfig {
        moniker: format!("kontor-{}", &address.to_string()[..8]),
        consensus: ConsensusConfig {
            enabled: true,
            value_payload: ValuePayload::ProposalAndParts,
            p2p: P2pConfig {
                listen_addr,
                persistent_peers,
                ..Default::default()
            },
            ..Default::default()
        },
        value_sync: ValueSyncConfig::default(),
    };

    let ctx = Ctx::new();
    std::fs::create_dir_all(&config.data_dir)
        .context("Failed to create consensus data directory")?;
    let wal_path = config.data_dir.join("consensus.wal");

    let identity = NetworkIdentity::new(
        node_config.moniker.clone(),
        keypair,
        Some(address.to_string()),
    );

    let engine_provider = Ed25519Provider::new(config.private_key.clone());
    let app_provider = Ed25519Provider::new(config.private_key);

    let (channels, handle) = malachitebft_app_channel::start_engine(
        ctx,
        node_config,
        WalContext::new(wal_path, ProtobufCodec),
        NetworkContext::new(identity, ProtobufCodec),
        ConsensusContext::new(address, engine_provider),
        SyncContext::new(ProtobufCodec),
        RequestContext::new(100),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(EngineOutput {
        channels,
        signing_provider: app_provider,
        address,
        _handle: handle,
    })
}
