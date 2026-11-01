use std::time::Instant;

use malachitebft_app::config::{
    BootstrapProtocol, ConsensusConfig, DiscoveryConfig, GossipSubConfig, NodeConfig, P2pConfig,
    PubSubProtocol, Selector, ValuePayload, ValueSyncConfig,
};
use malachitebft_app::types::Keypair;

use crate::api::{Bootstrap, EngineConfig, EngineError, PeerSelection};
use crate::bridge_types::check_length;

pub(crate) struct Config {
    moniker: String,
    consensus: ConsensusConfig,
    sync: ValueSyncConfig,
}

pub(crate) struct Prepared {
    pub config: Config,
    pub keypair: Keypair,
    pub deadline: Instant,
}

impl Config {
    pub(crate) fn prepare(input: &EngineConfig, validator: bool) -> Result<Prepared, EngineError> {
        let invalid = |reason: &str| EngineError::InvalidConfiguration(reason.into());
        if input.generation == 0 || input.channel_capacity == 0 {
            return Err(invalid("generation and channel capacity must be positive"));
        }
        if input.readiness_timeout.is_zero() {
            return Err(invalid("readiness timeout must be positive"));
        }
        let deadline = Instant::now()
            .checked_add(input.readiness_timeout)
            .ok_or_else(|| invalid("readiness deadline overflow"))?;
        let listen_addr = input
            .listen_address
            .parse()
            .map_err(|_| invalid("invalid listen address"))?;
        check_length(input.persistent_peers.len())
            .map_err(|_| invalid("too many persistent peers"))?;
        let persistent_peers = input
            .persistent_peers
            .iter()
            .map(|peer| {
                peer.parse()
                    .map_err(|_| invalid("invalid persistent peer address"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let keypair = Keypair::ed25519_from_bytes(input.network_key)
            .map_err(|_| invalid("invalid network key"))?;
        let config = Self {
            moniker: input.moniker.clone(),
            consensus: ConsensusConfig {
                enabled: validator,
                value_payload: ValuePayload::ProposalAndParts,
                p2p: P2pConfig {
                    listen_addr,
                    persistent_peers,
                    discovery: DiscoveryConfig {
                        enabled: input.discovery.enabled,
                        bootstrap_protocol: match input.discovery.bootstrap {
                            Bootstrap::Kademlia => BootstrapProtocol::Kademlia,
                            Bootstrap::Full => BootstrapProtocol::Full,
                        },
                        selector: match input.discovery.selection {
                            PeerSelection::Kademlia => Selector::Kademlia,
                            PeerSelection::Random => Selector::Random,
                        },
                        ..Default::default()
                    },
                    protocol: PubSubProtocol::GossipSub(GossipSubConfig::new(
                        6, 12, 4, 2, true, true, true,
                    )),
                    ..Default::default()
                },
                ..Default::default()
            },
            sync: ValueSyncConfig::default(),
        };
        Ok(Prepared {
            config,
            keypair,
            deadline,
        })
    }
}

impl NodeConfig for Config {
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
        &self.sync
    }
    fn value_sync_mut(&mut self) -> &mut ValueSyncConfig {
        &mut self.sync
    }
}
