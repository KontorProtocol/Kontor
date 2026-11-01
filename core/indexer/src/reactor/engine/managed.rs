use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use malachitebft_app_channel::app::config::{BootstrapProtocol, Selector};

use super::{EngineConfig, EngineOutput};
use crate::consensus::Address;
use crate::consensus::signing::PrivateKey;
use crate::database::{Reader, Writer, admit_node_database, open_node_database_for_genesis};
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::coordinator::durable_signer::{
    DurableSigner, GenerationOwner, OwnedGeneration,
};
use crate::protocol::coordinator::managed::control::EngineSlot;
use crate::protocol::coordinator::managed::reactor::ReactorEngine;
use crate::protocol::coordinator::managed::startup::{
    Bootstrap, Bundle, Configuration, PeerSelection,
};
use crate::reactor::transport::Engine;
use crate::runtime::GenesisParameters;

struct PreparedGeneration {
    ownership: OwnedGeneration,
    signer: Option<Arc<DurableSigner>>,
}

impl PreparedGeneration {
    fn reserve(
        owner: &Arc<GenerationOwner>,
        context: EraContext,
        key: Option<PrivateKey>,
    ) -> Result<Self> {
        let ownership = owner.reserve(key.as_ref().map(|key| *key.public_key().as_bytes()))?;
        let signer = key
            .map(|key| DurableSigner::open_owned(ownership.clone(), context, key).map(Arc::new))
            .transpose()?;
        Ok(Self { ownership, signer })
    }
}

pub struct NodeCoordinator {
    owner: Arc<GenerationOwner>,
    slot: EngineSlot,
    directory: PathBuf,
    context: EraContext,
    validator: Option<[u8; 32]>,
    prepared: Mutex<Option<PreparedGeneration>>,
}

impl NodeCoordinator {
    pub async fn open_database(
        config: &EngineConfig,
        filename: &str,
        network: Network,
        starting_block_height: u64,
        genesis: &GenesisParameters,
    ) -> Result<(Arc<Self>, Reader, Writer)> {
        let baseline = admit_node_database(
            &config.data_dir,
            filename,
            network,
            starting_block_height,
            genesis,
        )
        .await?;
        let directory = config.data_dir.clone();
        let context = baseline.context;
        let key = config.consensus_enabled.then(|| config.private_key.clone());
        let coordinator = tokio::task::spawn_blocking(move || -> Result<Arc<Self>> {
            let owner =
                GenerationOwner::open(&directory.join("consensus-authority"), context.chain)?;
            let validator = key.as_ref().map(|key| *key.public_key().as_bytes());
            let prepared = PreparedGeneration::reserve(&owner, context, key)?;
            Ok(Arc::new(Self {
                owner,
                slot: EngineSlot::default(),
                directory: directory.canonicalize()?,
                context,
                validator,
                prepared: Mutex::new(Some(prepared)),
            }))
        })
        .await
        .context("engine ownership initialization task failed")??;
        // Recheck after acquiring ownership: another node could have completed
        // work between the first read-only snapshot and our exclusive lock.
        let (reader, writer) = open_node_database_for_genesis(
            &config.data_dir,
            filename,
            network,
            starting_block_height,
            genesis,
        )
        .await?;
        Ok((coordinator, reader, writer))
    }

    pub(crate) fn start(&self, config: &EngineConfig, context: EraContext) -> Result<EngineOutput> {
        ensure!(
            context == self.context,
            "engine protocol differs from admitted context"
        );
        ensure!(
            config.data_dir.canonicalize()? == self.directory,
            "engine directory differs from admitted directory"
        );
        let key = config.consensus_enabled.then(|| config.private_key.clone());
        ensure!(
            key.as_ref().map(|key| *key.public_key().as_bytes()) == self.validator,
            "engine validator mode or identity changed after admission"
        );
        let prepared = self
            .prepared
            .lock()
            .map_err(|_| anyhow::anyhow!("engine startup lock poisoned"))?
            .take();
        let prepared = match prepared {
            Some(prepared) => prepared,
            None => PreparedGeneration::reserve(&self.owner, context, key)?,
        };
        let address = Address::from_public_key(&config.private_key.public_key());
        let input = Configuration {
            generation: prepared.ownership.generation(),
            channel_capacity: 128,
            moniker: format!("kontor-{}", &address.to_string()[..8]),
            network_key: prepared.ownership.network_key(),
            listen_address: config.listen_addr.clone(),
            persistent_peers: config.persistent_peers.clone(),
            // A restart reopens this era's WAL. A protocol switch uses a new
            // era path, even if the two engines happen to share a WAL codec.
            wal_path: self
                .directory
                .join(format!("consensus-{}.wal", hex::encode(context.era))),
            discovery_enabled: config.discovery.enabled,
            bootstrap: match config.discovery.bootstrap_protocol {
                BootstrapProtocol::Kademlia => Bootstrap::Kademlia,
                BootstrapProtocol::Full => Bootstrap::Full,
            },
            peer_selection: match config.discovery.selector {
                Selector::Kademlia => PeerSelection::Kademlia,
                Selector::Random => PeerSelection::Random,
            },
            readiness_timeout: Duration::from_secs(30),
        };
        let engine = ReactorEngine::start_owned(
            &self.slot,
            Bundle::First,
            input,
            prepared.signer,
            prepared.ownership,
        )?;
        Ok(EngineOutput {
            engine: Engine::managed(engine),
            address,
        })
    }
}

#[cfg(test)]
mod tests;
