use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use libsql::Connection;
use malachitebft_app_channel::app::config::{BootstrapProtocol, Selector};

use super::{EngineConfig, EngineOutput};
use crate::build_record;
use crate::consensus::Address;
use crate::consensus::signing::PrivateKey;
use crate::database::{
    Reader, Writer, admit_node_database, certified_history, open_node_database_for_genesis,
};
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::coordinator::durable_signer::{
    DurableSigner, GenerationOwner, OwnedGeneration,
};
use crate::protocol::coordinator::managed::control::EngineSlot;
use crate::protocol::coordinator::managed::reactor::ReactorEngine;
use crate::protocol::coordinator::managed::startup::{Bootstrap, Configuration, PeerSelection};
use crate::protocol::coordinator::registry;
use crate::reactor::consensus_state::certified_startup;
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
    genesis: EraContext,
    validator: Option<[u8; 32]>,
}

impl NodeCoordinator {
    pub async fn open_database(
        config: &EngineConfig,
        filename: &str,
        network: Network,
        starting_block_height: u64,
        genesis: &GenesisParameters,
    ) -> Result<(Arc<Self>, Reader, Writer)> {
        build_record::verify()?;
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
            Ok(Arc::new(Self {
                owner,
                slot: EngineSlot::default(),
                directory: directory.canonicalize()?,
                genesis: context,
                validator,
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

    pub(crate) async fn start(
        &self,
        config: &EngineConfig,
        conn: &Connection,
    ) -> Result<EngineOutput> {
        let (context, height, _) = certified_startup(conn).await?;
        ensure!(
            certified_history::eras::genesis(conn).await? == self.genesis,
            "engine genesis differs from admitted context"
        );
        let manifest = certified_history::protocol(conn, context.protocol).await?;
        let installed = registry::resolve(&manifest)?;
        ensure!(
            config.data_dir.canonicalize()? == self.directory,
            "engine directory differs from admitted directory"
        );
        let key = config.consensus_enabled.then(|| config.private_key.clone());
        ensure!(
            key.as_ref().map(|key| *key.public_key().as_bytes()) == self.validator,
            "engine validator mode or identity changed after admission"
        );
        // No signing state is opened until closure recovery has established the
        // next engine's exact era and installed implementation.
        let prepared = PreparedGeneration::reserve(&self.owner, context, key)?;
        if let Some(signer) = prepared.signer.clone() {
            let committee = certified_history::committee(conn, height.as_u64()).await?;
            let completed_closure = certified_history::frontier(conn)
                .await?
                .closure_id
                .context("startup lacks completed closure")?;
            tokio::task::spawn_blocking(move || {
                signer.authorize_height(&committee, completed_closure)
            })
            .await
            .context("startup signing authorization task failed")??;
        }
        let address = Address::from_public_key(&config.private_key.public_key());
        let input = Configuration {
            generation: prepared.ownership.generation(),
            channel_capacity: 128,
            moniker: format!("kontor-{}", &address.to_string()[..8]),
            network_key: prepared.ownership.network_key(),
            listen_address: config.listen_addr.clone(),
            persistent_peers: config.persistent_peers.clone(),
            // Nonvalidator startup resets its WAL. Never let catch-up discard
            // the validator's durable votes, including across protocol changes.
            wal_path: self.directory.join(if config.consensus_enabled {
                "consensus-validator.wal"
            } else {
                "consensus-catchup.wal"
            }),
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
            installed.consensus,
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

#[cfg(any(test, feature = "protocol-qualification"))]
pub(crate) mod qualification;
