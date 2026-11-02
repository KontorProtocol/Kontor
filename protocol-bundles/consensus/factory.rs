use std::panic::{AssertUnwindSafe, catch_unwind};

use bytes::Bytes;
use malachitebft_app::types::Keypair;
use malachitebft_app_channel::{ConsensusContext, NetworkIdentity};

use crate::api::{EngineConfig, EngineError};
use crate::authority::context;
use crate::authority_api::Authority;
use crate::config::{Config, Prepared};
use crate::consensus::Ctx;
use crate::engine::Engine;
use crate::owner::Owner;

pub fn network_peer_id(network_key: &[u8; 32]) -> Result<Vec<u8>, EngineError> {
    let keypair = Keypair::ed25519_from_bytes(*network_key)
        .map_err(|_| EngineError::InvalidConfiguration("invalid network key".into()))?;
    Ok(keypair.public().to_peer_id().to_bytes())
}

pub fn start(config: EngineConfig, authority: Authority) -> Result<Engine, EngineError> {
    catch_unwind(AssertUnwindSafe(|| {
        // Reject invalid configuration before asking the durable signer for a
        // membership proof or creating the engine's WAL and network resources.
        let prepared = Config::prepare(&config, matches!(&authority, Authority::Validator { .. }))?;
        let peer_id = prepared.keypair.public().to_peer_id().to_bytes();
        let (consensus, proof) = context(authority, config.generation, peer_id)
            .map_err(|error| EngineError::Failed(error.to_string()))?;
        start_prepared(config, prepared, consensus, proof)
    }))
    .unwrap_or(Err(EngineError::Panicked))
}

fn start_prepared(
    config: EngineConfig,
    prepared: Prepared,
    consensus: ConsensusContext<Ctx>,
    proof: Option<Vec<u8>>,
) -> Result<Engine, EngineError> {
    let identity = match proof {
        Some(proof) => NetworkIdentity::new_validator(
            config.moniker,
            prepared.keypair,
            consensus.address.to_string(),
            Bytes::from(proof),
        ),
        None => NetworkIdentity::new(config.moniker, prepared.keypair, None),
    };
    let owner = Owner::start(
        config.generation,
        config.channel_capacity,
        prepared.config,
        config.wal_path,
        identity,
        consensus,
    )
    .map_err(|error| EngineError::Failed(error.to_string()))?;
    Ok(Engine::from_owner(
        owner,
        config.generation,
        prepared.deadline,
    ))
}
