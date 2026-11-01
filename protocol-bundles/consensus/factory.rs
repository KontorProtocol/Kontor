use std::panic::{AssertUnwindSafe, catch_unwind};

use bytes::Bytes;
use malachitebft_app::types::Keypair;
use malachitebft_app_channel::{ConsensusContext, NetworkIdentity};

use crate::api::{EngineConfig, EngineError};
use crate::config::Config;
use crate::consensus::Ctx;
use crate::engine::Engine;
use crate::owner::Owner;

pub fn network_peer_id(network_key: &[u8; 32]) -> Result<Vec<u8>, EngineError> {
    let keypair = Keypair::ed25519_from_bytes(*network_key)
        .map_err(|_| EngineError::InvalidConfiguration("invalid network key".into()))?;
    Ok(keypair.public().to_peer_id().to_bytes())
}

pub(crate) fn start_with_context(
    config: EngineConfig,
    consensus: ConsensusContext<Ctx>,
    proof: Option<Vec<u8>>,
) -> Result<Engine, EngineError> {
    catch_unwind(AssertUnwindSafe(|| {
        let validator = consensus.signer.is_some();
        if validator != proof.is_some() {
            return Err(EngineError::InvalidConfiguration(
                "validator signing and membership proof must agree".into(),
            ));
        }
        let prepared = Config::prepare(&config, validator)?;
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
    }))
    .unwrap_or(Err(EngineError::Panicked))
}
