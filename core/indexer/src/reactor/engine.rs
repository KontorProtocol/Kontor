use std::path::PathBuf;

use malachitebft_app_channel::app::config::DiscoveryConfig;

use super::transport::Engine;
use crate::consensus::Address;
use crate::consensus::signing::PrivateKey;

mod validator_start;
pub use validator_start::ValidatorStart;

#[cfg(kontor_consensus_runtime)]
mod managed;
#[cfg(kontor_consensus_runtime)]
pub use managed::NodeCoordinator;
#[cfg(all(kontor_managed, feature = "protocol-qualification"))]
pub(crate) use managed::qualification::run as qualify_managed_startup;

#[derive(Clone)]
pub struct EngineConfig {
    pub private_key: PrivateKey,
    pub listen_addr: String,
    pub persistent_peers: Vec<String>,
    pub data_dir: PathBuf,
    pub consensus_enabled: bool,
    pub validator_start: ValidatorStart,
    pub discovery: DiscoveryConfig,
}

pub struct EngineOutput {
    pub(super) engine: Engine,
    pub(super) promotion_floor: Option<u64>,
    pub address: Address,
}

#[cfg(any(
    test,
    feature = "testing",
    feature = "protocol-qualification",
    not(kontor_consensus_runtime)
))]
mod legacy;
#[cfg(any(
    test,
    feature = "testing",
    feature = "protocol-qualification",
    not(kontor_consensus_runtime)
))]
pub use legacy::{LegacyEngineOutput, start};
