use bitcoin::Network;

use super::selection::ExecutorVersion;
use crate::protocol::v1::native::NATIVE_GENESIS_ID;

/// Initial executor inputs, not a commitment to the complete network genesis.
/// The migration phase adds durable network, committee and configuration identity.
pub(crate) struct InitialProtocol {
    pub(crate) network: Network,
    pub(crate) executor: ExecutorVersion,
    pub(crate) native_genesis: &'static str,
}

impl InitialProtocol {
    pub(crate) fn for_network(network: Network) -> Self {
        // All currently supported networks start with the same retained executor.
        // A future definition must select its own set rather than changing P1.
        Self {
            network,
            executor: ExecutorVersion::LegacyP1,
            native_genesis: NATIVE_GENESIS_ID,
        }
    }
}
