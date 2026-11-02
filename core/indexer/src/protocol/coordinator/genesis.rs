use anyhow::{Result, ensure};
use bitcoin::Network;
use libsql::{Connection, TransactionBehavior};

use super::selection::ExecutorVersion;
use crate::database::canonical_history::{self, HistoryState};
use crate::protocol::genesis_identity::chain_identity;
use crate::protocol::identity::ChainId;
use crate::protocol::operations::GenesisEnvelope;
use crate::protocol::v1::native::NATIVE_GENESIS_ID;
use crate::runtime::GenesisParameters;
use crate::runtime::numerics::decimal_to_string;

pub(crate) struct InitialProtocol {
    pub(crate) network: Network,
    pub(crate) executor: ExecutorVersion,
    pub(crate) native_genesis: &'static str,
}

pub(crate) fn envelope(genesis: &GenesisParameters) -> GenesisEnvelope {
    (
        decimal_to_string(genesis.sigma_min),
        genesis
            .validators
            .iter()
            .map(|validator| {
                (
                    validator.x_only_pubkey.clone(),
                    decimal_to_string(validator.stake),
                    validator.ed25519_pubkey.clone(),
                )
            })
            .collect(),
    )
}

pub(crate) fn configured_chain(
    network: Network,
    starting_block_height: u64,
    genesis: &GenesisEnvelope,
) -> Result<ChainId> {
    let mut native = [0; 32];
    hex::decode_to_slice(NATIVE_GENESIS_ID, &mut native)?;
    Ok(chain_identity(
        network.magic().to_bytes(),
        starting_block_height,
        native,
        &genesis.0,
        &genesis.1,
    )?)
}

pub(crate) async fn bind_identity(
    conn: &Connection,
    network: Network,
    starting_block_height: u64,
    genesis: &GenesisEnvelope,
) -> Result<ChainId> {
    let chain = configured_chain(network, starting_block_height, genesis)?;
    ensure!(
        conn.is_autocommit(),
        "genesis admission requires an idle writer"
    );
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    if canonical_history::state(&transaction).await? != HistoryState::Unavailable {
        canonical_history::bind_genesis(&transaction, chain).await?;
    }
    transaction.commit().await?;
    Ok(chain)
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
