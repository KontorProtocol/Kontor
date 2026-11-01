use anyhow::{Result, ensure};
use bitcoin::Network;
use libsql::{Connection, TransactionBehavior};

use super::selection::ExecutorVersion;
use crate::database::canonical_history::{self, HistoryState};
use crate::protocol::genesis_identity::chain_identity;
use crate::protocol::identity::ChainId;
use crate::protocol::operations::GenesisEnvelope;
use crate::protocol::v1::native::NATIVE_GENESIS_ID;

pub(crate) struct InitialProtocol {
    pub(crate) network: Network,
    pub(crate) executor: ExecutorVersion,
    pub(crate) native_genesis: &'static str,
}

pub(crate) async fn bind_identity(
    conn: &Connection,
    network: Network,
    starting_block_height: u64,
    genesis: &GenesisEnvelope,
) -> Result<ChainId> {
    let mut native = [0; 32];
    hex::decode_to_slice(NATIVE_GENESIS_ID, &mut native)?;
    let chain = chain_identity(
        network.magic().to_bytes(),
        starting_block_height,
        native,
        &genesis.0,
        &genesis.1,
    )?;
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
