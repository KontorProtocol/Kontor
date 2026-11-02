use anyhow::{Context, Result};
use bitcoin::Network;
use deadpool::managed::Object;
use indexer_types::{
    ContractAddress, ContractArtifactSource, ContractProvenanceResponse, EffectiveContractArtifact,
    ProvenanceEntry,
};
use sha2::{Digest, Sha256};

use super::linked::read_snapshot;
use super::selection::ExecutorVersion;
use crate::database::queries;
#[cfg(all(not(kontor_node), not(kontor_managed)))]
use crate::protocol::v2::native as p2_native;
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::LinkedManager;

fn native_hash(version: ExecutorVersion, contract_id: u64) -> Result<Option<[u8; 32]>> {
    match version {
        ExecutorVersion::LegacyP1 => Ok(None),
        ExecutorVersion::P2 => {
            #[cfg(kontor_managed)]
            {
                Ok(kontor_executor_observer::p2_native_artifact_hash(
                    contract_id,
                ))
            }
            #[cfg(all(not(kontor_node), not(kontor_managed)))]
            {
                Ok(p2_native::artifact_hash(contract_id))
            }
            #[cfg(all(kontor_node, not(kontor_managed)))]
            {
                anyhow::bail!("P2 artifact mapping is not installed")
            }
        }
    }
}

pub(crate) async fn contract_provenance(
    service: &OwnerService,
    object: Object<LinkedManager>,
    network: Network,
    address: ContractAddress,
) -> Result<Option<ContractProvenanceResponse>> {
    read_snapshot(
        service,
        object,
        network,
        move |conn, executor, selection| async move {
            let Some(id) = queries::get_contract_id_from_address(&conn, &address).await? else {
                return Ok(None);
            };
            let published = queries::get_contract_bytes_by_id(&conn, id)
                .await?
                .context("contract disappeared from pinned snapshot")?;
            let published_hash: [u8; 32] = Sha256::digest(published).into();
            let replacement = native_hash(selection.version(), id)?;
            let source = if replacement.is_some() {
                ContractArtifactSource::ProtocolNative
            } else {
                ContractArtifactSource::Publication
            };
            let mut entries = Vec::new();
            for row in queries::get_contract_provenance_log(&conn, id).await? {
                entries.push(ProvenanceEntry {
                    height: row.height,
                    tx_index: row.tx_index,
                    author_signer_id: row.author_signer_id,
                    provenance: postcard::from_bytes(&row.provenance)?,
                });
            }
            Ok(Some(ContractProvenanceResponse {
                entries,
                effective_artifact: EffectiveContractArtifact {
                    sha256: hex::encode(replacement.unwrap_or(published_hash)),
                    published_sha256: hex::encode(published_hash),
                    source,
                    protocol_id: selection.protocol_id().map(|id| hex::encode(id.0)),
                    execution_definition: hex::encode(executor.execution_definition?.0),
                },
            }))
        },
    )
    .await
}
