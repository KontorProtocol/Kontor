use anyhow::{Context, Result};
use bitcoin::Network;
use deadpool::managed::Object;
use indexer_types::{
    ContractAddress, ContractArtifactSource, ContractProvenanceResponse, EffectiveContractArtifact,
    ProvenanceEntry,
};
use sha2::{Digest, Sha256};

use super::linked::read_snapshot;
use crate::database::queries;
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::LinkedManager;

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
                    sha256: hex::encode(published_hash),
                    published_sha256: hex::encode(published_hash),
                    source: ContractArtifactSource::Publication,
                    protocol_id: selection.protocol_id().map(|id| hex::encode(id.0)),
                    execution_definition: hex::encode(executor.execution_definition?.0),
                },
            }))
        },
    )
    .await
}
