use super::storage_error::ReadError;
use crate::protocol::storage_contracts::{ContractCallbacks, ResultWrite};

pub(crate) async fn insert_contract(
    callbacks: ContractCallbacks,
    height: u64,
    tx_index: Option<u32>,
    name: &str,
    bytes: &[u8],
) -> Result<u64, ReadError> {
    let signer_id = callbacks.0(height)
        .await
        .map_err(ReadError::Infrastructure)?;
    let tx_index = tx_index.expect("Transaction index is required when inserting contract");
    callbacks.1((
        name.to_owned(),
        height,
        tx_index,
        bytes.len() as u64,
        bytes.to_vec(),
        Some(signer_id),
    ))
    .await
    .map_err(ReadError::Infrastructure)
}

pub(crate) async fn insert_provenance(
    callbacks: ContractCallbacks,
    contract_id: u64,
    author_signer_id: u64,
    height: u64,
    tx_index: Option<u32>,
    provenance: &[u8],
) -> Result<(), ReadError> {
    let tx_index = tx_index.expect("Transaction index is required when inserting provenance");
    callbacks.5((
        contract_id,
        author_signer_id,
        height,
        tx_index,
        provenance.to_vec(),
    ))
    .await
    .map_err(ReadError::Infrastructure)?;
    Ok(())
}

pub(crate) fn result_write(
    position: (u64, Option<u64>, Option<u32>, Option<u32>),
    result_index: u32,
    contract_id: u64,
    func: String,
    gas: u64,
    value: Option<String>,
    signer_id: u64,
    payer_signer_id: Option<u64>,
    status: &str,
) -> ResultWrite {
    (
        contract_id,
        value.as_ref().map_or(0, |value| value.len() as u64),
        func,
        position.0,
        position.1,
        position.2,
        position.3,
        result_index,
        gas,
        value,
        signer_id,
        payer_signer_id,
        status.to_owned(),
    )
}
