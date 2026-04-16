use anyhow::Result;
use indexer::database::queries::get_signer_entry;
use testlib::Runtime;

pub async fn get_signer_id(runtime: &mut Runtime, xonly: &str) -> Result<Option<u64>> {
    let conn = runtime.get_storage_conn();
    Ok(get_signer_entry(&conn, xonly)
        .await?
        .map(|e| e.signer_id as u64))
}

pub async fn get_bls_pubkey(runtime: &mut Runtime, xonly: &str) -> Result<Option<Vec<u8>>> {
    let conn = runtime.get_storage_conn();
    Ok(get_signer_entry(&conn, xonly)
        .await?
        .and_then(|e| e.bls_pubkey))
}

pub async fn get_entry_by_id(
    runtime: &mut Runtime,
    signer_id: u64,
) -> Result<Option<indexer::database::types::SignerEntry>> {
    let conn = runtime.get_storage_conn();
    Ok(indexer::database::queries::get_signer_entry_by_id(&conn, signer_id as i64).await?)
}
