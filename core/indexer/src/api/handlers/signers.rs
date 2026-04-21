use axum::extract::{Path, State};
use indexer_types::SignerResponse;

use crate::api::{Env, error::HttpError, result::Result};
use crate::database::queries::{
    get_signer_entry_by_bls_pubkey, get_signer_entry_by_id, get_signer_entry_by_x_only_pubkey,
};

/// Identifier accepted by `get_signer`. Disambiguated by shape — numeric is a
/// signer_id, 64-char hex is an x-only pubkey, 192-char hex is a BLS pubkey.
fn is_hex_of_len(s: &str, len: usize) -> bool {
    s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub async fn get_signer(
    Path(identifier): Path<String>,
    State(env): State<Env>,
) -> Result<SignerResponse> {
    if !*env.available.read().await {
        return Err(HttpError::ServiceUnavailable("Indexer is not available".to_string()).into());
    }
    let runtime = env.runtime_pool.get().await?;
    let conn = runtime.get_storage_conn();

    let entry = if let Ok(signer_id) = identifier.parse::<u64>() {
        get_signer_entry_by_id(&conn, signer_id as i64).await
    } else if is_hex_of_len(&identifier, 64) {
        get_signer_entry_by_x_only_pubkey(&conn, &identifier).await
    } else if is_hex_of_len(&identifier, 192) {
        let bytes = hex::decode(&identifier)
            .map_err(|e| HttpError::BadRequest(format!("invalid bls_pubkey hex: {e}")))?;
        get_signer_entry_by_bls_pubkey(&conn, &bytes).await
    } else {
        return Err(HttpError::BadRequest(
            "identifier must be signer_id (numeric), x-only pubkey (64 hex), or bls pubkey (192 hex)"
                .to_string(),
        )
        .into());
    };
    let entry = entry.map_err(|e| HttpError::BadRequest(e.to_string()))?;

    match entry {
        Some(e) => Ok(SignerResponse {
            signer_id: e.signer_id as u64,
            x_only_pubkey: e.x_only_pubkey,
            bls_pubkey: e.bls_pubkey,
            next_nonce: e.next_nonce.map(|n| n as u64),
        }
        .into()),
        None => Err(HttpError::NotFound(format!("signer not found for: {identifier}")).into()),
    }
}
