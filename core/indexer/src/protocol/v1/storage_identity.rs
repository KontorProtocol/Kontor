use thiserror::Error;

use crate::protocol::storage_identity::{CoreCallbacks, IdentityCallbacks, NonceCallbacks};

#[derive(Debug, Error)]
pub(crate) enum IdentityError {
    #[error("{0}")]
    Infrastructure(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub(crate) async fn ensure_identity(
    callbacks: IdentityCallbacks,
    pubkey: &str,
    height: u64,
) -> Result<u64, IdentityError> {
    if let Some(id) = callbacks.0(pubkey.to_owned())
        .await
        .map_err(IdentityError::Infrastructure)?
    {
        return Ok(id);
    }
    let id = callbacks.1(height)
        .await
        .map_err(IdentityError::Infrastructure)?;
    callbacks.2(id, pubkey.to_owned(), height)
        .await
        .map_err(IdentityError::Infrastructure)?;
    callbacks.3(id, height)
        .await
        .map_err(IdentityError::Infrastructure)?;
    Ok(id)
}

pub(crate) async fn x_only_pubkey(
    callbacks: IdentityCallbacks,
    signer_id: u64,
) -> Result<String, IdentityError> {
    callbacks.4(signer_id)
        .await
        .map_err(IdentityError::Infrastructure)?
        .ok_or_else(|| {
            IdentityError::InvalidData(format!("no x_only_pubkey for signer_id {signer_id}"))
        })
}

pub(crate) async fn create_core_signer(callbacks: CoreCallbacks) -> Result<u64, IdentityError> {
    const CORE_SIGNER_ID: u64 = 1;
    if let Some(id) = callbacks.0().await.map_err(IdentityError::Infrastructure)? {
        if id != CORE_SIGNER_ID {
            return Err(IdentityError::InvalidData(format!(
                "existing Core signer id ({id}) does not match CORE_SIGNER_ID ({CORE_SIGNER_ID})"
            )));
        }
        return Ok(id);
    }
    let id = callbacks.1().await.map_err(IdentityError::Infrastructure)?;
    if id != CORE_SIGNER_ID {
        return Err(IdentityError::InvalidData(format!(
            "newly-created Core signer id ({id}) does not match CORE_SIGNER_ID ({CORE_SIGNER_ID})"
        )));
    }
    Ok(id)
}

pub(crate) async fn advance_nonce(
    callbacks: NonceCallbacks,
    signer_id: u64,
    caller_nonce: u64,
    height: u64,
) -> Result<u64, IdentityError> {
    let (owner, stored) = callbacks.0(signer_id)
        .await
        .map_err(IdentityError::Infrastructure)?;
    let stored_nonce = stored
        .ok_or_else(|| IdentityError::InvalidData(format!("no nonce for signer_id {signer_id}")))?;
    const MAX_NONCE_GAP: u64 = 10_000;
    if caller_nonce < stored_nonce {
        return Err(IdentityError::InvalidData(format!(
            "nonce too low for signer_id {signer_id}: got {caller_nonce}, expected >= {stored_nonce}"
        )));
    }
    if caller_nonce - stored_nonce > MAX_NONCE_GAP {
        return Err(IdentityError::InvalidData(format!(
            "nonce too far ahead for signer_id {signer_id}: got {caller_nonce}, expected <= {}",
            stored_nonce + MAX_NONCE_GAP
        )));
    }
    let next_nonce = caller_nonce
        .checked_add(1)
        .ok_or_else(|| IdentityError::InvalidData("nonce overflow".to_owned()))?;
    callbacks.1(owner, next_nonce, height)
        .await
        .map_err(IdentityError::Infrastructure)?;
    Ok(next_nonce)
}
