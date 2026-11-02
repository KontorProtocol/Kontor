use super::storage_error::ReadError;
use crate::protocol::storage_point::PointCallbacks;

pub(crate) async fn read_value(
    callbacks: PointCallbacks,
    max_bytes: u64,
    contract_id: u64,
    path: &[u8],
) -> Result<Option<Vec<u8>>, ReadError> {
    let Some((owner, height)) = callbacks.0(contract_id, path.to_vec())
        .await
        .map_err(ReadError::Infrastructure)?
    else {
        return Ok(None);
    };
    let path = path.to_vec();
    let (owner, size) = callbacks.1(owner)
        .await
        .map_err(ReadError::Infrastructure)?;
    if size > max_bytes {
        return Err(ReadError::ValueTooLarge);
    }
    let bytes = callbacks.2(owner, height, path)
        .await
        .map_err(ReadError::Infrastructure)?;
    Ok(Some(bytes))
}
