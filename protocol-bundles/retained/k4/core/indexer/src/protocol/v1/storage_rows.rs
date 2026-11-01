use stdlib::next_element;

use super::storage_bounds::scan_bounds;
use super::storage_error::ReadError;

use crate::protocol::storage_rows::{CursorOwner, RowCallbacks};

#[cfg(test)]
mod tests;

pub struct StorageRowCursor {
    owner: Option<CursorOwner>,
    callbacks: RowCallbacks,
    prefix_len: usize,
}

impl StorageRowCursor {
    pub(crate) fn new(
        callbacks: RowCallbacks,
        contract_id: u64,
        path: Vec<u8>,
        lo: Option<Vec<u8>>,
        hi: Option<Vec<u8>>,
        descending: bool,
    ) -> Self {
        let prefix_len = path.len();
        let (lower, inclusive, upper) = scan_bounds(&path, lo, hi);
        let owner = callbacks.0((
            contract_id,
            lower,
            inclusive,
            upper,
            descending,
            prefix_len as u64,
        ));
        Self {
            owner: Some(owner),
            callbacks,
            prefix_len,
        }
    }

    pub async fn next(&mut self, max_bytes: u64) -> Result<Option<(Vec<u8>, Vec<u8>)>, ReadError> {
        let Some(owner) = self.owner.take() else {
            return Ok(None);
        };
        // Each pending stage owns the cursor. An error or cancelled poll drops
        // its rows and statement before the enclosing transaction can reset.
        let Some((owner, key_bytes)) = (self.callbacks.1)(owner)
            .await
            .map_err(ReadError::Infrastructure)?
        else {
            return Ok(None);
        };
        let max_value_bytes = max_bytes
            .checked_sub(key_bytes)
            .ok_or(ReadError::ValueTooLarge)?;
        let (owner, size) = (self.callbacks.2)(owner)
            .await
            .map_err(ReadError::Infrastructure)?;
        if size > max_value_bytes {
            return Err(ReadError::ValueTooLarge);
        }
        let (owner, full) = (self.callbacks.3)(owner)
            .await
            .map_err(ReadError::Infrastructure)?;
        let (element, tail) =
            next_element(&full[self.prefix_len..]).map_err(ReadError::KeyCodec)?;
        if !tail.is_empty() {
            return Err(ReadError::NonScalarRow);
        }
        let member = element.to_vec();
        let (owner, height) = (self.callbacks.4)(owner)
            .await
            .map_err(ReadError::Infrastructure)?;
        let (owner, value) = (self.callbacks.5)(owner, height, full)
            .await
            .map_err(ReadError::Infrastructure)?;
        self.owner = Some(owner);
        Ok(Some((member, value)))
    }
}
