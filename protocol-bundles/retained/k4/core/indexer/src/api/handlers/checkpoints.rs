use axum::extract::{Path, State};
use indexer_types::CheckpointRow;

use crate::api::{Env, error::HttpError, result::Result};
use crate::database::queries::get_checkpoint_as_of_height;

/// Return the checkpoint as of `height` (the latest checkpoint at or before it).
/// Comparing this across nodes at a fixed past height is race-free, since a past
/// checkpoint is immutable once a node has processed beyond it.
pub async fn get_checkpoint(
    State(env): State<Env>,
    Path(height): Path<u64>,
) -> Result<CheckpointRow> {
    match get_checkpoint_as_of_height(&*env.reader.connection().await?, height).await? {
        Some(checkpoint) => Ok(checkpoint.into()),
        None => {
            Err(HttpError::NotFound(format!("no checkpoint at or before height {height}")).into())
        }
    }
}
