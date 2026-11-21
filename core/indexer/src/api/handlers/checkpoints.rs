use axum::extract::{Path, State};
use indexer_types::CheckpointRow;

use crate::api::{Env, error::HttpError, result::Result};
use crate::database::queries::get_checkpoint_as_of_height;

/// Return the checkpoint as of `height` (the latest checkpoint at or before it).
/// Rollback and replay can replace past checkpoints. Compare nodes through
/// `/api/protocol`, which binds the checkpoint to its completed execution context.
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
