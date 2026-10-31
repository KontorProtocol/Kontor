use anyhow::{Error as AnyError, anyhow};
use stdlib::CodecError;
use thiserror::Error;

use crate::protocol::storage_aux::StorageFailure;

pub(crate) fn host_failure(causes: StorageFailure) -> AnyError {
    let mut causes = causes.into_iter().rev();
    let mut error = anyhow!(
        causes
            .next()
            .unwrap_or_else(|| "storage callback failed without an error".to_owned())
    );
    for cause in causes {
        error = error.context(cause);
    }
    error
}

#[derive(Debug, Error)]
pub enum ReadError {
    #[error("{0}")]
    Infrastructure(String),
    #[error("Storage value exceeds the requested byte limit")]
    ValueTooLarge,
    #[error("row scan requires direct scalar leaves")]
    NonScalarRow,
    #[error("Key codec error: {0:?}")]
    KeyCodec(CodecError),
}
