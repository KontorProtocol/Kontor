use stdlib::CodecError;
use thiserror::Error;

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
