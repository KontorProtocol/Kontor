use serde::Deserialize;
use thiserror::Error as ThisError;

#[derive(Deserialize, Debug)]
pub struct BitcoinRpcErrorResponse {
    pub code: i32,
    pub message: String,
}

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Unexpected error: {0}")]
    Unexpected(String),
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON serialization/deserialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Bitcoin RPC error (code {code}): {message}")]
    BitcoinRpc { code: i32, message: String },
    #[error("Deserialize hex error: {0}")]
    DeserializeHex(#[from] bitcoin::consensus::encode::FromHexError),
    #[error("Invalid header value error: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
}
