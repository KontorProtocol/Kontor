use thiserror::Error as ThisError;

mod batches;
mod blocks;
mod checkpoints;
mod contract_results;
mod contract_state;
mod contracts;
mod files;
mod pagination;
mod signers;
mod transactions;

pub use batches::*;
pub use blocks::*;
pub use checkpoints::*;
pub use contract_results::*;
pub use contract_state::*;
pub use contracts::*;
pub use files::*;
pub use pagination::*;
pub use signers::*;
pub use transactions::*;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Turso error: {0}")]
    Turso(#[from] turso::Error),
    #[error("Row deserialization error: {0}")]
    RowDeserialization(#[from] serde::de::value::Error),
    #[error("Invalid cursor format")]
    InvalidCursor,
    #[error("Out of fuel")]
    OutOfFuel,
    #[error("Contract not found: {0}")]
    ContractNotFound(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

#[cfg(test)]
mod tests;
