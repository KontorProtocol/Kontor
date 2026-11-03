mod blocks;
mod checkpoints;
mod compose;
mod contracts;
mod fees;
mod info;
mod metrics;
mod protocol;
mod receipt_stream;
mod results;
mod signers;
mod transactions;
mod upgrades;

pub use blocks::*;
pub use checkpoints::*;
pub use compose::*;
pub use contracts::*;
pub use fees::*;
pub use info::*;
pub use metrics::*;
pub use protocol::*;
pub use receipt_stream::*;
pub use results::*;
pub use signers::*;
pub use transactions::*;
pub use upgrades::*;

use crate::api::error::HttpError;

pub fn validate_query(
    cursor: Option<u64>,
    offset: Option<u64>,
) -> std::result::Result<(), HttpError> {
    if cursor.is_some() && offset.is_some() {
        return Err(HttpError::BadRequest(
            "Cannot specify both cursor and offset parameters".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod info_tests;
