mod blocks;
mod compose;
mod contracts;
mod info;
mod results;
mod signers;
mod transactions;

pub use blocks::*;
pub use compose::*;
pub use contracts::*;
pub use info::*;
pub use results::*;
pub use signers::*;
pub use transactions::*;

use crate::api::error::HttpError;

pub fn validate_query(
    cursor: Option<i64>,
    offset: Option<i64>,
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
