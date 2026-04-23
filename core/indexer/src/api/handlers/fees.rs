use axum::extract::State;
use indexer_types::Fees;

use crate::api::{Env, result::Result};

pub async fn get_fees(State(env): State<Env>) -> Result<Fees> {
    Ok((*env.fees_rx.borrow()).into())
}
