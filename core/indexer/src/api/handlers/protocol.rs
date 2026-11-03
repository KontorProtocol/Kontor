use axum::extract::State;
use libsql::TransactionBehavior;

use crate::api::{Env, result::Result};
use crate::protocol_info::{ProtocolSnapshot, snapshot};

pub async fn get_protocol(State(env): State<Env>) -> Result<ProtocolSnapshot> {
    let conn = env.reader.connection().await?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let result = snapshot(&transaction).await?;
    transaction.commit().await?;
    Ok(result.into())
}
