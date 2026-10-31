use anyhow::{Result, anyhow};

use crate::protocol::storage_session::SessionCallbacks;
use crate::runtime::{counter::Counter, stack::Stack};

pub(crate) async fn savepoint(
    callbacks: SessionCallbacks,
    stack: &Stack<u64>,
    counter: &Counter,
) -> Result<()> {
    if stack.is_empty().await {
        callbacks.0().await.map_err(|error| anyhow!(error))?;
        stack.push(0).await?;
        counter.reset().await;
    } else {
        let index = counter.get().await;
        callbacks.1(index).await.map_err(|error| anyhow!(error))?;
        stack.push(index).await?;
    }
    counter.increment().await;
    Ok(())
}

pub(crate) async fn commit(callbacks: SessionCallbacks, stack: &Stack<u64>) -> Result<()> {
    match stack.pop().await {
        Some(0) => callbacks.2().await.map_err(|error| anyhow!(error))?,
        Some(index) => callbacks.3(index).await.map_err(|error| anyhow!(error))?,
        None => (),
    }
    Ok(())
}

pub(crate) async fn rollback_transaction(
    callbacks: SessionCallbacks,
    stack: &Stack<u64>,
) -> Result<()> {
    stack.clear().await;
    callbacks.4().await.map_err(|error| anyhow!(error))
}

pub(crate) async fn rollback(callbacks: SessionCallbacks, stack: &Stack<u64>) -> Result<()> {
    match stack.pop().await {
        Some(0) => callbacks.4().await.map_err(|error| anyhow!(error))?,
        Some(index) => callbacks.5(index).await.map_err(|error| anyhow!(error))?,
        None => (),
    }
    Ok(())
}
