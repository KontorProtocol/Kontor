#[cfg(not(kontor_node))]
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, anyhow, ensure};
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep_until};
#[cfg(not(kontor_node))]
use wasmtime::component::ResourceTable;

#[cfg(not(kontor_node))]
use super::Runtime;
use super::{RootAuthority, RootKeeper, RootOutcome, RootState, adapter};

pub(super) async fn restore_with_deadline<T>(
    keeper: &RootKeeper,
    operation_result: Result<RootOutcome<T>>,
    deadline: Option<Instant>,
    timed_out: bool,
    response: &mut Option<oneshot::Sender<Result<T>>>,
) -> Result<Result<T>> {
    let restoration = restore(keeper, operation_result);
    tokio::pin!(restoration);
    if let Some(deadline) = deadline.filter(|_| !timed_out) {
        tokio::select! {
            biased;
            _ = sleep_until(deadline) => {
                if keeper.quarantine_before_commit()
                    && let Some(response) = response.take()
                {
                    let _ = response.send(Err(anyhow!(
                        "operation restoration exceeded five seconds; root quarantined"
                    )));
                }
            }
            result = &mut restoration => return result,
        }
    }
    restoration.await
}

pub(super) async fn restore<T>(
    keeper: &RootKeeper,
    result: Result<RootOutcome<T>>,
) -> Result<Result<T>> {
    let mut authority = keeper.authority.lock().await;
    if matches!(
        authority.as_ref(),
        Some(RootAuthority::LinkedPooled(_) | RootAuthority::LinkedStateful(_))
    ) {
        return restore_linked(
            keeper,
            authority.as_mut().expect("root authority retained"),
            result,
        )
        .await;
    }
    #[cfg(kontor_node)]
    unreachable!("linked node authority handled above");
    #[cfg(not(kontor_node))]
    {
        let stateful = matches!(authority.as_ref(), Some(RootAuthority::Stateful(_)));
        let runtime: &mut Runtime = authority.as_mut().expect("root authority retained");
        let wants_commit = result.as_ref().is_ok_and(|outcome| outcome.commit);
        let commit_authorized = wants_commit
            && !keeper.caught_host_panic.load(Ordering::SeqCst)
            && !keeper.blocking.panicked()
            && keeper
                .state
                .compare_exchange(
                    RootState::Running as u8,
                    RootState::Committing as u8,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok();
        if commit_authorized {
            runtime
                .storage
                .commit()
                .await
                .context("root commit failed")?;
        } else if !runtime.storage.conn.is_autocommit() {
            runtime
                .storage
                .rollback_transaction()
                .await
                .context("root rollback failed")?;
            if stateful
                && (result.is_err()
                    || matches!(
                        RootState::load(&keeper.state),
                        RootState::Closing | RootState::Quarantined
                    ))
            {
                // A cancelled publication can have populated the cache under an id
                // that the full rollback makes available to a different contract.
                runtime.component_cache.clear();
            }
        }
        if !commit_authorized {
            runtime.stack.clear().await;
            runtime.deposit.reset().await;
        }
        runtime.ownership = None;
        runtime.storage.ownership = None;
        runtime.bundle_owner = None;
        runtime.storage.bundle_owner = None;
        let live_store_table = runtime.store_table_owners.as_ref().is_some_and(|owners| {
            owners
                .lock()
                .expect("store table tracker poisoned")
                .iter()
                .any(|owner| owner.strong_count() != 0)
        });
        if !runtime.storage.conn.is_autocommit()
            || !runtime.storage.savepoint_stack.is_empty().await
            || !runtime.stack.is_empty().await
            || runtime
                .invocation_budget
                .as_ref()
                .is_some_and(|budget| budget.live() != 0)
            || live_store_table
            || Arc::strong_count(&runtime.table) != 1
        {
            return Err(anyhow!(
                "root still has live SQL, stack, Store or table ownership"
            ));
        }
        runtime.invocation_budget = None;
        runtime.store_table_owners = None;
        *runtime.table.lock().await = ResourceTable::new();
        keeper.quiescent.store(true, Ordering::SeqCst);
        if RootState::load(&keeper.state) == RootState::Closing {
            return Ok(Err(anyhow!(
                "operation cancelled before commit authorization"
            )));
        }
        Ok(result.map(|outcome| outcome.value))
    }
}

async fn restore_linked<T>(
    keeper: &RootKeeper,
    authority: &mut RootAuthority,
    result: Result<RootOutcome<T>>,
) -> Result<Result<T>> {
    let (session, stateful) = match authority {
        RootAuthority::LinkedPooled(object) => (&mut **object, false),
        RootAuthority::LinkedStateful(session) => (session, true),
        #[cfg(not(kontor_node))]
        RootAuthority::Pooled(_) | RootAuthority::Stateful(_) => {
            return Err(anyhow!("linked restoration received a legacy authority"));
        }
    };
    let hooks = keeper
        .linked_hooks
        .lock()
        .await
        .clone()
        .context("linked root hooks missing")?;
    let owner = session.executor.owner.clone();
    let wants_commit = result.as_ref().is_ok_and(|outcome| outcome.commit);
    let commit_authorized = wants_commit
        && !keeper.caught_host_panic.load(Ordering::SeqCst)
        && !keeper.blocking.panicked()
        && keeper
            .state
            .compare_exchange(
                RootState::Running as u8,
                RootState::Committing as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok();
    if commit_authorized || !session.conn.is_autocommit() {
        (hooks.settle)(owner.clone(), commit_authorized)
            .await
            .map_err(adapter::HostFailure::from)
            .context("linked root settlement failed")?;
    }
    let clear_cache = stateful
        && (result.is_err()
            || matches!(
                RootState::load(&keeper.state),
                RootState::Closing | RootState::Quarantined
            ));
    (hooks.reset)(owner, false, clear_cache)
        .await
        .map_err(adapter::HostFailure::from)
        .context("linked root reset failed")?;
    ensure!(
        session.conn.is_autocommit(),
        "linked root still has live SQL transaction"
    );
    keeper.quiescent.store(true, Ordering::SeqCst);
    if RootState::load(&keeper.state) == RootState::Closing {
        return Ok(Err(anyhow!(
            "operation cancelled before commit authorization"
        )));
    }
    Ok(result.map(|outcome| outcome.value))
}
