use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Result, anyhow};
use bitcoin::Network;
use futures_util::poll;
use libsql::Connection;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::{DrainedCanonicalRoot, LinkedCanonicalRootLease};
use crate::database::connection::new_connection;
use crate::protocol::coordinator::linked::{abort_failed_begin, finish_canonical_unit};
use crate::protocol::coordinator::selection::{
    ApplicationPosition, ExecutionSelection, select_legacy_p1,
};
use crate::protocol::v1::definition::execution_definition;
use crate::runtime::ownership::adapter::{ExecutorSession, RootHooks};
use crate::runtime::ownership::{AsyncGate, OwnerService};
use crate::runtime::pool::LinkedSession;

const LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone, Default)]
struct Hooks {
    transaction: bool,
    inspect: Option<Arc<AsyncGate>>,
    before_settle: Option<Arc<AsyncGate>>,
    after_settle: Option<Arc<AsyncGate>>,
    reset: Option<Arc<AsyncGate>>,
    reset_fails: bool,
}

struct Fixture {
    _dir: TempDir,
    session: LinkedSession,
    reader: Connection,
    service: OwnerService,
    selection: ExecutionSelection,
    settlements: Arc<AtomicUsize>,
    resets: Arc<AtomicUsize>,
    hooks: Hooks,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for gate in [
            &self.hooks.inspect,
            &self.hooks.before_settle,
            &self.hooks.after_settle,
            &self.hooks.reset,
        ]
        .into_iter()
        .flatten()
        {
            gate.release();
        }
    }
}

impl Fixture {
    async fn new(hooks: Hooks) -> Result<Self> {
        let dir = TempDir::new()?;
        // Use a separate connection so durable-result assertions cannot see the
        // writer's uncommitted rows through a cloned connection handle.
        let conn = new_connection(dir.path(), "finalization.db").await?;
        let reader = new_connection(dir.path(), "finalization.db").await?;
        conn.execute("CREATE TABLE finalization_probe (value INTEGER)", ())
            .await?;
        let selection =
            select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::Committee).await?;
        let settlements = Arc::new(AtomicUsize::new(0));
        let resets = Arc::new(AtomicUsize::new(0));
        let hook_conn = conn.clone();
        let hook_config = hooks.clone();
        let count = settlements.clone();
        let reset_count = resets.clone();
        let executor = ExecutorSession {
            execution_definition: execution_definition(),
            origin: selection.version(),
            operations: Default::default(),
            owner: Arc::new(()),
            make_root: Arc::new(move |_, adapter| {
                let prepare_conn = hook_conn.clone();
                let settle_conn = hook_conn.clone();
                let config = hook_config.clone();
                let inspect = config.inspect.clone();
                let count = count.clone();
                let reset_count = reset_count.clone();
                Ok(RootHooks {
                    prepare: Arc::new(move |_| {
                        let conn = prepare_conn.clone();
                        Box::pin(async move {
                            if config.transaction {
                                conn.execute("BEGIN", ())
                                    .await
                                    .map_err(|e| (0, e.to_string()))?;
                                conn.execute("INSERT INTO finalization_probe VALUES (7)", ())
                                    .await
                                    .map_err(|e| (0, e.to_string()))?;
                            }
                            Ok(())
                        })
                    }),
                    inspect_canonical_drain: Arc::new(move |_| {
                        let gate = inspect.clone();
                        Box::pin(async move {
                            wait_optional(gate).await;
                            Ok(())
                        })
                    }),
                    settle: Arc::new(move |_, commit| {
                        let conn = settle_conn.clone();
                        let count = count.clone();
                        let adapter = adapter.clone();
                        let before = config.before_settle.clone();
                        let after = config.after_settle.clone();
                        Box::pin(async move {
                            if commit {
                                (adapter.check_commit)(adapter.root.clone())?;
                            }
                            // Gate after authorization, before SQL, to model an in-flight commit.
                            wait_optional(before).await;
                            count.fetch_add(1, Ordering::SeqCst);
                            conn.execute(if commit { "COMMIT" } else { "ROLLBACK" }, ())
                                .await
                                .map_err(|e| (0, e.to_string()))?;
                            wait_optional(after).await;
                            Ok(())
                        })
                    }),
                    reset: Arc::new(move |_, _, _| {
                        let gate = config.reset.clone();
                        let fail = config.reset_fails;
                        let count = reset_count.clone();
                        Box::pin(async move {
                            count.fetch_add(1, Ordering::SeqCst);
                            wait_optional(gate).await;
                            if fail {
                                Err((0, "injected reset failure".into()))
                            } else {
                                Ok(())
                            }
                        })
                    }),
                })
            }),
            recycle: Arc::new(|_| Box::pin(async { Ok(()) })),
        };
        Ok(Self {
            _dir: dir,
            session: LinkedSession::new(conn, executor),
            reader,
            service: OwnerService::new(),
            selection,
            settlements,
            resets,
            hooks,
        })
    }

    async fn begin(&self) -> Result<LinkedCanonicalRootLease> {
        self.service
            .begin_linked_canonical_reserved(
                &self.session,
                self.service.reserve_root_capacity().await?,
                self.selection.clone(),
                false,
            )
            .await
    }

    async fn rows(&self) -> Result<i64> {
        Ok(self
            .reader
            .query("SELECT COUNT(*) FROM finalization_probe", ())
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?)
    }

    async fn assert_fenced(&self) -> Result<()> {
        assert!(self.service.is_fatal());
        assert!(self.session.canonical_busy.load(Ordering::SeqCst));
        assert_eq!(self.service.quarantined_roots().await, 1);
        assert!(self.service.reserve_root_capacity().await.is_err());
        Ok(())
    }
}

async fn wait_optional(gate: Option<Arc<AsyncGate>>) {
    if let Some(gate) = gate {
        gate.wait().await;
    }
}

async fn entered(gate: &AsyncGate) -> Result<()> {
    timeout(LIMIT, async {
        while !gate.entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn unpolled_transition_futures_keep_the_abandonment_guard() -> Result<()> {
    for phase in ["drain", "settle", "complete", "committed_complete"] {
        let fixture = Fixture::new(Hooks {
            transaction: phase != "complete",
            ..Hooks::default()
        })
        .await?;
        let lease = fixture.begin().await?;
        match phase {
            "drain" => drop(lease.drain()),
            "settle" => drop(lease.drain().await?.require_settlement()?.settle(true)),
            "complete" => {
                let DrainedCanonicalRoot::NoTransaction(root) = lease.drain().await? else {
                    return Err(anyhow!("expected no transaction"));
                };
                drop(root.complete());
            }
            "committed_complete" => {
                let ready = lease
                    .drain()
                    .await?
                    .require_settlement()?
                    .settle(true)
                    .await?;
                drop(ready.complete());
            }
            _ => unreachable!(),
        }
        fixture.assert_fenced().await?;
        assert_eq!(
            fixture.settlements.load(Ordering::SeqCst),
            usize::from(phase == "committed_complete")
        );
        assert_eq!(fixture.resets.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.rows().await?,
            i64::from(phase == "committed_complete")
        );
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_drain_or_dropped_drained_capability_quarantines() -> Result<()> {
    for after_ack in [false, true] {
        let gate = Arc::new(AsyncGate::default());
        let fixture = Fixture::new(Hooks {
            inspect: Some(gate.clone()),
            ..Hooks::default()
        })
        .await?;
        let mut draining = Box::pin(fixture.begin().await?.drain());
        assert!(poll!(&mut draining).is_pending());
        entered(&gate).await?;
        if after_ack {
            gate.release();
            drop(draining.await?);
        } else {
            drop(draining);
            gate.release();
        }
        fixture.assert_fenced().await?;
        assert_eq!(fixture.settlements.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.resets.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn failed_begin_uses_drain_outcome_but_normal_finish_requires_sql() -> Result<()> {
    for transaction in [false, true] {
        let fixture = Fixture::new(Hooks {
            transaction,
            ..Hooks::default()
        })
        .await?;
        abort_failed_begin(fixture.begin().await?).await?;
        assert_eq!(
            fixture.settlements.load(Ordering::SeqCst),
            usize::from(transaction)
        );
        assert_eq!(fixture.resets.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.rows().await?, 0);
        assert!(!fixture.service.is_fatal());
        assert!(!fixture.session.canonical_busy.load(Ordering::SeqCst));
    }
    let fixture = Fixture::new(Hooks {
        transaction: true,
        ..Hooks::default()
    })
    .await?;
    let lease = fixture.begin().await?;
    fixture.session.conn.execute("ROLLBACK", ()).await?;
    let error = finish_canonical_unit(lease, Ok(()), true)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no transaction"));
    fixture.assert_fenced().await?;
    assert_eq!(fixture.settlements.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.resets.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn failed_settlement_send_keeps_root_fenced() -> Result<()> {
    let fixture = Fixture::new(Hooks {
        transaction: true,
        ..Hooks::default()
    })
    .await?;
    let mut root = fixture.begin().await?.drain().await?.require_settlement()?;
    let (closed, receiver) = oneshot::channel();
    drop(receiver);
    root.settlement = closed;
    let error = root.settle(true).await.err().unwrap();
    assert!(error.to_string().contains("supervisor disappeared"));
    fixture.assert_fenced().await?;
    assert_eq!(fixture.rows().await?, 0);
    assert_eq!(fixture.settlements.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn cancelled_settlement_does_not_infer_rollback_from_lost_ack() -> Result<()> {
    for commit in [false, true] {
        for after_sql in [false, true] {
            let gate = Arc::new(AsyncGate::default());
            let fixture = Fixture::new(Hooks {
                transaction: true,
                before_settle: (!after_sql).then(|| gate.clone()),
                after_settle: after_sql.then(|| gate.clone()),
                ..Hooks::default()
            })
            .await?;
            let root = fixture.begin().await?.drain().await?.require_settlement()?;
            let mut settlement = Box::pin(root.settle(commit));
            assert!(poll!(&mut settlement).is_pending());
            entered(&gate).await?;
            assert_eq!(fixture.rows().await?, i64::from(after_sql && commit));
            drop(settlement);
            fixture.assert_fenced().await?;
            gate.release();
            timeout(LIMIT, async {
                while !fixture.session.conn.is_autocommit() {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            assert_eq!(fixture.rows().await?, i64::from(commit));
            assert_eq!(fixture.settlements.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.resets.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

#[tokio::test]
async fn reset_failure_after_commit_never_repeats_settlement_or_releases_session() -> Result<()> {
    let fixture = Fixture::new(Hooks {
        transaction: true,
        reset_fails: true,
        ..Hooks::default()
    })
    .await?;
    assert!(
        finish_canonical_unit(fixture.begin().await?, Ok(()), true)
            .await
            .is_err()
    );
    fixture.assert_fenced().await?;
    assert_eq!(fixture.rows().await?, 1);
    assert_eq!(fixture.settlements.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.resets.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn completed_sql_does_not_release_same_session_until_reset_finishes() -> Result<()> {
    let gate = Arc::new(AsyncGate::default());
    let fixture = Fixture::new(Hooks {
        transaction: true,
        reset: Some(gate.clone()),
        ..Hooks::default()
    })
    .await?;
    let ready = fixture
        .begin()
        .await?
        .drain()
        .await?
        .require_settlement()?
        .settle(true)
        .await?;
    assert_eq!(fixture.rows().await?, 1);
    let capacity_before = fixture.service.registry.capacity.available_permits();
    let mut completing = Box::pin(ready.complete());
    assert!(poll!(&mut completing).is_pending());
    entered(&gate).await?;
    assert!(fixture.session.canonical_busy.load(Ordering::SeqCst));
    assert!(fixture.begin().await.is_err());
    assert_eq!(
        fixture.service.registry.capacity.available_permits(),
        capacity_before
    );
    assert_eq!(fixture.service.active_roots().await, 1);
    drop(completing);
    assert!(!fixture.service.is_fatal());
    gate.release();
    timeout(LIMIT, async {
        while fixture.session.canonical_busy.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(fixture.service.active_roots().await, 0);
    assert_eq!(
        fixture.service.registry.capacity.available_permits(),
        capacity_before + 1
    );
    // A fresh root on the same session can now start and roll back independently.
    abort_failed_begin(fixture.begin().await?).await?;
    assert_eq!(fixture.rows().await?, 1);
    assert_eq!(fixture.settlements.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.resets.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_of_queued_settlement_prevents_commit_authorization() -> Result<()> {
    let fixture = Fixture::new(Hooks {
        transaction: true,
        ..Hooks::default()
    })
    .await?;
    let mut root = fixture.begin().await?.drain().await?.require_settlement()?;
    let (_sender, replacement) = oneshot::channel();
    let completed = std::mem::replace(&mut root.release.completed, replacement);
    let mut settlement = Box::pin(root.settle(true));
    assert!(poll!(&mut settlement).is_pending());
    // This current-thread task has not yielded since the request was sent.
    // Cancellation therefore precedes the supervisor's authorization check.
    drop(settlement);
    assert!(timeout(LIMIT, completed).await??.is_err());
    fixture.assert_fenced().await?;
    assert_eq!(fixture.rows().await?, 0);
    assert!(!fixture.session.conn.is_autocommit());
    assert_eq!(fixture.settlements.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.resets.load(Ordering::SeqCst), 0);
    Ok(())
}
