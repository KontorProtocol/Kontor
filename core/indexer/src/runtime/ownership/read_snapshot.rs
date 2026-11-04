use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use deadpool::managed::Object;
use libsql::Connection;

use super::adapter::{ExecutorSession, HostFailure};
use crate::database::storage_contract::StorageContract;
use crate::protocol::coordinator::selection::ExecutionSelection;
use crate::protocol::storage_callbacks::StorageCallbacks;
use crate::runtime::pool::{LinkedManager, LinkedSession};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Selected,
    Armed,
    Claimed,
}

struct Scope {
    generation: u64,
    selection: ExecutionSelection,
    phase: Phase,
}

#[derive(Default)]
pub(crate) struct ReadSnapshot {
    state: Mutex<(u64, Option<Scope>)>,
}

impl ReadSnapshot {
    pub(crate) fn select(&self, selection: ExecutionSelection) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        ensure!(
            state.1.is_none(),
            "reader retains an earlier snapshot scope"
        );
        state.0 = state.0.checked_add(1).context("read scope exhausted")?;
        state.1 = Some(Scope {
            generation: state.0,
            selection,
            phase: Phase::Selected,
        });
        Ok(())
    }

    pub(crate) fn selection(&self) -> Result<ExecutionSelection> {
        let state = self.state.lock().unwrap();
        Ok(state
            .1
            .as_ref()
            .context("reader has no selected snapshot")?
            .selection
            .clone())
    }

    pub(crate) fn claimed(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .1
            .as_ref()
            .is_some_and(|scope| scope.phase == Phase::Claimed)
    }

    pub(crate) fn is_idle(&self) -> bool {
        self.state.lock().unwrap().1.is_none()
    }

    pub(crate) fn clear(&self, conn: &Connection) -> Result<()> {
        ensure!(conn.is_autocommit(), "reader snapshot is still open");
        self.state.lock().unwrap().1 = None;
        Ok(())
    }

    fn arm(&self, generation: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let scope = state
            .1
            .as_mut()
            .context("reader has no snapshot to claim")?;
        ensure!(
            scope.generation == generation && scope.phase == Phase::Selected,
            "read root does not own this snapshot"
        );
        scope.phase = Phase::Armed;
        Ok(())
    }

    fn claim(&self, conn: &Connection) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let scope = state
            .1
            .as_mut()
            .context("reader has no snapshot to claim")?;
        ensure!(
            scope.phase == Phase::Armed && !conn.is_autocommit(),
            "read snapshot was not armed by its root"
        );
        scope.phase = Phase::Claimed;
        Ok(())
    }

    fn callbacks(
        self: &Arc<Self>,
        conn: &Connection,
        mut callbacks: StorageCallbacks,
    ) -> StorageCallbacks {
        let scope = self.clone();
        let conn = conn.clone();
        callbacks.10.0 = Arc::new(move || {
            let scope = scope.clone();
            let conn = conn.clone();
            Box::pin(async move { scope.claim(&conn).map_err(|error| error.to_string()) })
        });
        callbacks
    }

    fn attach(self: &Arc<Self>, mut executor: ExecutorSession) -> ExecutorSession {
        let scope = self.clone();
        let make_root = executor.make_root;
        executor.make_root = Arc::new(move |selection, adapter| {
            let generation = {
                let state = scope.state.lock().unwrap();
                let active = state
                    .1
                    .as_ref()
                    .ok_or_else(|| (0, "reader has no snapshot".into()))?;
                if active.selection != selection || active.phase != Phase::Selected {
                    return Err((0, "read root selection differs from its snapshot".into()));
                }
                active.generation
            };
            let mut hooks = make_root(selection, adapter)?;
            let prepare = hooks.prepare;
            let scope = scope.clone();
            hooks.prepare = Arc::new(move |owner| {
                let prepare = prepare.clone();
                let scope = scope.clone();
                Box::pin(async move {
                    scope
                        .arm(generation)
                        .map_err(|error| (0, error.to_string()))?;
                    prepare(owner).await
                })
            });
            Ok(hooks)
        });
        executor
    }
}

// This node-local input does not cross the retained executor ABI. Writers use
// ordinary callbacks; read factories receive the pool item's ownership adapter.
#[derive(Clone)]
pub(crate) struct SessionConnection {
    pub(crate) conn: Connection,
    pub(crate) read: Option<Arc<ReadSnapshot>>,
}

impl From<Connection> for SessionConnection {
    fn from(conn: Connection) -> Self {
        Self { conn, read: None }
    }
}

impl SessionConnection {
    pub(crate) fn callbacks(&self, contract: StorageContract) -> StorageCallbacks {
        let callbacks = contract.callbacks(&self.conn);
        match &self.read {
            Some(scope) => scope.callbacks(&self.conn, callbacks),
            None => callbacks,
        }
    }

    pub(crate) fn attach(&self, executor: ExecutorSession) -> ExecutorSession {
        match &self.read {
            Some(scope) => scope.attach(executor),
            None => executor,
        }
    }
}

pub(crate) struct AdmittedRead {
    object: Option<Object<LinkedManager>>,
}

impl AdmittedRead {
    pub(crate) fn new(object: Object<LinkedManager>) -> Self {
        Self {
            object: Some(object),
        }
    }

    pub(crate) fn object(&self) -> &Object<LinkedManager> {
        self.object.as_ref().expect("read checkout retained")
    }

    pub(crate) fn object_mut(&mut self) -> &mut Object<LinkedManager> {
        self.object.as_mut().expect("read checkout retained")
    }

    pub(crate) fn session(&self) -> &LinkedSession {
        self.object()
            .session
            .as_ref()
            .expect("read executor admitted")
    }

    pub(crate) fn session_mut(&mut self) -> &mut LinkedSession {
        self.object_mut()
            .session
            .as_mut()
            .expect("read executor admitted")
    }

    pub(crate) async fn rollback(&mut self) -> Result<()> {
        let object = self.object();
        if !object.conn.is_autocommit() {
            object.conn.execute("ROLLBACK", ()).await?;
        }
        if let Some(session) = &object.session {
            (session.executor.recycle)(session.executor.owner.clone())
                .await
                .map_err(HostFailure::from)?;
        }
        object.snapshot.clear(&object.conn)
    }

    pub(crate) fn discard(mut self) {
        if let Some(object) = self.object.take() {
            drop(Object::take(object));
        }
    }
}

impl Drop for AdmittedRead {
    fn drop(&mut self) {
        if self.object.is_none() {
            return;
        }
        if self.object().conn.is_autocommit() && self.object().snapshot.is_idle() {
            return;
        }
        // Never return a checkout with uncertain cleanup to another request.
        // Normal cleanup is async and explicit; this also covers unwinding.
        drop(Object::take(
            self.object.take().expect("read checkout retained"),
        ));
    }
}
