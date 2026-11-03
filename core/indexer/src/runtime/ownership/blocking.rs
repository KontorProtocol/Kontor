use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{Result, ensure};
use tokio::sync::{Notify, oneshot};

#[derive(Default)]
pub(super) struct BlockingRegistry {
    next_id: AtomicU64,
    gate: Arc<std::sync::Mutex<BlockingGateState>>,
    panicked: Arc<AtomicBool>,
}

#[derive(Default)]
struct BlockingGateState {
    closed: bool,
    active: HashMap<u64, Arc<BlockingState>>,
}

struct BlockingState {
    done: AtomicBool,
    notify: Notify,
}

impl BlockingRegistry {
    pub(super) fn panicked(&self) -> bool {
        self.panicked.load(Ordering::SeqCst)
    }

    pub(super) async fn wait_all(&self) {
        loop {
            let entries = self
                .gate
                .lock()
                .expect("blocking registry poisoned")
                .active
                .values()
                .cloned()
                .collect::<Vec<_>>();
            if entries.is_empty() {
                return;
            }
            for entry in entries {
                while !entry.done.load(Ordering::SeqCst) {
                    entry.notify.notified().await;
                }
            }
        }
    }

    pub(super) fn spawn<F, T>(
        &self,
        work: F,
    ) -> Result<oneshot::Receiver<std::result::Result<T, tokio::task::JoinError>>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let state = Arc::new(BlockingState {
            done: AtomicBool::new(false),
            notify: Notify::new(),
        });
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        {
            let mut gate = self.gate.lock().expect("blocking registry poisoned");
            ensure!(
                !gate.closed,
                "blocking registration closed after root drain"
            );
            gate.active.insert(id, state.clone());
        }
        let (sender, receiver) = oneshot::channel();
        let task = tokio::task::spawn_blocking(work);
        let gate = self.gate.clone();
        let panicked = self.panicked.clone();
        tokio::spawn(async move {
            let result = task.await;
            // A dropped receiver must not erase the root's panic evidence.
            if result.as_ref().is_err_and(tokio::task::JoinError::is_panic) {
                panicked.store(true, Ordering::SeqCst);
            }
            let _ = sender.send(result);
            gate.lock()
                .expect("blocking registry poisoned")
                .active
                .remove(&id);
            state.done.store(true, Ordering::SeqCst);
            state.notify.notify_one();
        });
        Ok(receiver)
    }

    pub(super) fn close_registration(&self) {
        self.gate.lock().expect("blocking registry poisoned").closed = true;
    }
}
