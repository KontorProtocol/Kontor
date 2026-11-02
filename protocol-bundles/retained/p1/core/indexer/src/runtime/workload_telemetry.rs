use std::sync::{Arc, Mutex};

use serde::Serialize;

#[derive(Clone, Default, Serialize)]
pub(crate) struct Snapshot {
    pub(crate) live_roots: u64,
    pub(crate) live_stores: u64,
    peak_roots: u64,
    peak_stores: u64,
    created_roots: u64,
    created_stores: u64,
}

#[derive(Default)]
pub(crate) struct WorkloadTelemetry(Mutex<Snapshot>);

impl WorkloadTelemetry {
    pub(crate) fn begin_window(&self) -> Snapshot {
        let mut state = self.0.lock().expect("workload telemetry poisoned");
        // Views may already be executing. Reset peaks atomically with Store
        // transitions, retaining the live counts across the window boundary.
        *state = Snapshot {
            live_roots: state.live_roots,
            live_stores: state.live_stores,
            peak_roots: state.live_roots,
            peak_stores: state.live_stores,
            ..Snapshot::default()
        };
        state.clone()
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        self.0.lock().expect("workload telemetry poisoned").clone()
    }

    pub(super) fn store(self: &Arc<Self>, root: bool) -> StoreGuard {
        let mut state = self.0.lock().expect("workload telemetry poisoned");
        state.live_stores += 1;
        state.created_stores += 1;
        state.peak_stores = state.peak_stores.max(state.live_stores);
        if root {
            state.live_roots += 1;
            state.created_roots += 1;
            state.peak_roots = state.peak_roots.max(state.live_roots);
        }
        StoreGuard {
            telemetry: self.clone(),
            root,
        }
    }
}

pub(super) struct StoreGuard {
    telemetry: Arc<WorkloadTelemetry>,
    root: bool,
}

impl Drop for StoreGuard {
    fn drop(&mut self) {
        let mut state = self
            .telemetry
            .0
            .lock()
            .expect("workload telemetry poisoned");
        state.live_stores = state
            .live_stores
            .checked_sub(1)
            .expect("Store telemetry underflow");
        if self.root {
            state.live_roots = state
                .live_roots
                .checked_sub(1)
                .expect("root telemetry underflow");
        }
    }
}

#[test]
fn workload_window_reset_preserves_live_stores_until_teardown() {
    let telemetry = Arc::new(WorkloadTelemetry::default());
    let root = telemetry.store(true);
    let nested = telemetry.store(false);
    let baseline = telemetry.begin_window();
    assert_eq!((baseline.live_roots, baseline.live_stores), (1, 2));
    let second = telemetry.store(true);
    drop(nested);
    drop(root);
    let snapshot = telemetry.snapshot();
    assert_eq!((snapshot.live_roots, snapshot.live_stores), (1, 1));
    assert_eq!((snapshot.peak_roots, snapshot.peak_stores), (2, 3));
    assert_eq!((snapshot.created_roots, snapshot.created_stores), (1, 1));
    drop(second);
    let drained = telemetry.snapshot();
    assert_eq!((drained.live_roots, drained.live_stores), (0, 0));
}
