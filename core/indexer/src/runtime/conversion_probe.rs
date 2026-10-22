use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wasmtime::{AsContext, CallHook, Store};

use crate::runtime::Runtime;

#[derive(Clone, Copy, Debug)]
pub(super) enum Policy {
    Observe,
    Fixed(usize),
}

#[derive(Clone, Debug)]
pub(super) struct Event {
    pub store: usize,
    pub kind: CallHook,
    pub fuel: u64,
}

#[derive(Clone)]
pub(super) struct Probe {
    policy: Policy,
    trace: bool,
    pub events: Arc<Mutex<Vec<Event>>>,
    pub stores: Arc<AtomicUsize>,
}

impl Probe {
    pub fn new(policy: Policy, trace: bool) -> Self {
        Self {
            policy,
            trace,
            events: Arc::default(),
            stores: Arc::default(),
        }
    }

    pub fn install(&self, store: &mut Store<Runtime>) {
        if let Policy::Fixed(limit) = self.policy {
            store.set_hostcall_fuel_enabled(true);
            store.set_hostcall_fuel(limit);
        }
        let probe = self.clone();
        let id = self.stores.fetch_add(1, Ordering::Relaxed);
        store.call_hook(move |store, kind| {
            let fuel = store.as_context().get_fuel()?;
            if probe.trace {
                probe.events.lock().unwrap().push(Event {
                    store: id,
                    kind,
                    fuel,
                });
            }
            Ok(())
        });
    }
}
