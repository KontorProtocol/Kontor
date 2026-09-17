use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wasmtime::{CallHook, Store};

use crate::runtime::Runtime;

#[derive(Clone, Copy, Debug)]
pub(super) enum Policy {
    Observe,
    Fixed(usize),
    Dynamic(u64),
}

#[derive(Clone, Debug)]
pub(super) struct Event {
    pub store: usize,
    pub kind: CallHook,
    pub fuel: u64,
    pub allowance: usize,
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
        let probe = self.clone();
        let id = self.stores.fetch_add(1, Ordering::Relaxed);
        let ceiling = store.hostcall_fuel();
        store.call_hook(move |mut store, kind| {
            let fuel = store.get_fuel()?;
            if matches!(kind, CallHook::CallingHost | CallHook::ReturningFromWasm) {
                match probe.policy {
                    Policy::Observe => {}
                    Policy::Fixed(limit) => store.set_hostcall_fuel(limit),
                    Policy::Dynamic(rate) => {
                        let limit = usize::try_from(fuel / rate).unwrap_or(usize::MAX);
                        store.set_hostcall_fuel(ceiling.min(limit));
                    }
                }
            }
            if probe.trace {
                probe.events.lock().unwrap().push(Event {
                    store: id,
                    kind,
                    fuel,
                    allowance: store.hostcall_fuel(),
                });
            }
            Ok(())
        });
    }
}
