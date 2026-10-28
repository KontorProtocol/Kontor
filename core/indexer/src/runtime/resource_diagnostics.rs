use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;

#[cfg(target_os = "linux")]
use libc::gettid;

#[derive(Clone, Debug)]
pub(crate) struct ThreadEvent {
    pub name: &'static str,
    pub thread_id: ThreadId,
    #[cfg(target_os = "linux")]
    pub os_thread_id: i32,
}

static TRACE: OnceLock<Mutex<Option<Vec<ThreadEvent>>>> = OnceLock::new();

pub(crate) struct ScopeGuard {
    exit: &'static str,
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        record(self.exit);
    }
}

pub(crate) fn scope(entry: &'static str, exit: &'static str) -> ScopeGuard {
    record(entry);
    ScopeGuard { exit }
}

pub(crate) fn start() {
    let trace = TRACE.get_or_init(|| Mutex::new(None));
    let mut current = trace.lock().expect("resource diagnostic trace lock");
    assert!(
        current.is_none(),
        "resource diagnostic trace is already active"
    );
    *current = Some(Vec::new());
}

pub(crate) fn record(name: &'static str) {
    let Some(trace) = TRACE.get() else {
        return;
    };
    let mut current = trace.lock().expect("resource diagnostic trace lock");
    if let Some(events) = current.as_mut() {
        events.push(ThreadEvent {
            name,
            thread_id: std::thread::current().id(),
            #[cfg(target_os = "linux")]
            os_thread_id: unsafe { gettid() },
        });
    }
}

pub(crate) fn finish() -> Vec<ThreadEvent> {
    TRACE
        .get()
        .expect("resource diagnostic trace was not started")
        .lock()
        .expect("resource diagnostic trace lock")
        .take()
        .expect("resource diagnostic trace was not active")
}
