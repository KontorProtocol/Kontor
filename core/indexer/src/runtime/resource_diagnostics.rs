use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;

#[cfg(target_os = "linux")]
use libc::gettid;
#[cfg(target_os = "macos")]
use libc::{pthread_self, pthread_threadid_np};

#[derive(Clone, Debug)]
pub(crate) struct ThreadEvent {
    pub name: &'static str,
    pub thread_id: ThreadId,
    #[cfg(target_os = "linux")]
    pub os_thread_id: i32,
    #[cfg(target_os = "macos")]
    pub os_thread_id: i64,
}

struct TraceState {
    events: Vec<ThreadEvent>,
    conversion_enabled: bool,
}

static TRACE: OnceLock<Mutex<Option<TraceState>>> = OnceLock::new();

pub(crate) struct ScopeGuard {
    exit: &'static str,
    conversion_only: bool,
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        if self.conversion_only {
            record_conversion(self.exit);
        } else {
            record(self.exit);
        }
    }
}

pub(crate) fn scope(entry: &'static str, exit: &'static str) -> ScopeGuard {
    record(entry);
    ScopeGuard {
        exit,
        conversion_only: false,
    }
}

pub(crate) fn conversion_scope(entry: &'static str, exit: &'static str) -> ScopeGuard {
    record_conversion(entry);
    ScopeGuard {
        exit,
        conversion_only: true,
    }
}

pub(crate) fn start() {
    start_with_conversion(false);
}

pub(crate) fn start_chain() {
    start_with_conversion(true);
}

fn start_with_conversion(conversion_enabled: bool) {
    let trace = TRACE.get_or_init(|| Mutex::new(None));
    let mut current = trace.lock().expect("resource diagnostic trace lock");
    assert!(
        current.is_none(),
        "resource diagnostic trace is already active"
    );
    *current = Some(TraceState {
        events: Vec::new(),
        conversion_enabled,
    });
}

fn push(name: &'static str, conversion_only: bool) {
    let Some(trace) = TRACE.get() else {
        return;
    };
    let mut current = trace.lock().expect("resource diagnostic trace lock");
    if let Some(state) = current.as_mut()
        && (!conversion_only || state.conversion_enabled)
    {
        state.events.push(ThreadEvent {
            name,
            thread_id: std::thread::current().id(),
            #[cfg(target_os = "linux")]
            os_thread_id: unsafe { gettid() },
            #[cfg(target_os = "macos")]
            os_thread_id: {
                let mut id = 0;
                let status = unsafe { pthread_threadid_np(pthread_self(), &mut id) };
                assert_eq!(status, 0, "resource diagnostic thread ID unavailable");
                i64::try_from(id).expect("resource diagnostic thread ID overflow")
            },
        });
    }
}

pub(crate) fn record(name: &'static str) {
    push(name, false);
}

fn record_conversion(name: &'static str) {
    push(name, true);
}

pub(crate) fn finish() -> Vec<ThreadEvent> {
    TRACE
        .get()
        .expect("resource diagnostic trace was not started")
        .lock()
        .expect("resource diagnostic trace lock")
        .take()
        .expect("resource diagnostic trace was not active")
        .events
}
