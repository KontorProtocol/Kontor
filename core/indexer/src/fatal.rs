//! Why the process is shutting down.
//!
//! `CancellationToken` is the shutdown bus, but it is a bare "stop" signal: a
//! SIGTERM and a dead reactor look identical at the token, and every subsystem
//! hands `main` a `JoinHandle<()>` that cannot carry a failure either. So a
//! fatal error was logged, the token was cancelled, and `main` returned
//! `Ok(())` — exit status 0. Kubernetes read that as `Completed`, restarted the
//! pod, and never entered `CrashLoopBackOff`; on signet a validator crash-looped
//! 121 times over 20 h while `kubectl get pods` showed `1/1 Running` throughout.
//!
//! This slot carries the missing bit. Every fatal path records here next to its
//! `cancel()`; the signal path records nothing. `main` reads it once after all
//! tasks join and exits non-zero if it is set.

use std::sync::{Arc, Mutex};

/// The first fatal subsystem error of the process, if any.
///
/// Cloneable and cheap — every subsystem holds the same slot.
#[derive(Clone, Default)]
pub struct FatalSlot(Arc<Mutex<Option<String>>>);

impl FatalSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a fatal error, keeping the FIRST one.
    ///
    /// Cancellation propagates, so one real failure typically produces a burst
    /// of consequential ones — channels closing, tasks unwinding. The first
    /// writer is the cause; the rest are its wake. Reporting the cause is what
    /// makes the exit message actionable.
    pub fn record(&self, source: &str, err: &anyhow::Error) {
        self.record_msg(source, format!("{err:#}"));
    }

    /// Record a fatal condition that is not an `anyhow::Error` — a panic, or a
    /// task that ended when it should not have.
    pub fn record_msg(&self, source: &str, msg: impl Into<String>) {
        // A poisoned lock means another thread panicked while holding it; the
        // stored value is a `String` and cannot be left inconsistent, so
        // recovering is strictly better than panicking inside a panic hook.
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(format!("{source}: {}", msg.into()));
        }
    }

    /// Take the recorded cause, if any. Called once, by `main`, after every
    /// task has joined.
    pub fn take(&self) -> Option<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_writer_wins() {
        let fatal = FatalSlot::new();
        fatal.record_msg("reactor", "the cause");
        fatal.record_msg("bitcoin poller", "a consequence");
        fatal.record(
            "http server",
            &anyhow::anyhow!("another consequence"),
        );
        assert_eq!(fatal.take().as_deref(), Some("reactor: the cause"));
    }

    #[test]
    fn empty_slot_takes_none() {
        // The signal path records nothing — this is the exit-0 case.
        assert_eq!(FatalSlot::new().take(), None);
    }

    #[test]
    fn take_empties_the_slot() {
        let fatal = FatalSlot::new();
        fatal.record_msg("reactor", "boom");
        assert!(fatal.take().is_some());
        assert_eq!(fatal.take(), None);
    }

    #[test]
    fn record_flattens_the_error_chain() {
        let err = anyhow::anyhow!("root cause").context("outer context");
        let fatal = FatalSlot::new();
        fatal.record("reactor", &err);
        let msg = fatal.take().unwrap();
        assert!(msg.starts_with("reactor: "), "{msg}");
        assert!(msg.contains("outer context"), "{msg}");
        assert!(msg.contains("root cause"), "{msg}");
    }
}
