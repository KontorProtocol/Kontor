use std::future::Future;

use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::warn;

#[cfg(not(windows))]
use tokio::signal::unix::{SignalKind, signal};

/// Register the process signal handlers NOW and return the future that resolves
/// on the first Ctrl-C or SIGTERM.
///
/// Registration is the side effect that matters, and it happens in this call,
/// not when the future is first polled: a signal that lands before its handler
/// exists gets the default disposition, which kills the process (exit 143) —
/// so a rollout that catches a node mid-startup would page as a crash. `main`
/// calls this before any startup work and polls the future at the root select.
///
/// Deliberately a future, not a task that cancels: whoever awaits it learns
/// that the stop was *asked for*, and that is the whole basis for telling an
/// operator-initiated shutdown from a subsystem that died. A task that
/// cancelled on our behalf would erase the distinction the moment it fired,
/// which is how a crashed node comes to exit 0.
#[cfg(not(windows))]
pub fn signal_received() -> impl Future<Output = ()> {
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");
    async move {
        select! {
            _ = sigterm.recv() => warn!("SIGTERM received"),
            _ = sigint.recv() => warn!("Ctrl+C received"),
        }
    }
}

#[cfg(windows)]
pub fn signal_received() -> impl Future<Output = ()> {
    async {
        let _ = tokio::signal::ctrl_c().await;
        warn!("Ctrl+C received");
    }
}

/// A subsystem finished CLEANLY while nobody had asked the node to stop.
///
/// Typed, so cause-attribution can tell a manufactured error from a real one:
/// one failure cascades — channels close behind the dying subsystem and its
/// dependents can finish in the same poll, often `Ok` (from their own point of
/// view they simply ran out of work). When a sentinel and a real error are
/// ready together, the real error is the cause; position alone cannot always
/// know that.
#[derive(Debug)]
pub struct UnexpectedExit(pub &'static str);

impl std::fmt::Display for UnexpectedExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} exited without a shutdown request", self.0)
    }
}

impl std::error::Error for UnexpectedExit {}

/// The authority to stop the node. `main` holds the only one.
///
/// Subsystems get a [`ShutdownSignal`], which can observe the decision but not
/// make it. That is not ceremony: `main` works out *why* the node stopped from
/// which of its three futures resolved first, and that inference holds only
/// while nothing else can cancel behind its back. A subsystem that cancelled on
/// its own — which is what the code used to do, and what reads as obviously
/// correct when you are staring at one subsystem — makes every other subsystem
/// exit cleanly in response, and `main` then reports whichever of *those* it
/// noticed first as the cause. The real error becomes a line in the drain log.
///
/// Splitting the type is what turns that from a rule someone has to remember
/// into an error the compiler raises.
pub struct Shutdown {
    token: CancellationToken,
}

impl Shutdown {
    pub fn new() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    /// A read-only view for a subsystem.
    pub fn signal(&self) -> ShutdownSignal {
        ShutdownSignal {
            token: self.token.clone(),
        }
    }

    /// A child decision: cancelled when this one is, cancellable on its own.
    /// For a harness stopping ONE node of an in-process cluster. Test-gated so
    /// "production holds exactly one `Shutdown`, owned by `main`" stays
    /// compile-enforced in production builds rather than a convention.
    #[cfg(test)]
    pub fn child(&self) -> Shutdown {
        Shutdown {
            token: self.token.child_token(),
        }
    }

    // The ONE sanctioned stop decision — see clippy.toml's disallowed-methods.
    #[allow(clippy::disallowed_methods)]
    pub fn cancel(&self) {
        self.token.cancel();
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// A subsystem's view of the shutdown decision: observe it, never make it.
#[derive(Clone)]
pub struct ShutdownSignal {
    token: CancellationToken,
}

impl ShutdownSignal {
    /// A signal with no [`Shutdown`] behind it, so it never fires. For tests and
    /// for `Env::new_test`, where there is no node to stop. A test that wants to
    /// *observe* a shutdown builds a real `Shutdown` and hands out `signal()`.
    pub fn never() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    /// Resolves once the node has been asked to stop.
    pub async fn cancelled(&self) {
        self.token.cancelled().await
    }

    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use super::Shutdown;

    /// The two directions the cluster harness depends on: stopping the cluster
    /// stops every node, and stopping one node leaves its siblings running.
    #[test]
    fn a_child_hears_the_parent_but_not_its_siblings() {
        let cluster = Shutdown::new();
        let a = cluster.child();
        let b = cluster.child();

        a.cancel();
        assert!(a.signal().is_cancelled(), "cancelling a child fires it");
        assert!(
            !b.signal().is_cancelled() && !cluster.signal().is_cancelled(),
            "a child's cancel must not reach its parent or siblings"
        );

        cluster.cancel();
        assert!(
            b.signal().is_cancelled(),
            "the cluster's cancel must reach every remaining child"
        );
    }
}
