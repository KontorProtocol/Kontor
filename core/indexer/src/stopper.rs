use tokio::{select, signal::ctrl_c};
use tokio_util::sync::CancellationToken;
use tracing::warn;

#[cfg(not(windows))]
use tokio::signal::unix::{SignalKind, signal};

#[cfg(not(windows))]
async fn sigterm_listener() {
    let mut stream = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
    stream.recv().await;
}

#[cfg(windows)]
async fn sigterm_listener() {
    // On non-unix platforms, this future never resolves.
    std::future::pending::<()>().await;
}

/// Resolves when the process is asked to stop from outside — Ctrl-C or SIGTERM.
///
/// Deliberately just a future, not a task that cancels: whoever awaits it learns
/// that the stop was *asked for*, and that is the whole basis for telling an
/// operator-initiated shutdown from a subsystem that died. A task that cancelled
/// on our behalf would erase the distinction the moment it fired, which is how a
/// crashed node comes to exit 0.
pub async fn signal_received() {
    select! {
        _ = ctrl_c() => warn!("Ctrl+C received"),
        _ = sigterm_listener() => warn!("SIGTERM received"),
    }
}

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
