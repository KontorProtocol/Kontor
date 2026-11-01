use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant as WallInstant};

use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, sleep};

use super::adapter::SelectedEngine;
use super::startup::{Bundle, Configuration};
use super::types::{
    Delivery, EngineError, EnginePoll, EngineState, Event, ProposalPartBytes, PublishError,
    ReplyToken, Response,
};
use crate::protocol::coordinator::durable_signer::DurableSigner;

const POLL_INTERVAL: Duration = Duration::from_millis(2);

#[derive(Default)]
pub(crate) struct EngineSlot {
    occupied: Arc<AtomicBool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) state: EngineState,
    pub(crate) failure: Option<EngineError>,
}

enum Command {
    Respond(
        ReplyToken,
        Response,
        oneshot::Sender<Result<Delivery, EngineError>>,
    ),
    Publish(
        u64,
        ProposalPartBytes,
        oneshot::Sender<Result<(), PublishError>>,
    ),
    RequestListen(oneshot::Sender<Result<bool, EngineError>>),
    PollListen(oneshot::Sender<Result<Option<String>, EngineError>>),
}

pub(crate) struct Control {
    generation: u64,
    signer: Option<Arc<DurableSigner>>,
    stop: Arc<AtomicBool>,
    occupied: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), EngineError>>>,
    terminal: Option<Result<(), EngineError>>,
    commands: mpsc::Sender<Command>,
    pub(crate) events: mpsc::Receiver<Event>,
    status: watch::Receiver<Status>,
}

impl EngineSlot {
    pub(crate) fn start(
        &self,
        bundle: Bundle,
        config: Configuration,
        signer: Option<Arc<DurableSigner>>,
    ) -> Result<Control, EngineError> {
        let generation = config.generation;
        let capacity = config.channel_capacity;
        let readiness_timeout = config.readiness_timeout;
        let authority = signer.clone();
        self.spawn(generation, capacity, readiness_timeout, signer, move || {
            bundle.start(config, authority)
        })
    }

    fn spawn<F>(
        &self,
        generation: u64,
        capacity: usize,
        readiness_timeout: Duration,
        signer: Option<Arc<DurableSigner>>,
        factory: F,
    ) -> Result<Control, EngineError>
    where
        F: FnOnce() -> Result<SelectedEngine, EngineError> + Send + 'static,
    {
        if generation == 0 || capacity == 0 || capacity > 4096 {
            return Err(EngineError::InvalidConfiguration(
                "invalid control generation or channel capacity".into(),
            ));
        }
        let deadline = WallInstant::now()
            .checked_add(readiness_timeout)
            .filter(|_| !readiness_timeout.is_zero())
            .ok_or_else(|| EngineError::InvalidConfiguration("invalid readiness timeout".into()))?;
        if self
            .occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(EngineError::Failed(
                "previous consensus owner has not joined successfully".into(),
            ));
        }
        let (commands, command_rx) = mpsc::channel(capacity);
        let (event_tx, events) = mpsc::channel(capacity);
        let (status_tx, status) = watch::channel(Status {
            state: EngineState::Starting,
            failure: None,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread_signer = signer.clone();
        let worker = match thread::Builder::new()
            .name(format!("consensus-control-{generation}"))
            .spawn(move || {
                run(
                    factory,
                    command_rx,
                    event_tx,
                    status_tx,
                    thread_stop,
                    thread_signer,
                    generation,
                    capacity,
                    deadline,
                )
            }) {
            Ok(worker) => worker,
            Err(error) => {
                self.occupied.store(false, Ordering::Release);
                return Err(EngineError::Failed(error.to_string()));
            }
        };
        Ok(Control {
            generation,
            signer,
            stop,
            occupied: self.occupied.clone(),
            worker: Some(worker),
            terminal: None,
            commands,
            events,
            status,
        })
    }
}

impl Control {
    pub(crate) fn subscribe(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }

    pub(crate) fn status(&self) -> Status {
        self.status.borrow().clone()
    }

    fn wake(&self) {
        if let Some(worker) = &self.worker {
            worker.thread().unpark();
        }
    }

    pub(crate) fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.wake();
    }

    pub(crate) async fn revoke_signing(&self) -> Result<(), EngineError> {
        let Some(signer) = self.signer.clone() else {
            return Ok(());
        };
        let generation = self.generation;
        tokio::task::spawn_blocking(move || signer.fence_generation(generation))
            .await
            .map_err(|_| EngineError::Panicked)?
            .map_err(|error| EngineError::Failed(error.to_string()))
    }

    pub(crate) async fn respond(
        &self,
        token: ReplyToken,
        response: Response,
    ) -> Result<Delivery, EngineError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Respond(token, response, tx)).await?;
        rx.await.map_err(|_| self.closed_error())?
    }

    pub(crate) async fn publish(
        &self,
        generation: u64,
        part: ProposalPartBytes,
    ) -> Result<(), PublishError> {
        if self.stop.load(Ordering::Acquire) {
            return Err(PublishError::Closed(part));
        }
        let (tx, rx) = oneshot::channel();
        if let Err(error) = self
            .commands
            .send(Command::Publish(generation, part, tx))
            .await
        {
            let Command::Publish(_, part, _) = error.0 else {
                unreachable!()
            };
            return Err(PublishError::Closed(part));
        }
        self.wake();
        // Once admitted, a lost acknowledgement does not prove non-publication.
        rx.await.unwrap_or(Err(PublishError::Unconfirmed))
    }

    pub(crate) async fn request_listen_address(&self) -> Result<bool, EngineError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::RequestListen(tx)).await?;
        rx.await.map_err(|_| self.closed_error())?
    }

    pub(crate) async fn poll_listen_address(&self) -> Result<Option<String>, EngineError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::PollListen(tx)).await?;
        rx.await.map_err(|_| self.closed_error())?
    }

    async fn send(&self, command: Command) -> Result<(), EngineError> {
        if self.stop.load(Ordering::Acquire) {
            return Err(self.closed_error());
        }
        self.commands
            .send(command)
            .await
            .map_err(|_| self.closed_error())?;
        self.wake();
        Ok(())
    }

    fn closed_error(&self) -> EngineError {
        self.status().failure.unwrap_or(EngineError::Stopping)
    }

    pub(crate) fn has_joined(&self) -> bool {
        self.terminal.is_some()
    }

    pub(crate) async fn wait_stopped(&mut self, timeout: Duration) -> Result<bool, EngineError> {
        if let Some(result) = &self.terminal {
            return result.clone().map(|()| true);
        }
        if !self.stop.load(Ordering::Acquire)
            && !self.worker.as_ref().expect("owned worker").is_finished()
        {
            return Err(EngineError::NotRunning);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| EngineError::InvalidConfiguration("join deadline overflow".into()))?;
        loop {
            if self.worker.as_ref().expect("owned worker").is_finished() {
                // is_finished makes this join nonblocking on the node executor.
                let result = self
                    .worker
                    .take()
                    .expect("owned worker")
                    .join()
                    .unwrap_or(Err(EngineError::Panicked));
                if result.is_ok() {
                    self.occupied.store(false, Ordering::Release);
                }
                self.terminal = Some(result.clone());
                return result.map(|()| true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))).await;
        }
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        self.request_stop();
        // The worker owns the engine and still drains it. Dropping this handle
        // without a successful join leaves the slot occupied, never reusable.
    }
}

#[allow(clippy::too_many_arguments)]
fn run<F>(
    factory: F,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    status: watch::Sender<Status>,
    stop: Arc<AtomicBool>,
    signer: Option<Arc<DurableSigner>>,
    generation: u64,
    capacity: usize,
    deadline: WallInstant,
) -> Result<(), EngineError>
where
    F: FnOnce() -> Result<SelectedEngine, EngineError>,
{
    // Keep the owner outside the unwind scope so revocation precedes teardown
    // even if node-side dispatch panics.
    let mut engine = None;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        engine = Some(factory()?);
        drive(
            engine.as_mut().expect("created engine"),
            &mut commands,
            &events,
            &status,
            &stop,
            capacity,
            deadline,
        )
    }))
    .unwrap_or(Err(EngineError::Panicked));
    stop.store(true, Ordering::Release);
    commands.close();
    let mut failure = outcome.err();
    status.send_replace(Status {
        state: EngineState::Stopping,
        failure: failure.clone(),
    });
    reject_pending(&mut commands);
    if let Some(signer) = &signer {
        if let Err(error) = signer.fence_generation(generation) {
            failure = Some(EngineError::Failed(format!(
                "signing revocation failed: {error}"
            )));
        }
    }
    status.send_replace(Status {
        state: EngineState::Stopping,
        failure: failure.clone(),
    });
    if let Some(mut engine) = engine {
        if let Err(error) = engine.request_stop() {
            failure.get_or_insert(error);
        }
        while engine.state() != EngineState::Joined {
            if let Err(error) = engine.wait_stopped(Duration::from_millis(50)) {
                failure.get_or_insert(error);
            }
        }
        drop(engine);
    }
    status.send_replace(Status {
        state: EngineState::Joined,
        failure: failure.clone(),
    });
    failure.map_or(Ok(()), Err)
}

fn reject_pending(commands: &mut mpsc::Receiver<Command>) {
    // Resolve queued requests as unprocessed, including returning owned buffers.
    while let Ok(command) = commands.try_recv() {
        match command {
            Command::Publish(_, part, reply) => {
                let _ = reply.send(Err(PublishError::Closed(part)));
            }
            Command::Respond(_, _, reply) => {
                let _ = reply.send(Err(EngineError::Stopping));
            }
            Command::RequestListen(reply) => {
                let _ = reply.send(Err(EngineError::Stopping));
            }
            Command::PollListen(reply) => {
                let _ = reply.send(Err(EngineError::Stopping));
            }
        }
    }
}

fn drive(
    engine: &mut SelectedEngine,
    commands: &mut mpsc::Receiver<Command>,
    events: &mpsc::Sender<Event>,
    status: &watch::Sender<Status>,
    stop: &AtomicBool,
    capacity: usize,
    deadline: WallInstant,
) -> Result<(), EngineError> {
    let mut pending = None;
    loop {
        if stop.load(Ordering::Acquire) || events.is_closed() {
            return Ok(());
        }
        // A full node event queue must not postpone the startup deadline.
        if matches!(
            engine.state(),
            EngineState::Starting | EngineState::Initializing
        ) && WallInstant::now() >= deadline
        {
            return Err(EngineError::ReadinessTimeout);
        }
        for _ in 0..capacity {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            match commands.try_recv() {
                Ok(Command::Respond(token, response, reply)) => {
                    let _ = reply.send(engine.respond(token, response));
                }
                Ok(Command::Publish(generation, part, reply)) => {
                    let _ = reply.send(engine.publish(generation, part));
                }
                Ok(Command::RequestListen(reply)) => {
                    let _ = reply.send(engine.request_listen_address());
                }
                Ok(Command::PollListen(reply)) => {
                    let _ = reply.send(engine.poll_listen_address());
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
            }
            if let Some(error) = engine.failure() {
                return Err(error);
            }
        }
        if pending.is_none() {
            if let EnginePoll::Event(event) = engine.poll()? {
                pending = Some(event);
            }
        }
        if let Some(event) = pending.take() {
            match events.try_send(event) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(event)) => pending = Some(event),
                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
            }
        }
        status.send_if_modified(|current| {
            let next = Status {
                state: engine.state(),
                failure: engine.failure(),
            };
            if *current == next {
                false
            } else {
                *current = next;
                true
            }
        });
        thread::park_timeout(POLL_INTERVAL);
    }
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
