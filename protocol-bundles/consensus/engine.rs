use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use crate::api::{
    Delivery, EngineError, EnginePoll, EngineState, ProposalPartBytes, Publish, ReplyError,
    ReplyToken, Request, Response,
};
use crate::channel_bridge::Poll;
use crate::owner::{Owner, State};

// The private owner makes this concrete facade !Send. Construction, every call,
// and drop belong to the node control thread, including after a timeout.
pub struct Engine {
    owner: Owner,
    generation: u64,
    deadline: Instant,
    state: EngineState,
    ready: Option<ReplyToken>,
    failure: Option<EngineError>,
}

impl Engine {
    pub(crate) fn from_owner(owner: Owner, generation: u64, deadline: Instant) -> Self {
        Self {
            owner,
            generation,
            deadline,
            state: EngineState::Starting,
            ready: None,
            failure: None,
        }
    }

    pub fn state(&self) -> EngineState {
        self.state
    }
    pub fn failure(&self) -> Option<&EngineError> {
        self.failure.as_ref()
    }

    fn guarded<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T, EngineError>,
    ) -> Result<T, EngineError> {
        match catch_unwind(AssertUnwindSafe(|| action(self))) {
            Ok(result) => result,
            Err(_) => {
                self.fail(EngineError::Panicked);
                Err(EngineError::Panicked)
            }
        }
    }

    fn fail(&mut self, error: EngineError) {
        self.failure.get_or_insert(error);
        if self.state != EngineState::Joined {
            self.state = EngineState::Stopping;
            self.ready = None;
            // Keep the owner even if shutdown signalling itself panics. Its
            // destructor still owns the mandatory engine-thread join.
            let _ = catch_unwind(AssertUnwindSafe(|| self.owner.request_stop()));
        }
    }

    fn check_deadline(&mut self) -> Result<(), EngineError> {
        if matches!(
            self.state,
            EngineState::Starting | EngineState::Initializing
        ) && Instant::now() >= self.deadline
        {
            self.fail(EngineError::ReadinessTimeout);
            return Err(EngineError::ReadinessTimeout);
        }
        if matches!(self.state, EngineState::Stopping | EngineState::Joined) {
            return Err(self.failure.clone().unwrap_or(EngineError::Stopping));
        }
        Ok(())
    }

    pub fn poll(&mut self) -> Result<EnginePoll, EngineError> {
        self.guarded(|this| {
            this.check_deadline()?;
            if this.owner.state() == State::Starting {
                match this.owner.wait_channels(Duration::ZERO) {
                    Ok(false) => return Ok(EnginePoll::Idle),
                    Ok(true) => {}
                    Err(error) => {
                        let error = EngineError::Failed(error.to_string());
                        this.fail(error.clone());
                        return Err(error);
                    }
                }
            }
            match this.owner.poll() {
                Ok(Poll::Idle) => Ok(EnginePoll::Idle),
                Ok(Poll::Handled) => Ok(EnginePoll::Handled),
                Ok(Poll::Event(event)) => {
                    if matches!(event.request, Request::Ready) {
                        if this.state != EngineState::Starting || event.reply.is_none() {
                            let error =
                                EngineError::Failed("unexpected consensus ready event".into());
                            this.fail(error.clone());
                            return Err(error);
                        }
                        this.ready = event.reply;
                        this.state = EngineState::Initializing;
                    }
                    Ok(EnginePoll::Event(event))
                }
                result => {
                    let error = match result {
                        Err(error) => EngineError::Failed(error.to_string()),
                        _ => EngineError::Failed("engine application channel closed".into()),
                    };
                    this.fail(error.clone());
                    Err(error)
                }
            }
        })
    }

    pub fn respond(
        &mut self,
        token: ReplyToken,
        response: Response,
    ) -> Result<Delivery, EngineError> {
        self.guarded(|this| {
            this.check_deadline()?;
            if matches!(response, Response::Abandon) && this.ready == Some(token) {
                let error = EngineError::Failed("consensus initialization abandoned".into());
                this.fail(error.clone());
                return Err(error);
            }
            match this.owner.respond(token, response) {
                Ok(delivery) => {
                    if this.ready == Some(token) {
                        if delivery == Delivery::Expired {
                            let error =
                                EngineError::Failed("consensus ready receiver expired".into());
                            this.fail(error.clone());
                            return Err(error);
                        }
                        this.ready = None;
                        this.state = EngineState::Running;
                    }
                    Ok(delivery)
                }
                Err(error) => {
                    let malformed = matches!(error, ReplyError::Malformed(_));
                    let error = EngineError::Reply(error);
                    if malformed {
                        this.fail(error.clone());
                    }
                    Err(error)
                }
            }
        })
    }

    pub fn publish(
        &mut self,
        generation: u64,
        part: &ProposalPartBytes,
    ) -> Result<Publish, EngineError> {
        self.guarded(|this| {
            this.check_deadline()?;
            if generation != this.generation {
                return Err(EngineError::StaleGeneration);
            }
            if this.state != EngineState::Running {
                return Err(EngineError::NotRunning);
            }
            match this.owner.publish(generation, part) {
                Ok(Publish::Closed) => {
                    let error = EngineError::Failed("engine publication channel closed".into());
                    this.fail(error.clone());
                    Err(error)
                }
                Ok(result) => Ok(result),
                Err(error) => {
                    let error = EngineError::Failed(error.to_string());
                    this.fail(error.clone());
                    Err(error)
                }
            }
        })
    }

    pub fn request_stop(&mut self) -> Result<(), EngineError> {
        self.guarded(|this| {
            if this.state != EngineState::Joined {
                this.state = EngineState::Stopping;
                this.ready = None;
                this.owner.request_stop();
            }
            Ok(())
        })
    }

    pub fn wait_stopped(&mut self, timeout: Duration) -> Result<bool, EngineError> {
        self.guarded(|this| {
            if !matches!(this.state, EngineState::Stopping | EngineState::Joined) {
                return Err(EngineError::NotRunning);
            }
            let result = this.owner.wait_stopped(timeout);
            // A joined engine can still have a failure. Expose both facts so
            // errors never accidentally authorize starting another generation.
            if this.owner.state() == State::Joined {
                this.state = EngineState::Joined;
            }
            match result {
                Ok(false) => Ok(false),
                Ok(true) => match &this.failure {
                    Some(error) => Err(error.clone()),
                    None => Ok(true),
                },
                Err(error) => {
                    let error = EngineError::Failed(error.to_string());
                    this.failure.get_or_insert(error);
                    Err(this.failure.clone().expect("recorded failure"))
                }
            }
        })
    }

    pub fn request_listen_address(&mut self) -> Result<bool, EngineError> {
        self.guarded(|this| {
            this.check_deadline()?;
            if this.state == EngineState::Starting {
                return Err(EngineError::NotRunning);
            }
            this.owner
                .request_listen_address()
                .map_err(|error| EngineError::Failed(error.to_string()))
        })
    }

    pub fn poll_listen_address(&mut self) -> Result<Option<String>, EngineError> {
        self.guarded(|this| {
            this.check_deadline()?;
            if this.state == EngineState::Starting {
                return Err(EngineError::NotRunning);
            }
            this.owner
                .poll_listen_address()
                .map_err(|error| EngineError::Failed(error.to_string()))
        })
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
