use std::marker::PhantomData;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Error, Result, bail, ensure};
use malachitebft_app::config::NodeConfig;
use malachitebft_app_channel::{
    Channels, ConsensusContext, ConsensusRequest, EngineBuilder, ManagedEngine, NetworkContext,
    NetworkIdentity, NetworkRequest, RequestContext, SyncContext, WalContext,
};
use malachitebft_engine::network::NetworkStateDump;
use malachitebft_engine::util::events::TxEvent;
use tokio::sync::{mpsc, oneshot};

use crate::channel_bridge::{ChannelBridge, Poll, Publish};
use crate::consensus::Ctx;
use crate::replies::{Delivery, ReplyError};
use crate::wire::WireCodec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Starting,
    ChannelsReady,
    Stopping,
    Joined,
}

struct Auxiliary {
    _events: TxEvent<Ctx>,
    _requests: mpsc::Sender<ConsensusRequest<Ctx>>,
    network: mpsc::Sender<NetworkRequest>,
    dump: Option<oneshot::Receiver<Option<NetworkStateDump>>>,
}

// Construct and keep this owner on the node's dedicated control thread. In
// particular, moving its blocking ManagedEngine destructor onto Tokio is invalid.
pub(crate) struct Owner {
    engine: ManagedEngine<Ctx>,
    generation: u64,
    capacity: usize,
    state: State,
    failure: Option<String>,
    bridge: Option<ChannelBridge>,
    auxiliary: Option<Auxiliary>,
    _control_thread: PhantomData<Rc<()>>,
}

impl Owner {
    pub(crate) fn start<C: NodeConfig + Send + 'static>(
        generation: u64,
        capacity: usize,
        config: C,
        wal: PathBuf,
        identity: NetworkIdentity,
        consensus: ConsensusContext<Ctx>,
    ) -> Result<Self> {
        ensure!(
            generation != 0 && capacity != 0,
            "invalid engine owner configuration"
        );
        let engine = EngineBuilder::new(Ctx::new(), config)
            .with_default_wal(WalContext::new(wal, WireCodec))
            .with_default_network(NetworkContext::new(identity, WireCodec))
            .with_default_sync(SyncContext::new(WireCodec))
            .with_default_consensus(consensus)
            .with_default_request(RequestContext::new(capacity))
            .start_managed()
            .map_err(|error| Error::msg(error.to_string()))?;
        Ok(Self {
            engine,
            generation,
            capacity,
            state: State::Starting,
            failure: None,
            bridge: None,
            auxiliary: None,
            _control_thread: PhantomData,
        })
    }

    pub(crate) fn state(&self) -> State {
        self.state
    }

    pub(crate) fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    // Channel delivery precedes the application's ConsensusReady notification.
    // A node must still process that event before declaring consensus ready.
    pub(crate) fn wait_channels(&mut self, timeout: Duration) -> Result<bool> {
        match self.state {
            State::ChannelsReady => return Ok(true),
            State::Starting => {}
            _ => bail!("engine is stopping or joined"),
        }
        match self.engine.wait_ready(timeout) {
            Ok(None) => Ok(false),
            Ok(Some(Channels {
                consensus,
                network,
                events,
                requests,
                net_requests,
            })) => {
                self.bridge = Some(ChannelBridge::new(
                    self.generation,
                    self.capacity,
                    consensus,
                    network,
                )?);
                self.auxiliary = Some(Auxiliary {
                    _events: events,
                    _requests: requests,
                    network: net_requests,
                    dump: None,
                });
                self.state = State::ChannelsReady;
                Ok(true)
            }
            Err(error) => {
                let error = error.to_string();
                self.fail(error.clone());
                Err(Error::msg(error))
            }
        }
    }

    pub(crate) fn poll(&mut self) -> Result<Poll> {
        ensure!(
            self.state == State::ChannelsReady,
            "engine channels unavailable"
        );
        let result = self.bridge.as_mut().expect("ready bridge").poll();
        match &result {
            Ok(Poll::Closed) => self.fail("engine application channel closed".into()),
            Err(error) => self.fail(error.to_string()),
            _ => {}
        }
        result
    }

    pub(crate) fn respond(
        &mut self,
        generation: u64,
        operation: u8,
        token: u64,
        payload: &[u8],
    ) -> Result<Delivery, ReplyError> {
        if self.state != State::ChannelsReady {
            return Err(ReplyError::StaleGeneration);
        }
        let result = self
            .bridge
            .as_mut()
            .expect("ready bridge")
            .respond(generation, operation, token, payload);
        if let Err(ReplyError::Malformed(error)) = &result {
            self.fail(error.clone());
        }
        result
    }

    pub(crate) fn publish(&mut self, generation: u64, payload: &[u8]) -> Result<Publish> {
        ensure!(
            self.state == State::ChannelsReady && generation == self.generation,
            "stale proposal publication"
        );
        let result = self
            .bridge
            .as_mut()
            .expect("ready bridge")
            .publish(generation, payload);
        match &result {
            Ok(Publish::Closed) => self.fail("engine publication channel closed".into()),
            Err(error) => self.fail(error.to_string()),
            _ => {}
        }
        result
    }

    pub(crate) fn request_listen_address(&mut self) -> Result<bool> {
        ensure!(
            self.state == State::ChannelsReady,
            "engine channels unavailable"
        );
        let auxiliary = self.auxiliary.as_mut().expect("ready auxiliary channels");
        ensure!(
            auxiliary.dump.is_none(),
            "network state request already pending"
        );
        let (sender, receiver) = oneshot::channel();
        match auxiliary
            .network
            .try_send(NetworkRequest::DumpState(sender))
        {
            Ok(()) => {
                auxiliary.dump = Some(receiver);
                Ok(true)
            }
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                bail!("engine network request channel closed")
            }
        }
    }

    pub(crate) fn poll_listen_address(&mut self) -> Result<Option<String>> {
        ensure!(
            self.state == State::ChannelsReady,
            "engine channels unavailable"
        );
        let auxiliary = self.auxiliary.as_mut().expect("ready auxiliary channels");
        let receiver = auxiliary
            .dump
            .as_mut()
            .ok_or_else(|| Error::msg("no pending network state request"))?;
        match receiver.try_recv() {
            Err(oneshot::error::TryRecvError::Empty) => Ok(None),
            result => {
                auxiliary.dump = None;
                match result {
                    Ok(Some(dump)) => Ok(Some(dump.local_node.listen_addr.to_string())),
                    Ok(None) => bail!("engine network state unavailable"),
                    Err(_) => bail!("engine network state reply closed"),
                }
            }
        }
    }

    fn fail(&mut self, error: String) {
        self.failure.get_or_insert(error);
        self.request_stop();
    }

    pub(crate) fn request_stop(&mut self) {
        if self.state == State::Joined {
            return;
        }
        if let Some(bridge) = &mut self.bridge {
            bridge.retire();
        }
        if let Some(auxiliary) = &mut self.auxiliary {
            auxiliary.dump = None;
        }
        self.state = State::Stopping;
        self.engine.request_stop();
    }

    pub(crate) fn wait_stopped(&mut self, timeout: Duration) -> Result<bool> {
        if self.state == State::Joined {
            return match &self.failure {
                Some(error) => Err(Error::msg(error.clone())),
                None => Ok(true),
            };
        }
        ensure!(
            matches!(self.state, State::Stopping | State::Joined),
            "stop must be requested before join"
        );
        match self.engine.wait_stopped(timeout) {
            Ok(false) => Ok(false),
            outcome => {
                // The fork guarantees both success and failure here are joined.
                // A timeout above leaves every ownership field in place.
                self.state = State::Joined;
                self.bridge = None;
                self.auxiliary = None;
                if let Err(error) = outcome {
                    let error = error.to_string();
                    self.failure = Some(match self.failure.take() {
                        Some(previous) => format!("{previous}; shutdown: {error}"),
                        None => error,
                    });
                }
                match &self.failure {
                    Some(error) => Err(Error::msg(error.clone())),
                    None => Ok(true),
                }
            }
        }
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        // Release application reply ports before ManagedEngine's blocking drop.
        self.request_stop();
    }
}

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;
