//! Node-owned coordination data. Bundle adapters preserve distinct dependency identities.
use std::error::Error;
use std::fmt;
use std::time::Duration;

use kontor_consensus_first::api::ReplyToken as FirstToken;
use kontor_consensus_second::api::ReplyToken as SecondToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyToken {
    First(FirstToken),
    Second(SecondToken),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Validator {
    pub(crate) public_key: [u8; 32],
    pub(crate) voting_power: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Timeouts {
    pub(crate) propose: Duration,
    pub(crate) propose_delta: Duration,
    pub(crate) prevote: Duration,
    pub(crate) prevote_delta: Duration,
    pub(crate) precommit: Duration,
    pub(crate) precommit_delta: Duration,
    pub(crate) rebroadcast: Duration,
    pub(crate) max_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeightParameters {
    pub(crate) height: u64,
    pub(crate) validators: Vec<Validator>,
    pub(crate) timeouts: Timeouts,
    pub(crate) target_time: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValueBytes(pub(crate) Vec<u8>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProposalBytes(pub(crate) Vec<u8>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateBytes(pub(crate) Vec<u8>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProposalPartBytes(pub(crate) Vec<u8>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyncedValueBytes(pub(crate) Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Proposer,
    Validator,
    Observer,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Event {
    pub(crate) generation: u64,
    pub(crate) request: Request,
    pub(crate) reply: Option<ReplyToken>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Request {
    Ready,
    StartedRound {
        height: u64,
        round: Option<u32>,
        proposer: [u8; 20],
        role: Role,
    },
    GetValue {
        height: u64,
        round: Option<u32>,
        timeout: Duration,
    },
    ProposalPart {
        from: Vec<u8>,
        published_by: Option<Vec<u8>>,
        part: ProposalPartBytes,
    },
    Decided {
        certificate: CertificateBytes,
    },
    Finalized {
        certificate: CertificateBytes,
        evidence: String,
    },
    HistoryMinHeight,
    DecidedValues {
        start: u64,
        end: u64,
    },
    SyncedValue {
        height: u64,
        round: Option<u32>,
        proposer: [u8; 20],
        value: Vec<u8>,
    },
    RestreamProposal {
        height: u64,
        round: Option<u32>,
        valid_round: Option<u32>,
        address: [u8; 20],
        value_id: [u8; 32],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NextHeight {
    Start(HeightParameters),
    Restart(HeightParameters),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SyncOutcome {
    Verdict(ProposalBytes),
    PeerFault,
    LocalTransientError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Response {
    Ready(HeightParameters),
    StartedRound(Vec<ProposalBytes>),
    Value {
        height: u64,
        round: Option<u32>,
        value: ValueBytes,
    },
    ProposalPart(Option<ProposalBytes>),
    Decided,
    Finalized(NextHeight),
    HistoryMinHeight(u64),
    DecidedValues(Vec<SyncedValueBytes>),
    SyncedValue(SyncOutcome),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EngineState {
    Starting,
    Initializing,
    Running,
    Stopping,
    Joined,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EnginePoll {
    Idle,
    Handled,
    Event(Event),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReplyError {
    StaleGeneration,
    UnknownToken,
    WrongOperation,
    Malformed(String),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    Delivered,
    Expired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Publish {
    Sent,
    Full,
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublishError {
    Unconfirmed,
    Full(ProposalPartBytes),
    Closed(ProposalPartBytes),
    Engine(EngineError, ProposalPartBytes),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EngineError {
    InvalidConfiguration(String),
    NotRunning,
    Stopping,
    ReadinessTimeout,
    StaleGeneration,
    Reply(ReplyError),
    Failed(String),
    Panicked,
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(reason) => {
                write!(f, "invalid engine configuration: {reason}")
            }
            Self::NotRunning => f.write_str("engine is not running"),
            Self::Stopping => f.write_str("engine is stopping or joined"),
            Self::ReadinessTimeout => f.write_str("engine readiness timed out"),
            Self::StaleGeneration => f.write_str("stale engine generation"),
            Self::Reply(error) => write!(f, "engine reply rejected: {error:?}"),
            Self::Failed(reason) => write!(f, "engine failed: {reason}"),
            Self::Panicked => f.write_str("engine operation panicked"),
        }
    }
}
impl Error for EngineError {}
