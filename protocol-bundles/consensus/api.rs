//! Same-compiler, in-process facade. Each independently linked bundle owns its
//! own types; node adapters translate explicitly rather than sharing dependencies.
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyToken {
    pub(crate) generation: u64,
    pub(crate) id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub public_key: [u8; 32],
    pub voting_power: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timeouts {
    pub propose: Duration,
    pub propose_delta: Duration,
    pub prevote: Duration,
    pub prevote_delta: Duration,
    pub precommit: Duration,
    pub precommit_delta: Duration,
    pub rebroadcast: Duration,
    pub max_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeightParameters {
    pub height: u64,
    pub validators: Vec<Validator>,
    pub timeouts: Timeouts,
    pub target_time: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueBytes(pub Vec<u8>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalBytes(pub Vec<u8>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateBytes(pub Vec<u8>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalPartBytes(pub Vec<u8>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncedValueBytes(pub Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Proposer,
    Validator,
    Observer,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Event {
    pub generation: u64,
    pub request: Request,
    pub reply: Option<ReplyToken>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
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
pub enum NextHeight {
    Start(HeightParameters),
    Restart(HeightParameters),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    Verdict(ProposalBytes),
    PeerFault,
    LocalTransientError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    Abandon,
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
pub(crate) enum ReplyKind {
    Ready,
    StartedRound,
    Value,
    ProposalPart,
    Decided,
    Finalized,
    HistoryMinHeight,
    DecidedValues,
    SyncedValue,
}
impl Response {
    pub(crate) fn kind(&self) -> Option<ReplyKind> {
        Some(match self {
            Self::Abandon => return None,
            Self::Ready(_) => ReplyKind::Ready,
            Self::StartedRound(_) => ReplyKind::StartedRound,
            Self::Value { .. } => ReplyKind::Value,
            Self::ProposalPart(_) => ReplyKind::ProposalPart,
            Self::Decided => ReplyKind::Decided,
            Self::Finalized(_) => ReplyKind::Finalized,
            Self::HistoryMinHeight(_) => ReplyKind::HistoryMinHeight,
            Self::DecidedValues(_) => ReplyKind::DecidedValues,
            Self::SyncedValue(_) => ReplyKind::SyncedValue,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bootstrap {
    Kademlia,
    Full,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerSelection {
    Kademlia,
    Random,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Discovery {
    pub enabled: bool,
    pub bootstrap: Bootstrap,
    pub selection: PeerSelection,
}

// Deliberately no Debug implementation: this contains the network-only secret.
pub struct EngineConfig {
    pub generation: u64,
    pub channel_capacity: usize,
    pub moniker: String,
    pub network_key: [u8; 32],
    pub listen_address: String,
    pub persistent_peers: Vec<String>,
    pub wal_path: PathBuf,
    pub discovery: Discovery,
    pub readiness_timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineState {
    Starting,
    Initializing,
    Running,
    Stopping,
    Joined,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnginePoll {
    Idle,
    Handled,
    Event(Event),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplyError {
    StaleGeneration,
    UnknownToken,
    WrongOperation,
    Malformed(String),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Delivered,
    Expired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publish {
    Sent,
    Full,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
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
