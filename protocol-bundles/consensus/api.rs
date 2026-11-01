//! Same-compiler, in-process facade. Each independently linked bundle owns its
//! own types; node adapters translate explicitly rather than sharing dependencies.
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
    pub(crate) fn kind(&self) -> ReplyKind {
        match self {
            Self::Ready(_) => ReplyKind::Ready,
            Self::StartedRound(_) => ReplyKind::StartedRound,
            Self::Value { .. } => ReplyKind::Value,
            Self::ProposalPart(_) => ReplyKind::ProposalPart,
            Self::Decided => ReplyKind::Decided,
            Self::Finalized(_) => ReplyKind::Finalized,
            Self::HistoryMinHeight(_) => ReplyKind::HistoryMinHeight,
            Self::DecidedValues(_) => ReplyKind::DecidedValues,
            Self::SyncedValue(_) => ReplyKind::SyncedValue,
        }
    }
}
