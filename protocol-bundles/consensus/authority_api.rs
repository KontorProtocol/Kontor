use std::fmt;
use std::sync::Arc;

pub enum Authority {
    Follower,
    Validator {
        public_key: [u8; 32],
        signer: Arc<dyn SigningService>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteStep {
    Prevote,
    Precommit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningRequest {
    Vote {
        generation: u64,
        height: u64,
        round: u32,
        step: VoteStep,
        value_id: Option<[u8; 32]>,
        validator_address: [u8; 20],
        preimage: Vec<u8>,
    },
    Proposal {
        generation: u64,
        height: u64,
        round: u32,
        pol_round: Option<u32>,
        validator_address: [u8; 20],
        descriptor: Vec<u8>,
        preimage: Vec<u8>,
    },
    ProposalFin {
        generation: u64,
        height: u64,
        round: u32,
        descriptor: Vec<u8>,
        digest: [u8; 32],
    },
    ValidatorProof {
        generation: u64,
        public_key: [u8; 32],
        network_peer_id: Vec<u8>,
        preimage: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum SigningError {
    InvalidRequest(String),
    Conflict,
    Stale,
    Fenced,
    Storage(String),
    Fault(String),
}

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => write!(formatter, "invalid signing request: {reason}"),
            Self::Conflict => formatter.write_str("conflicting consensus signature request"),
            Self::Stale => formatter.write_str("regressing consensus signature request"),
            Self::Fenced => formatter.write_str("consensus signing generation is fenced"),
            Self::Storage(reason) => write!(formatter, "durable signing storage failed: {reason}"),
            Self::Fault(reason) => write!(formatter, "durable signing authority fault: {reason}"),
        }
    }
}

impl std::error::Error for SigningError {}

pub trait SigningService: Send + Sync + 'static {
    fn sign(&self, request: SigningRequest) -> Result<[u8; 64], SigningError>;
}
