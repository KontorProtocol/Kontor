mod address;
pub mod codec;
mod context;
pub mod finality_types;
mod genesis;
mod height;
mod proposal;
mod proposal_part;
pub mod signing;
mod validator_set;
mod value;
mod vote;

#[allow(clippy::all)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/consensus.v1.rs"));
}

pub use address::Address;
pub use context::Ctx;
pub use genesis::Genesis;
pub use height::Height;
pub use proposal::Proposal;
pub use proposal_part::{ProposalData, ProposalFin, ProposalInit, ProposalPart};
pub use validator_set::{Validator, ValidatorSet};
pub use value::{BatchTx, Value, ValueId};
pub use vote::Vote;

// Re-export from malachite for downstream crates that don't depend on it directly
pub use malachitebft_core_types::CommitCertificate;
