#[path = "../../core/indexer/src/consensus/address.rs"]
mod address;
#[path = "../../core/indexer/src/consensus/codec.rs"]
pub(crate) mod codec;
#[path = "../../core/indexer/src/consensus/context.rs"]
mod context;
#[path = "../../core/indexer/src/consensus/height.rs"]
mod height;
#[path = "../../core/indexer/src/consensus/proposal.rs"]
mod proposal;
#[path = "../../core/indexer/src/consensus/proposal_part.rs"]
mod proposal_part;
#[path = "../../core/indexer/src/consensus/validator_set.rs"]
mod validator_set;
#[path = "../../core/indexer/src/consensus/value.rs"]
mod value;
#[path = "../../core/indexer/src/consensus/vote.rs"]
mod vote;

#[cfg(test)]
#[path = "../../core/indexer/src/consensus/test_fixtures.rs"]
pub(crate) mod test_fixtures;

#[path = "signing.rs"]
pub(crate) mod signing;

#[allow(clippy::all)]
pub(crate) mod proto {
    include!(concat!(env!("OUT_DIR"), "/consensus.v1.rs"));
}

pub(crate) use address::Address;
pub(crate) use context::Ctx;
pub(crate) use height::Height;
pub(crate) use proposal::Proposal;
pub(crate) use proposal_part::{ProposalData, ProposalFin, ProposalInit, ProposalPart};
pub(crate) use validator_set::{Validator, ValidatorSet};
pub(crate) use value::{Value, ValueId};
pub(crate) use vote::Vote;
