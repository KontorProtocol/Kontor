use std::sync::Arc;

use super::committee::Committee;
use super::execution::SelectionEnvelope;
use super::operations::{OperationFuture, SessionOwner};

// Status tags are inactive, active, pending join and pending exit. Holders use
// the staking contract's canonical identity strings, not Bitcoin public keys.
pub(crate) type Registration = (Vec<u8>, u8, u64, u64);
pub(crate) type RegistrationObservation = (Committee, Vec<(String, Option<Registration>)>);
pub(crate) type RegistrationCall = Arc<
    dyn Fn(SessionOwner, SelectionEnvelope, Vec<String>) -> OperationFuture<RegistrationObservation>
        + Send
        + Sync,
>;
