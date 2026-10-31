use super::native_bootstrap::BootstrapRead;
use super::storage_aux::AuxiliaryCallbacks;
use super::storage_contracts::ContractCallbacks;
use super::storage_footprint::FootprintCallbacks;
use super::storage_identity::{CoreCallbacks, IdentityCallbacks, NonceCallbacks};
use super::storage_keys::KeyCallbacks;
use super::storage_point::PointCallbacks;
use super::storage_rows::RowCallbacks;
use super::storage_session::SessionCallbacks;
use super::storage_state::StateCallbacks;

// Only structural standard-library types cross independently compiled graphs.
// The receiving graph may give these fields names in its own local wrapper.
pub(crate) type StorageCallbacks = (
    BootstrapRead,
    IdentityCallbacks,
    CoreCallbacks,
    NonceCallbacks,
    PointCallbacks,
    StateCallbacks,
    FootprintCallbacks,
    ContractCallbacks,
    KeyCallbacks,
    RowCallbacks,
    SessionCallbacks,
    AuxiliaryCallbacks,
);
