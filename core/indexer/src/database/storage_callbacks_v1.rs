use libsql::Connection;

use super::native_bootstrap::bootstrap_reader;
use super::queries::{
    core_callbacks, footprint_callbacks, identity_callbacks, key_callbacks, nonce_callbacks,
    point_callbacks, row_callbacks, state_callbacks,
};
use super::storage_aux_v1::auxiliary_callbacks;
use super::storage_contracts_v1::contract_callbacks;
use super::storage_session_v1::session_callbacks;
use crate::protocol::storage_callbacks::StorageCallbacks;

pub(crate) fn storage_callbacks(conn: &Connection) -> StorageCallbacks {
    (
        bootstrap_reader(conn),
        identity_callbacks(conn),
        core_callbacks(conn),
        nonce_callbacks(conn),
        point_callbacks(conn),
        state_callbacks(conn),
        footprint_callbacks(conn),
        contract_callbacks(conn),
        key_callbacks(conn),
        row_callbacks(conn),
        session_callbacks(conn),
        auxiliary_callbacks(conn),
    )
}
