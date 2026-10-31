use crate::protocol::native_bootstrap::BootstrapRead;
use crate::protocol::storage_aux::{HistoryCallbacks, MaintenanceCallbacks};
use crate::protocol::storage_callbacks::StorageCallbacks;
use crate::protocol::storage_contracts::ContractCallbacks;
use crate::protocol::storage_footprint::FootprintCallbacks;
use crate::protocol::storage_identity::{CoreCallbacks, IdentityCallbacks, NonceCallbacks};
use crate::protocol::storage_inspection::InspectionCallbacks;
use crate::protocol::storage_keys::KeyCallbacks;
use crate::protocol::storage_point::PointCallbacks;
use crate::protocol::storage_rows::RowCallbacks;
use crate::protocol::storage_session::SessionCallbacks;
use crate::protocol::storage_state::StateCallbacks;

#[derive(Clone)]
pub(crate) struct StorageHost {
    pub bootstrap: BootstrapRead,
    pub identity: IdentityCallbacks,
    pub core: CoreCallbacks,
    pub nonce: NonceCallbacks,
    pub point: PointCallbacks,
    pub state: StateCallbacks,
    pub footprint: FootprintCallbacks,
    pub contracts: ContractCallbacks,
    pub keys: KeyCallbacks,
    pub rows: RowCallbacks,
    pub session: SessionCallbacks,
    pub history: HistoryCallbacks,
    pub maintenance: MaintenanceCallbacks,
    pub inspection: InspectionCallbacks,
}

impl From<StorageCallbacks> for StorageHost {
    fn from(callbacks: StorageCallbacks) -> Self {
        let (
            bootstrap,
            identity,
            core,
            nonce,
            point,
            state,
            footprint,
            contracts,
            keys,
            rows,
            session,
            auxiliary,
            inspection,
        ) = callbacks;
        let (history, maintenance) = auxiliary;
        Self {
            bootstrap,
            identity,
            core,
            nonce,
            point,
            state,
            footprint,
            contracts,
            keys,
            rows,
            session,
            history,
            maintenance,
            inspection,
        }
    }
}
