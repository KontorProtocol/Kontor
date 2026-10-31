use anyhow::Result;

use super::selection::{
    ApplicationPosition, ExecutionSelection, ExecutorVersion, select_legacy_p1,
};
use crate::consensus::ValidatorSet;
use crate::protocol::v1::committee;
use crate::runtime::Runtime;

pub(crate) async fn derive_selected(
    runtime: &mut Runtime,
    selection: &ExecutionSelection,
) -> Result<ValidatorSet> {
    selection
        .verify_committee(
            &runtime.get_storage_conn(),
            runtime.network,
            runtime.executor_version(),
        )
        .await?;
    let mut runtime = runtime.bind_selection(selection)?;
    match selection.version() {
        ExecutorVersion::LegacyP1 => committee::build_validator_set(&mut runtime).await,
    }
}

pub(crate) async fn build_validator_set(runtime: &mut Runtime) -> Result<ValidatorSet> {
    // Startup has an owned runtime but no application savepoint yet. Refresh may
    // already be inside one. A nested storage savepoint keeps every staking read
    // on the selected snapshot and leaves any enclosing transaction intact.
    runtime.storage.savepoint().await?;
    let result = async {
        let selection = select_legacy_p1(
            &runtime.get_storage_conn(),
            runtime.network,
            ApplicationPosition::Committee,
        )
        .await?;
        derive_selected(runtime, &selection).await
    }
    .await;
    runtime.storage.rollback().await?;
    result
}
