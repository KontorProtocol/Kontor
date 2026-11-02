use super::selection::{ExecutionSelection, ExecutorVersion};
use crate::runtime::{ContractAddress, ExecutionError, Runtime};

pub(crate) async fn execute_selected_view(
    runtime: &mut Runtime,
    selection: &ExecutionSelection,
    contract_address: &ContractAddress,
    expr: &str,
) -> Result<String, ExecutionError> {
    selection
        .verify_view(
            &runtime.get_storage_conn(),
            runtime.network,
            runtime.executor_version(),
        )
        .await
        .map_err(ExecutionError::NonDeterministic)?;
    match selection.version() {
        ExecutorVersion::LegacyP1 => {
            runtime
                .bind_selection(&selection.envelope())
                .map_err(ExecutionError::NonDeterministic)?
                .execute(None, None, contract_address, expr)
                .await
        }
    }
}
