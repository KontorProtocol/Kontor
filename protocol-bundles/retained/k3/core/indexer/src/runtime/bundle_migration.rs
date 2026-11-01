use std::sync::Arc;

use super::bundle_session::{BundleSession, infrastructure};
use crate::protocol::identity::MigrationDefinition;
use crate::protocol::operations::MigrationCall;
use crate::protocol::v1::definition::execution_definition;
use crate::protocol::v1::migration::{MigrationContext, MigrationFailure};
use crate::protocol::v1::migration_definition;

impl BundleSession {
    pub(crate) fn migration(self: &Arc<Self>) -> MigrationCall {
        self.migration_registry(false)
    }

    pub(crate) fn migration_qualification(self: &Arc<Self>) -> MigrationCall {
        self.migration_registry(true)
    }

    fn migration_registry(self: &Arc<Self>, qualification: bool) -> MigrationCall {
        let expected = self.clone();
        Arc::new(move |opaque, selection, definition, input| {
            let session = expected.clone();
            Box::pin(async move {
                session.verify_operation_owner(opaque)?;
                let mut runtime = session.runtime.lock().await;
                runtime
                    .verify_bundle_operation(&selection, 8)
                    .map_err(infrastructure)?;
                let mut runtime = runtime.bind_selection(&selection).map_err(infrastructure)?;
                runtime.storage.height = selection.3.1;
                let execution = execution_definition().map_err(|error| (2, error.to_string()))?;
                let Ok(definition) = MigrationDefinition::decode(&definition) else {
                    return Ok(Err(0));
                };
                let rewrite = if definition == migration_definition::noop(execution) {
                    false
                } else if qualification
                    && [false, true].into_iter().any(|exhaust| {
                        definition == migration_definition::qualification(execution, exhaust)
                    })
                {
                    true
                } else {
                    return Ok(Err(0));
                };
                let result = async {
                    let mut context = MigrationContext::new(
                        &runtime.storage,
                        input,
                        definition.budget,
                        runtime.storage.bundle_owner.clone().ok_or(
                            MigrationFailure::InvalidOperation(
                                "migration requires an admitted root",
                            ),
                        )?,
                    )
                    .await?;
                    if rewrite {
                        qualification_rewrite(&mut context).await?;
                    }
                    context.finish()
                }
                .await;
                match result {
                    Ok(work) => Ok(Ok(work.values())),
                    Err(MigrationFailure::Budget) => Ok(Err(1)),
                    Err(MigrationFailure::InvalidOperation(_)) => Ok(Err(2)),
                    Err(MigrationFailure::Infrastructure(message)) => Err((0, message)),
                }
            })
        })
    }
}

async fn qualification_rewrite(context: &mut MigrationContext) -> Result<(), MigrationFailure> {
    context.step(1)?;
    let row = context.input_point(1, b"migration-input").await?.ok_or(
        MigrationFailure::InvalidOperation("qualification input is absent"),
    )?;
    let value = context.input_value(&row).await?;
    context.begin_nested().await?;
    context
        .set(1, b"migration-output", &value, row.deposit())
        .await?;
    context.finish_nested(false).await?;
    context
        .set(1, b"migration-output", &value, row.deposit())
        .await?;
    context.delete(1, b"migration-input").await?;
    // Open the first scan only after destructive writes at the same height.
    let original = context
        .input_next(1, None)
        .await?
        .ok_or(MigrationFailure::InvalidOperation(
            "qualification snapshot lost its input",
        ))?;
    let key = context.input_key(&original).await?;
    let retained = context.input_value(&original).await?;
    let current = context.current_value(1, b"migration-output").await?;
    context.step((key.len() + retained.len() + value.len()) as u64)?;
    if key != b"migration-input"
        || retained != value
        || current.as_ref() != Some(&value)
        || context.input_next(1, Some(&key)).await?.is_some()
    {
        return Err(MigrationFailure::InvalidOperation(
            "qualification snapshot or current-state read changed",
        ));
    }
    Ok(())
}
