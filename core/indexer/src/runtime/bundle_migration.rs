use std::sync::Arc;

use super::bundle_session::{BundleSession, infrastructure};
use crate::protocol::execution::ExecutorVersion;
use crate::protocol::identity::MigrationDefinition;
use crate::protocol::migration_work::MigrationWork;
use crate::protocol::operations::MigrationCall;
use crate::protocol::v1::definition::execution_definition;
use crate::protocol::v1::migration::{MigrationContext, MigrationFailure};
use crate::protocol::v1::migration_definition;
use crate::protocol::v2::{migration_definition as p2_migration, token_migration};

enum Routine {
    Noop,
    Qualification,
    TokenCount,
}

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
                session.verify_operation_owner(opaque).map_err(unstarted)?;
                let mut runtime = session.runtime.lock().await;
                runtime
                    .verify_bundle_operation(&selection, 8)
                    .map_err(infrastructure)
                    .map_err(unstarted)?;
                let mut runtime = runtime
                    .bind_selection(&selection)
                    .map_err(infrastructure)
                    .map_err(unstarted)?;
                runtime.storage.height = selection.3.1;
                let execution =
                    execution_definition().map_err(|error| (2, error.to_string(), Some([0; 5])))?;
                let Ok(definition) = MigrationDefinition::decode(&definition) else {
                    return Ok(Err((0, Some([0; 5]))));
                };
                let routine = match runtime.executor_version() {
                    ExecutorVersion::P2 if definition == p2_migration::preserve(execution) => {
                        Routine::Noop
                    }
                    ExecutorVersion::P2 if definition == p2_migration::token_count(execution) => {
                        Routine::TokenCount
                    }
                    ExecutorVersion::LegacyP1
                        if definition == migration_definition::noop(execution) =>
                    {
                        Routine::Noop
                    }
                    ExecutorVersion::LegacyP1
                        if qualification
                            && [false, true].into_iter().any(|exhaust| {
                                definition
                                    == migration_definition::qualification(execution, exhaust)
                            }) =>
                    {
                        Routine::Qualification
                    }
                    _ => return Ok(Err((0, Some([0; 5])))),
                };
                let mut used = MigrationWork::default();
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
                    let outcome = match routine {
                        Routine::Noop => Ok(()),
                        Routine::Qualification => qualification_rewrite(&mut context).await,
                        Routine::TokenCount => token_migration::backfill(&mut context).await,
                    };
                    used = context.used();
                    outcome.and_then(|()| context.finish())
                }
                .await;
                match result {
                    Ok(work) => Ok(Ok(work.values())),
                    Err(MigrationFailure::Budget) => Ok(Err((1, Some(used.values())))),
                    Err(MigrationFailure::InvalidOperation(_)) => Ok(Err((2, Some(used.values())))),
                    Err(MigrationFailure::Infrastructure(message)) => {
                        Err((0, message, Some(used.values())))
                    }
                }
            })
        })
    }
}

fn unstarted((tag, message): (u8, String)) -> (u8, String, Option<[u64; 5]>) {
    (tag, message, Some([0; 5]))
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
