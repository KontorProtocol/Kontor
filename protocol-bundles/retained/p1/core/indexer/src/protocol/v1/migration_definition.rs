use crate::protocol::identity::{ExecutionDefinitionId, MigrationDefinition, domain_digest};
use crate::protocol::migration_work::MigrationWork;

pub(crate) fn noop(execution: ExecutionDefinitionId) -> MigrationDefinition {
    let schema = domain_digest(b"kontor/storage-schema/v1", b"legacy-contract-state-v1");
    MigrationDefinition {
        execution,
        routine: "kontor/noop/v1".into(),
        input_schema: schema,
        output_schema: schema,
        accounting_version: 1,
        budget: MigrationWork::default(),
    }
}

// These definitions are available only through the qualification factory's
// registry. The normal node factory cannot select them by submitted definition.
pub(crate) fn qualification(
    execution: ExecutionDefinitionId,
    exhaust: bool,
) -> MigrationDefinition {
    let mut definition = noop(execution);
    definition.routine = "kontor/qualification/rewrite/v1".into();
    definition.budget = MigrationWork {
        computation_steps: 64,
        read_operations: 32,
        read_bytes: 4096,
        write_operations: if exhaust { 1 } else { 32 },
        write_bytes: 4096,
    };
    definition
}
