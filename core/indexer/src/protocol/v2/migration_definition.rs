use crate::protocol::identity::{ExecutionDefinitionId, MigrationDefinition, domain_digest};
use crate::protocol::migration_work::MigrationWork;

pub(crate) fn preserve(execution: ExecutionDefinitionId) -> MigrationDefinition {
    let schema = domain_digest(b"kontor/storage-schema/v1", b"qualification-contract-v2");
    MigrationDefinition {
        execution,
        routine: "kontor/noop/v2".into(),
        input_schema: schema,
        output_schema: schema,
        accounting_version: 1,
        budget: MigrationWork::default(),
    }
}

pub(crate) fn install_fixture(execution: ExecutionDefinitionId) -> MigrationDefinition {
    MigrationDefinition {
        execution,
        routine: "kontor/qualification-contract/v2".into(),
        input_schema: domain_digest(b"kontor/storage-schema/v1", b"legacy-contract-state-v1"),
        output_schema: domain_digest(b"kontor/storage-schema/v1", b"qualification-contract-v2"),
        accounting_version: 1,
        // Installation is bounded by the compiled fixture, not ledger size.
        budget: MigrationWork {
            computation_steps: 1024 * 1024,
            read_operations: 8,
            read_bytes: 1024,
            write_operations: 3,
            write_bytes: 1024 * 1024,
        },
    }
}
