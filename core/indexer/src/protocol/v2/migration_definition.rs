use crate::protocol::identity::{ExecutionDefinitionId, MigrationDefinition, domain_digest};
use crate::protocol::migration_work::MigrationWork;

pub(crate) fn preserve(execution: ExecutionDefinitionId) -> MigrationDefinition {
    let schema = domain_digest(
        b"kontor/storage-schema/v1",
        b"token-positive-balance-count-v2",
    );
    MigrationDefinition {
        execution,
        routine: "kontor/noop/v2".into(),
        input_schema: schema,
        output_schema: schema,
        accounting_version: 1,
        budget: MigrationWork::default(),
    }
}

pub(crate) fn token_count(execution: ExecutionDefinitionId) -> MigrationDefinition {
    MigrationDefinition {
        execution,
        routine: "kontor/token-positive-balance-count/v2".into(),
        input_schema: domain_digest(b"kontor/storage-schema/v1", b"legacy-contract-state-v1"),
        output_schema: domain_digest(
            b"kontor/storage-schema/v1",
            b"token-positive-balance-count-v2",
        ),
        accounting_version: 1,
        // Fixed migration work, independent of ordinary transaction gas. Input
        // larger than this allowance fails atomically instead of partial backfill.
        budget: MigrationWork {
            computation_steps: 64 * 1024 * 1024,
            read_operations: 1_000_000,
            read_bytes: 64 * 1024 * 1024,
            write_operations: 1,
            write_bytes: 32,
        },
    }
}
