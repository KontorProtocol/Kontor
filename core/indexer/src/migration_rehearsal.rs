use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use bitcoin::{BlockHash, Network, hashes::Hash};
use clap::Args;
use libsql::{Builder, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::database::canonical_history::{self, HistoryState};
use crate::database::certified_history::{self, Status, completion, control};
use crate::database::init::load_extensions;
use crate::database::queries::get_checkpoint_latest;
use crate::protocol::coordinator::baseline::consensus_is_registered;
use crate::protocol::coordinator::linked::session_factory_for_definition;
use crate::protocol::coordinator::manifest::ProtocolManifest;
use crate::protocol::coordinator::migration::{
    self, MigrationAttemptWork, MigrationRejected, MigrationRequest,
};
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::protocol::identity::{ExecutionIdentity, MigrationDefinition, PlanId, domain_digest};
use crate::protocol::migration_work::MigrationWork;
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::LinkedSession;

const MAX_TARGET_BYTES: u64 = 262_144;

#[derive(Args)]
pub struct MigrationRehearsalArgs {
    /// Existing node database, opened read-only and never initialized or migrated.
    #[arg(long)]
    pub database: PathBuf,
    /// JSON containing manifest_hex and migration_definition_hex.
    #[arg(long)]
    pub target: PathBuf,
    #[arg(long)]
    pub network: Network,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetFile {
    manifest_hex: String,
    migration_definition_hex: String,
}

#[derive(Debug, Serialize)]
pub struct WorkReport {
    pub computation_steps: String,
    pub read_operations: String,
    pub read_bytes: String,
    pub write_operations: String,
    pub write_bytes: String,
}

impl From<MigrationWork> for WorkReport {
    fn from(work: MigrationWork) -> Self {
        Self {
            computation_steps: work.computation_steps.to_string(),
            read_operations: work.read_operations.to_string(),
            read_bytes: work.read_bytes.to_string(),
            write_operations: work.write_operations.to_string(),
            write_bytes: work.write_bytes.to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TargetSupport {
    pub execution_definition_id: String,
    pub consensus_definition_id: String,
    pub executor_registered: bool,
    pub consensus_registered: bool,
    /// None means the attempt did not establish whether the routine is registered.
    pub migration_registered: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RehearsalReport {
    pub scope: &'static str,
    pub authorizes_upgrade: bool,
    pub network: String,
    pub chain_id: String,
    pub source_protocol_id: String,
    pub source_era_id: String,
    pub decision_height: String,
    pub decision_id: String,
    pub application_ordinal: String,
    pub input_lineage: String,
    pub bitcoin_height: String,
    pub bitcoin_hash: String,
    pub checkpoint: Option<String>,
    pub target_protocol_id: String,
    pub target_support: TargetSupport,
    pub target_manifest_hex: String,
    pub migration_definition_id: String,
    pub migration_definition_hex: String,
    pub work_budget: WorkReport,
    pub work_consumed: Option<WorkReport>,
    pub outcome: &'static str,
    pub error: Option<String>,
    pub output_lineage: Option<String>,
}

pub async fn run(args: MigrationRehearsalArgs) -> Result<RehearsalReport> {
    let mut bytes = Vec::new();
    File::open(&args.target)?
        .take(MAX_TARGET_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_TARGET_BYTES,
        "target file exceeds byte limit"
    );
    let target: TargetFile = serde_json::from_slice(&bytes)?;
    let manifest = ProtocolManifest::decode(&hex::decode(target.manifest_hex)?)?;
    let definition = MigrationDefinition::decode(&hex::decode(target.migration_definition_hex)?)?;
    ensure!(
        definition.id()? == manifest.migration && definition.execution == manifest.executor,
        "migration definition differs from target manifest"
    );
    let (_directory, snapshot) = isolated_snapshot(&args.database).await?;
    rehearse(&snapshot, args.network, &manifest, &definition).await
}

async fn isolated_snapshot(path: &Path) -> Result<(TempDir, Connection)> {
    let source = Builder::new_local(path)
        .flags(OpenFlags::SQLITE_OPEN_READ_ONLY)
        .build()
        .await?;
    let source = source.connect()?;
    let directory = TempDir::new()?;
    let path = directory.path().join("rehearsal.db");
    // SQLite copies one consistent snapshot, including committed WAL contents.
    // A filesystem copy could combine incompatible database and WAL generations.
    source
        .execute(
            "VACUUM INTO ?1",
            [path.to_str().context("snapshot path is not UTF-8")?],
        )
        .await?;
    let snapshot = Builder::new_local(&path).build().await?.connect()?;
    snapshot
        .execute_batch(
            "PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;
        PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;",
        )
        .await?;
    load_extensions(directory.path(), &snapshot).await?;
    Ok((directory, snapshot))
}

async fn rehearse(
    conn: &Connection,
    network: Network,
    target: &ProtocolManifest,
    definition: &MigrationDefinition,
) -> Result<RehearsalReport> {
    let frontier = certified_history::frontier(conn).await?;
    ensure!(
        frontier.status == Status::Ready
            && frontier.closed_height > 0
            && frontier.closed_height == frontier.authenticated_height,
        "rehearsal requires a fully closed certified snapshot; retry after execution catches up"
    );
    let context = frontier
        .context
        .context("snapshot lacks protocol context")?;
    let closed = completion::completed(conn, frontier.closed_height).await?;
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        anyhow::bail!("snapshot lacks canonical execution history");
    };
    ensure!(
        cursor.authentic
            && cursor.chain == context.chain
            && cursor.ordinal == closed.output.ordinal
            && cursor.lineage == closed.output.lineage
            && cursor.storage_height == closed.bitcoin_height,
        "snapshot canonical state differs from certified closure"
    );
    let state = control::admission::state(conn, context).await?;
    ensure!(
        target.chain == context.chain
            && target.predecessor == context.protocol
            && state.current_manifest.protocol_number.checked_add(1)
                == Some(target.protocol_number)
            && target.input_state_schema == state.current_manifest.state_schema
            && target.output_state_schema == target.state_schema,
        "target does not follow the snapshot protocol and state schema"
    );
    ensure!(
        definition.id()? == target.migration && definition.execution == target.executor,
        "migration definition differs from target manifest"
    );
    let checkpoint = get_checkpoint_latest(conn)
        .await?
        .map(|row| -> Result<[u8; 32]> {
            hex::decode(row.hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid checkpoint digest"))
        })
        .transpose()?;
    let mut report = RehearsalReport {
        scope: "migration_on_snapshot_only",
        authorizes_upgrade: false,
        network: network.to_string(),
        chain_id: hex::encode(context.chain.0),
        source_protocol_id: hex::encode(context.protocol.0),
        source_era_id: hex::encode(context.era),
        decision_height: closed.height.to_string(),
        decision_id: hex::encode(closed.decision),
        application_ordinal: cursor.ordinal.to_string(),
        input_lineage: hex::encode(cursor.lineage),
        bitcoin_height: closed.bitcoin_height.to_string(),
        bitcoin_hash: BlockHash::from_byte_array(closed.bitcoin_hash).to_string(),
        checkpoint: checkpoint.map(hex::encode),
        target_protocol_id: hex::encode(target.id()?.0),
        target_support: TargetSupport {
            execution_definition_id: hex::encode(target.executor.0),
            consensus_definition_id: hex::encode(target.consensus),
            executor_registered: false,
            consensus_registered: consensus_is_registered(target.consensus),
            migration_registered: None,
        },
        target_manifest_hex: hex::encode(target.encode()?),
        migration_definition_id: hex::encode(definition.id()?.0),
        migration_definition_hex: hex::encode(definition.encode()?),
        work_budget: definition.budget.into(),
        work_consumed: Some(MigrationWork::default().into()),
        outcome: "failed",
        error: None,
        output_lineage: None,
    };
    let factory = match session_factory_for_definition(network, target.executor, None) {
        Ok(factory) => factory,
        Err(error) => {
            report.error = Some(format!("{error:#}"));
            return Ok(report);
        }
    };
    report.target_support.executor_registered = true;
    let service = OwnerService::new();
    let result = async {
        let executor = factory(conn.clone()).await?;
        let session = LinkedSession::new(conn.clone(), executor);
        let anchor_hash = BlockHash::from_byte_array(closed.bitcoin_hash);
        let selection = select_legacy_p1(
            conn,
            network,
            ApplicationPosition::Migration {
                anchor_height: closed.bitcoin_height,
                anchor_hash,
            },
        )
        .await?;
        // This identity belongs only to the disposable rehearsal. It cannot
        // serve as an authorized plan or a receipt for live activation.
        let request = MigrationRequest {
            expected: cursor,
            execution: ExecutionIdentity::Protocol {
                protocol: target.id()?,
                execution: target.executor,
            },
            plan: PlanId(domain_digest(
                b"kontor/migration-rehearsal/v1",
                &target.encode()?,
            )),
            anchor_height: closed.bitcoin_height,
            anchor_hash,
            checkpoint,
            definition: definition.clone(),
        };
        migration::apply(&service, &session, &selection, network, &request).await
    }
    .await;
    match result {
        Ok(receipt) => {
            report.target_support.migration_registered = Some(true);
            report.work_consumed = Some(receipt.work.into());
            match receipt.application.lineage() {
                Ok(lineage) => {
                    report.output_lineage = Some(hex::encode(lineage));
                    report.outcome = "succeeded";
                }
                Err(error) => report.error = Some(error.to_string()),
            }
        }
        Err(error) => {
            report.target_support.migration_registered = match error
                .downcast_ref::<MigrationRejected>()
            {
                Some(MigrationRejected::UnknownDefinition) => Some(false),
                Some(MigrationRejected::Budget | MigrationRejected::InvalidOperation) => Some(true),
                _ => None,
            };
            if let Some(work) = error.downcast_ref::<MigrationAttemptWork>() {
                report.work_consumed = work.0.map(Into::into);
            }
            report.error = Some(format!("{error:#}"));
        }
    }
    service.shutdown();
    if let Some(driver) = service.take_driver()
        && let Err(error) = async {
            driver.await??;
            Ok::<_, anyhow::Error>(())
        }
        .await
    {
        report.outcome = "failed";
        report.error = Some(format!(
            "owner shutdown failed: {error:#}; migration result: {:?}",
            report.error
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::new_connection;

    #[tokio::test]
    async fn snapshot_includes_committed_wal_and_excludes_uncommitted_work() -> Result<()> {
        let directory = TempDir::new()?;
        let path = directory.path().join("source.db");
        let source = Builder::new_local(&path).build().await?.connect()?;
        source
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
            CREATE TABLE test_state (value INTEGER);
            INSERT INTO test_state VALUES (1);
            BEGIN IMMEDIATE; INSERT INTO test_state VALUES (2);",
            )
            .await?;
        let (_snapshot_directory, snapshot) = isolated_snapshot(&path).await?;
        let sum = |conn: Connection| async move {
            conn.query("SELECT sum(value) FROM test_state", ())
                .await?
                .next()
                .await?
                .context("missing sum")?
                .get::<i64>(0)
                .map_err(anyhow::Error::from)
        };
        assert_eq!(sum(snapshot.clone()).await?, 1);
        source.execute("COMMIT", ()).await?;
        assert_eq!(sum(source.clone()).await?, 3);
        snapshot
            .execute("INSERT INTO test_state VALUES (100)", ())
            .await?;
        assert_eq!(sum(snapshot).await?, 101);
        assert_eq!(sum(source).await?, 3);
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_does_not_create_missing_source() -> Result<()> {
        let directory = TempDir::new()?;
        let missing = directory.path().join("absent.db");
        assert!(isolated_snapshot(&missing).await.is_err());
        assert!(!missing.exists());
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_writes_keep_checkpoint_functions_and_foreign_keys() -> Result<()> {
        let directory = TempDir::new()?;
        let source = new_connection(directory.path(), "source.db").await?;
        source
            .execute(
                "INSERT INTO blocks (height, hash, relevant) VALUES (1, ?1, 1)",
                [BlockHash::from_byte_array([1; 32]).to_string()],
            )
            .await?;
        source
            .execute(
                "INSERT INTO contract_state (contract_id, height, size, path, value)
            VALUES (1, 1, 1, x'01', x'02')",
                (),
            )
            .await?;
        let before = get_checkpoint_latest(&source)
            .await?
            .context("source checkpoint")?
            .hash;
        let (_snapshot_directory, snapshot) =
            isolated_snapshot(&directory.path().join("source.db")).await?;
        snapshot
            .execute(
                "INSERT INTO contract_state (contract_id, height, size, path, value)
            VALUES (1, 1, 1, x'02', x'03')",
                (),
            )
            .await?;
        assert_ne!(
            get_checkpoint_latest(&snapshot).await?.unwrap().hash,
            before
        );
        assert_eq!(get_checkpoint_latest(&source).await?.unwrap().hash, before);
        snapshot
            .execute_batch(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY);
            CREATE TABLE child (parent_id INTEGER REFERENCES parent(id));",
            )
            .await?;
        assert!(
            snapshot
                .execute("INSERT INTO child VALUES (123)", ())
                .await
                .is_err()
        );
        Ok(())
    }
}
