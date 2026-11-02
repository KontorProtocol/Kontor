#[cfg(kontor_linked)]
use super::{ALTERNATE_GRAPH, alternate_executor};
use std::fs;
use std::path::Path;
#[cfg(not(kontor_linked))]
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use bitcoin::{BlockHash, hashes::Hash};
use indexer_types::BlockRow;
use libsql::{Connection, params};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::fixture::NETWORK;
use super::snapshot::full_state;
use crate::database::canonical_history::{self, HistoryState};
use crate::database::connection::new_connection;
use crate::database::queries::{get_checkpoint_latest, insert_block};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::canonical_input::CanonicalInput;
#[cfg(kontor_linked)]
use crate::protocol::coordinator::linked::retained_session_factory;
#[cfg(not(kontor_linked))]
use crate::protocol::coordinator::linked::session_factory;
use crate::protocol::coordinator::migration::{MigrationRejected, MigrationRequest, apply};
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::protocol::identity::{ChainId, ExecutionIdentity, PlanId};
use crate::protocol::v1::migration_definition;
#[cfg(not(kontor_linked))]
use crate::runtime::bundle_session::BundleSession;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::LinkedSession;

pub(super) async fn seed() -> Result<TempDir> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "source.db").await?;
    conn.execute("BEGIN", ()).await?;
    // Real receipt epochs are random node-local metadata. Independent platform
    // runs need identical fixture input so every table can remain in comparison.
    let updated = conn
        .execute(
            "UPDATE receipt_stream_state SET epoch = ? WHERE singleton = 1",
            params!["a".repeat(64)],
        )
        .await?;
    ensure!(updated == 1, "migration fixture receipt stream is absent");
    canonical_history::bind_genesis(&conn, ChainId([1; 32])).await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(BlockHash::from_byte_array([2; 32]))
            .build(),
    )
    .await?;
    conn.execute("INSERT INTO contract_state (contract_id, height, size, path, value) VALUES (1, 1, 7, ?1, ?2)",
        params![b"migration-input".as_slice(), b"payload".as_slice()]).await?;
    conn.execute("COMMIT", ()).await?;
    conn.execute(
        "VACUUM INTO ?1",
        [dir.path().join("seed.db").to_string_lossy().as_ref()],
    )
    .await?;
    Ok(dir)
}

fn qualification_factory(name: &str) -> Result<SessionFactory> {
    #[cfg(kontor_linked)]
    {
        match name {
            "first" => retained_session_factory(
                NETWORK,
                None,
                kontor_executor_first::qualification_factory,
                kontor_executor_first::execution_definition(),
            ),
            ALTERNATE_GRAPH => retained_session_factory(
                NETWORK,
                None,
                alternate_executor::qualification_factory,
                alternate_executor::execution_definition(),
            ),
            _ => bail!("unknown migration qualification graph"),
        }
    }
    #[cfg(not(kontor_linked))]
    {
        ensure!(name == "in-tree", "unknown migration qualification graph");
        let factory = session_factory(NETWORK, None)?;
        Ok(Arc::new(move |conn| {
            let factory = factory.clone();
            Box::pin(async move {
                let mut executor = factory(conn).await?;
                let bundle = executor
                    .owner
                    .clone()
                    .downcast::<BundleSession>()
                    .map_err(|_| anyhow!("wrong in-tree migration executor"))?;
                executor.operations.migration = bundle.migration_qualification();
                Ok(executor)
            })
        }))
    }
}

async fn prepare(session: &LinkedSession) -> Result<MigrationRequest> {
    let conn = &session.conn;
    let HistoryState::Ready(mut cursor) = canonical_history::state(conn).await? else {
        bail!("migration fixture lacks genesis");
    };
    let definition = session.executor.execution_definition?;
    let execution = ExecutionIdentity::Baseline(definition);
    let hash = BlockHash::from_byte_array([2; 32]);
    conn.execute("BEGIN", ()).await?;
    for source in [
        ApplicationSource::BlockTransactions {
            height: 1,
            hash: hash.to_byte_array(),
            parent_hash: [0; 32],
        },
        ApplicationSource::BlockLifecycle {
            height: 1,
            hash: hash.to_byte_array(),
        },
    ] {
        let input = matches!(source, ApplicationSource::BlockTransactions { .. })
            .then(|| CanonicalInput::bitcoin(&[]))
            .transpose()?;
        cursor = canonical_history::append(
            conn,
            &CanonicalApplication {
                chain: cursor.chain,
                ordinal: cursor.ordinal + 1,
                parent_lineage: cursor.lineage,
                execution,
                storage_height: 1,
                source,
                input,
            },
        )
        .await?;
    }
    conn.execute("COMMIT", ()).await?;
    let checkpoint = get_checkpoint_latest(conn)
        .await?
        .context("seed checkpoint absent")?;
    Ok(MigrationRequest {
        expected: cursor,
        execution,
        plan: PlanId([3; 32]),
        anchor_height: 1,
        anchor_hash: hash,
        checkpoint: Some(
            hex::decode(checkpoint.hash)?
                .try_into()
                .map_err(|_| anyhow!("bad checkpoint"))?,
        ),
        definition: migration_definition::qualification(definition, false),
    })
}

async fn comparable_state(
    conn: &Connection,
    request: &MigrationRequest,
    count: u64,
) -> Result<Value> {
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        bail!("migration journal disappeared");
    };
    ensure!(
        cursor.authentic
            && cursor.chain == request.expected.chain
            && cursor.ordinal == count
            && cursor.storage_height == 1,
        "migration cursor does not match qualification history"
    );
    let mut rows = conn.query("SELECT ordinal, record, lineage, storage_height, authentic FROM canonical_applications ORDER BY ordinal", ()).await?;
    let mut parent = cursor.chain.0;
    let mut ordinal = 0;
    while let Some(row) = rows.next().await? {
        ordinal += 1;
        let record = CanonicalApplication::decode(&row.get::<Vec<u8>>(1)?)?;
        ensure!(
            record.ordinal == ordinal
                && row.get::<u64>(0)? == ordinal
                && record.chain == cursor.chain
                && record.execution == request.execution
                && record.parent_lineage == parent
                && record.storage_height == 1
                && row.get::<u64>(3)? == 1
                && row.get::<i64>(4)? == 1,
            "migration journal record identity/order differs"
        );
        parent = record.lineage()?;
        ensure!(
            row.get::<Vec<u8>>(2)? == parent,
            "migration journal digest differs"
        );
    }
    ensure!(
        ordinal == count && parent == cursor.lineage,
        "migration journal tail differs"
    );
    let mut snapshot = full_state(conn).await?;
    let tables = snapshot
        .as_object_mut()
        .context("SQL snapshot is not an object")?;
    ensure!(
        tables["genesis_applications"] == json!([]),
        "unexpected fixture genesis stages"
    );
    ensure!(
        tables["migration_applications"]
            .as_array()
            .context("missing markers")?
            .len()
            == (count - 2) as usize,
        "migration marker count differs"
    );
    // These four tables intentionally bind each graph's distinct execution ID.
    // They are checked above and through the receipt, not silently normalized.
    for name in [
        "canonical_history_state",
        "canonical_applications",
        "migration_applications",
        "genesis_applications",
    ] {
        ensure!(tables.remove(name).is_some(), "missing journal table");
    }
    Ok(snapshot)
}

pub(super) async fn qualify_graph(
    name: &str,
    seed: &Path,
    production: SessionFactory,
) -> Result<Value> {
    let dir = TempDir::new()?;
    fs::copy(seed.join("seed.db"), dir.path().join("migration.db"))?;
    let conn = new_connection(dir.path(), "migration.db").await?;
    let qualified = qualification_factory(name)?;
    let session = LinkedSession::new(conn.clone(), qualified(conn.clone()).await?);
    let mut request = prepare(&session).await?;
    let service = OwnerService::new();
    let result = async {
        let before = comparable_state(&conn, &request, 2).await?;
        let selected = select_legacy_p1(&conn, NETWORK, ApplicationPosition::Migration {
            anchor_height: 1, anchor_hash: request.anchor_hash,
        }).await?;
        let production = LinkedSession::new(conn.clone(), production(conn.clone()).await?);
        let error = apply(&service, &production, &selected, NETWORK, &request).await.unwrap_err();
        ensure!(error.downcast_ref::<MigrationRejected>() == Some(&MigrationRejected::UnknownDefinition), "production accepted a test migration");
        ensure!(comparable_state(&conn, &request, 2).await? == before, "production rejection changed state");
        request.definition = migration_definition::qualification(session.executor.execution_definition?, true);
        let error = apply(&service, &session, &selected, NETWORK, &request).await.unwrap_err();
        ensure!(error.downcast_ref::<MigrationRejected>() == Some(&MigrationRejected::Budget), "expected migration budget rejection");
        ensure!(comparable_state(&conn, &request, 2).await? == before, "exhaustion changed state");
        request.definition = migration_definition::qualification(session.executor.execution_definition?, false);
        let receipt = apply(&service, &session, &selected, NETWORK, &request).await?;
        ensure!(receipt.work.write_operations > 0, "qualification performed no writes");
        ensure!(canonical_history::surviving_migration_result(&conn, receipt.application.migration_key()?).await? == Some(receipt.clone()), "migration receipt was not stored");
        let after = comparable_state(&conn, &request, 3).await?;
        ensure!(before["contract_state"] != after["contract_state"] && before["checkpoints"] != after["checkpoints"], "migration effects/checkpoint absent");
        let selected = select_legacy_p1(&conn, NETWORK, ApplicationPosition::Migration { anchor_height: 1, anchor_hash: request.anchor_hash }).await?;
        let all_tables = full_state(&conn).await?;
        ensure!(apply(&service, &session, &selected, NETWORK, &request).await? == receipt, "migration retry result differs");
        ensure!(full_state(&conn).await? == all_tables, "migration retry changed persistent state");
        ensure!(conn.is_autocommit() && service.active_roots().await == 0 && !service.is_fatal(), "migration retained ownership");
        Ok(json!({"before":before,"after":after,"work":receipt.work.values(),"journal_records":3,"retry":"unchanged","production_registry":"rejects-test-routine"}))
    }.await;
    service.shutdown();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migration_qualification_compares_full_state_and_validates_journal() -> Result<()> {
        let first_seed = seed().await?;
        let second_seed = seed().await?;
        let factory = session_factory(NETWORK, None)?;
        let first = qualify_graph("in-tree", first_seed.path(), factory.clone()).await?;
        let second = qualify_graph("in-tree", second_seed.path(), factory).await?;
        assert_eq!(first, second);
        Ok(())
    }
}
