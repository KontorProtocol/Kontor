use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use libsql::{Builder, Connection, OpenFlags, params};

use super::native_bootstrap::bootstrap_reader;
use super::{Reader, Writer};
use crate::protocol::coordinator::genesis::InitialProtocol;
use crate::protocol::coordinator::selection::ExecutorVersion;
use crate::protocol::v1::native::{NATIVE_CONTRACTS, NATIVE_PROVENANCE, native_provenance};
use crate::protocol::v1::native_bootstrap;
use crate::protocol::v1::storage_identity::CORE_SIGNER_ID;

/// Validate existing genesis before opening connections that initialize or migrate
/// schema. Rejected databases remain available for an explicit legacy definition.
pub async fn open_node_database(
    data_dir: &Path,
    filename: &str,
    network: Network,
) -> Result<(Reader, Writer)> {
    let definition = InitialProtocol::for_network(network);
    preflight(&data_dir.join(filename), &definition)
        .await
        .with_context(|| {
            format!(
                "unsupported genesis for {} / {:?} / {}; database was not initialized or migrated",
                definition.network, definition.executor, definition.native_genesis
            )
        })?;
    let writer = Writer::new(data_dir, filename).await?;
    let reader = Reader::new(data_dir, filename).await?;
    Ok((reader, writer))
}

async fn preflight(path: &Path, definition: &InitialProtocol) -> Result<()> {
    match definition.executor {
        ExecutorVersion::LegacyP1 => {
            native_provenance()?;
        }
    }
    if !path.try_exists()? {
        return Ok(());
    }
    let db = Builder::new_local(path)
        .flags(OpenFlags::SQLITE_OPEN_READ_ONLY)
        .build()
        .await?;
    let conn = db.connect()?;
    // Pin all reads to one snapshot, including the publication prefix and its
    // original provenance. Never use the normal connection initializer here.
    conn.execute("BEGIN", ()).await?;
    validate_existing(&conn).await
}

async fn validate_existing(conn: &Connection) -> Result<()> {
    let mut tables = BTreeSet::new();
    let mut rows = conn
        .query(
            "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            (),
        )
        .await?;
    while let Some(row) = rows.next().await? {
        tables.insert(row.get::<String>(0)?);
    }
    if tables.is_empty() {
        return Ok(());
    }
    for name in [
        "contracts",
        "contract_provenance",
        "signers",
        "blocks",
        "transactions",
        "batches",
        "contract_results",
        "contract_state",
    ] {
        ensure!(tables.contains(name), "missing genesis table: {name}");
    }
    let count = NATIVE_CONTRACTS.len() as i64;
    let mut rows = conn
        .query(
            "SELECT c.id, c.name, c.height, c.tx_index, c.size, c.bytes, c.signer_id,
                p.author_signer_id, p.height, p.tx_index, p.provenance, s.height
         FROM contracts c
         LEFT JOIN contract_provenance p ON p.id =
             (SELECT MIN(id) FROM contract_provenance WHERE contract_id = c.id)
         LEFT JOIN signers s ON s.id = c.signer_id
         WHERE c.id <= ? OR c.height = 0 ORDER BY c.id",
            params![count],
        )
        .await?;
    let mut published = 0;
    while let Some(row) = rows.next().await? {
        ensure!(
            published < NATIVE_CONTRACTS.len(),
            "unexpected contract at genesis"
        );
        let (name, bytes) = NATIVE_CONTRACTS[published];
        let id = published as i64 + 1;
        ensure!(
            row.get::<i64>(0)? == id && row.get::<String>(1)? == name,
            "native publication prefix mismatch at {id}"
        );
        ensure!(
            row.get::<i64>(2)? == 0 && row.get::<i64>(3)? == 0,
            "native contract address mismatch at {id}"
        );
        ensure!(
            row.get::<i64>(4)? == bytes.len() as i64 && row.get::<Vec<u8>>(5)? == bytes,
            "native artifact mismatch at {id}"
        );
        let signer_id = row.get::<i64>(6)?;
        ensure!(
            signer_id == id + 1 && row.get::<i64>(11)? == 0,
            "native signer mismatch at {id}"
        );
        ensure!(
            row.get::<i64>(7)? == CORE_SIGNER_ID as i64
                && row.get::<i64>(8)? == 0
                && row.get::<i64>(9)? == 0,
            "native publisher or provenance position mismatch at {id}"
        );
        ensure!(
            row.get::<Vec<u8>>(10)? == NATIVE_PROVENANCE,
            "original native provenance mismatch at {id}"
        );
        published += 1;
    }
    let first_signer = conn
        .query("SELECT id, height FROM signers ORDER BY id LIMIT 1", ())
        .await?
        .next()
        .await?;
    if let Some(row) = first_signer {
        ensure!(
            row.get::<i64>(0)? == CORE_SIGNER_ID as i64 && row.get::<i64>(1)? == 0,
            "genesis core signer mismatch"
        );
    } else {
        ensure!(published == 0, "missing genesis core signer");
    }
    if published < NATIVE_CONTRACTS.len() {
        let row = conn
            .query(
                "SELECT EXISTS(SELECT 1 FROM contracts WHERE id > ?)
                 OR EXISTS(SELECT 1 FROM blocks WHERE height > 0)
                 OR EXISTS(SELECT 1 FROM transactions)
                 OR EXISTS(SELECT 1 FROM batches)
                 OR EXISTS(SELECT 1 FROM signers WHERE id > ?)
                 OR (SELECT COUNT(*) FROM contract_provenance) != ?",
                params![count, published as i64 + 1, published as i64],
            )
            .await?
            .next()
            .await?
            .context("missing prefix validation result")?;
        ensure!(
            row.get::<i64>(0)? == 0,
            "incomplete native set with later or conflicting state"
        );
    }
    let progress = native_bootstrap::read_progress(bootstrap_reader(conn)).await?;
    if !progress.admission_floor_initialized {
        let row = conn.query("SELECT EXISTS(SELECT 1 FROM blocks WHERE height > 0) OR EXISTS(SELECT 1 FROM batches) OR EXISTS(SELECT 1 FROM transactions)", ()).await?.next().await?.context("missing bootstrap position")?;
        ensure!(
            row.get::<i64>(0)? == 0,
            "later state before genesis admission floor"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use indexer_types::BlockRow;
    use stdlib::{KeyElement, KeyPath};
    use tempfile::TempDir;

    use super::*;
    use crate::database::canonical_history::{self, HistoryState};
    use crate::database::init::CREATE_SCHEMA;
    use crate::database::queries::insert_block;
    use crate::reg_tester::random_x_only_pubkey;
    use crate::runtime::ownership::OwnerService;
    use crate::runtime::wit::Signer;
    use crate::runtime::{
        Decimal, GenesisValidator, Runtime, Storage, TransactionContext, staking,
    };
    use crate::test_utils::{new_mock_block_hash, test_genesis, test_runtime};

    async fn fixture(count: usize) -> Result<(TempDir, Connection)> {
        let dir = TempDir::new()?;
        let db = Builder::new_local(dir.path().join("state.db"))
            .build()
            .await?;
        let conn = db.connect()?;
        // Negative cases deliberately construct inconsistent legacy databases.
        conn.execute("PRAGMA foreign_keys = OFF", ()).await?;
        conn.execute_batch(CREATE_SCHEMA).await?;
        conn.execute("INSERT INTO blocks VALUES (0, 'genesis', 1)", ())
            .await?;
        conn.execute("INSERT INTO signers VALUES (1, 0)", ())
            .await?;
        for (index, (name, bytes)) in NATIVE_CONTRACTS.iter().take(count).enumerate() {
            let id = index as i64 + 1;
            conn.execute("INSERT INTO signers VALUES (?, 0)", params![id + 1])
                .await?;
            conn.execute(
                "INSERT INTO contracts VALUES (?, ?, 0, 0, ?, ?, ?)",
                params![id, *name, bytes.len() as i64, *bytes, id + 1],
            )
            .await?;
            conn.execute(
                "INSERT INTO contract_provenance VALUES (?, ?, 1, 0, 0, ?)",
                params![id, id, NATIVE_PROVENANCE],
            )
            .await?;
            conn.execute("INSERT INTO contract_results (contract_id,func,height,tx_id,input_index,op_index,result_index,gas,size,value,signer_id,payer_signer_id,status) VALUES (?, 'init', 0, NULL, 0, 0, ?, 0, 0, NULL, 1, 1, 'Ok')", params![id, index as i64]).await?;
        }
        if count >= 3 {
            for (field, value) in [
                (0, postcard::to_allocvec(&Decimal::default().encode())?),
                (4, postcard::to_allocvec(&false)?),
            ] {
                conn.execute("INSERT INTO contract_state (contract_id,height,tx_id,size,path,value,deleted) VALUES (3, 0, NULL, ?, ?, ?, 0)", params![value.len() as i64, KeyPath::new().push_interned(field).as_bytes(), value]).await?;
            }
        }
        Ok((dir, conn))
    }

    async fn snapshot(conn: &Connection) -> Result<BTreeMap<String, Vec<String>>> {
        let mut result = BTreeMap::new();
        let mut tables = conn
            .query(
                "SELECT name, sql FROM sqlite_schema WHERE type = 'table' ORDER BY name",
                (),
            )
            .await?;
        while let Some(table) = tables.next().await? {
            let name: String = table.get(0)?;
            let definition: String = table.get(1)?;
            let quoted = name.replace('"', "\"\"");
            let mut rows = conn
                .query(&format!("SELECT * FROM \"{quoted}\""), ())
                .await?;
            let columns = rows.column_count();
            let mut values = Vec::new();
            while let Some(row) = rows.next().await? {
                let fields = (0..columns)
                    .map(|column| row.get_value(column))
                    .collect::<Result<Vec<_>, _>>()?;
                values.push(format!("{fields:?}"));
            }
            values.sort();
            result.insert(format!("{name}: {definition}"), values);
        }
        Ok(result)
    }

    #[tokio::test]
    async fn empty_database_and_all_valid_publication_prefixes_open() -> Result<()> {
        let dir = TempDir::new()?;
        open_node_database(dir.path(), "empty.db", Network::Regtest).await?;
        for count in 0..=NATIVE_CONTRACTS.len() {
            let (dir, conn) = fixture(count).await?;
            open_node_database(dir.path(), "state.db", Network::Regtest).await?;
            let mut rows = conn
                .query("SELECT provenance FROM contract_provenance", ())
                .await?;
            while let Some(row) = rows.next().await? {
                assert_eq!(row.get::<Vec<u8>>(0)?, NATIVE_PROVENANCE);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn unsupported_genesis_is_rejected_before_any_schema_or_state_change() -> Result<()> {
        for mutation in [
            "UPDATE contracts SET bytes = x'01' WHERE id = 1",
            "UPDATE contracts SET name = 'other' WHERE id = 2",
            "UPDATE contracts SET tx_index = 1 WHERE id = 3",
            "DELETE FROM contracts WHERE id = 2",
            "DELETE FROM contract_provenance WHERE contract_id = 1",
            "UPDATE contract_provenance SET provenance = x'01' WHERE contract_id = 1",
            "UPDATE contract_provenance SET author_signer_id = 2 WHERE contract_id = 1",
            "UPDATE contracts SET signer_id = 1 WHERE id = 1",
            "UPDATE contracts SET signer_id = 2 WHERE id = 2",
            "INSERT INTO signers VALUES (99, 0); UPDATE contracts SET signer_id = 99 WHERE id = 1",
            "UPDATE signers SET height = 1 WHERE id = 1",
            "DROP TABLE contract_provenance",
            "UPDATE contract_results SET result_index = 0 WHERE id = 2",
            "UPDATE contract_results SET result_index = -1 WHERE id = 1",
            "UPDATE contract_results SET result_index = 4294967296 WHERE id = 1",
            "UPDATE contract_results SET input_index = NULL WHERE id = 1",
            "UPDATE contract_results SET op_index = 1 WHERE id = 1",
            "UPDATE contract_results SET signer_id = 2 WHERE id = 1",
            "UPDATE contract_results SET payer_signer_id = NULL WHERE id = 1",
            "UPDATE contract_results SET status = 'Trap' WHERE id = 1",
            "UPDATE contract_results SET func = 'set-genesis-set' WHERE id = 3",
            "DELETE FROM contract_results WHERE id = 2",
            "UPDATE contract_state SET value = x'01' WHERE contract_id = 3 AND path = x'0604'",
            "UPDATE contract_state SET value = x'0000' WHERE contract_id = 3 AND path = x'0604'",
            "UPDATE contract_state SET value = CAST(value || x'ff' AS BLOB) WHERE contract_id = 3 AND path = x'0600'",
        ] {
            let (dir, conn) = fixture(5).await?;
            conn.execute_batch(mutation).await?;
            let before = snapshot(&conn).await?;
            let error = open_node_database(dir.path(), "state.db", Network::Regtest)
                .await
                .err()
                .context("unsupported genesis accepted")?;
            assert!(
                error.to_string().contains("unsupported genesis"),
                "{error:#}"
            );
            assert_eq!(snapshot(&conn).await?, before, "mutation: {mutation}");
            assert!(!dir.path().join("crypto.so").exists());
            assert!(!dir.path().join("crypto.dylib").exists());
        }
        Ok(())
    }

    #[tokio::test]
    async fn incomplete_native_set_with_later_state_is_rejected() -> Result<()> {
        for mutation in [
            "INSERT INTO blocks VALUES (1, 'later', 1)",
            "INSERT INTO contracts VALUES (6, 'later', 1, 0, 1, x'01', NULL)",
            "INSERT INTO contract_provenance VALUES (10, 1, 1, 0, 0, x'01')",
        ] {
            let (dir, conn) = fixture(2).await?;
            conn.execute_batch(mutation).await?;
            let before = snapshot(&conn).await?;
            assert!(
                open_node_database(dir.path(), "state.db", Network::Regtest)
                    .await
                    .is_err()
            );
            assert_eq!(snapshot(&conn).await?, before);
        }
        Ok(())
    }

    #[tokio::test]
    async fn later_provenance_cannot_mask_a_different_original() -> Result<()> {
        let (dir, conn) = fixture(5).await?;
        conn.execute(
            "UPDATE contract_provenance SET provenance = x'01' WHERE contract_id = 1",
            (),
        )
        .await?;
        conn.execute(
            "INSERT INTO contract_provenance VALUES (10, 1, 1, 0, 0, ?)",
            params![NATIVE_PROVENANCE],
        )
        .await?;
        let before = snapshot(&conn).await?;
        assert!(
            open_node_database(dir.path(), "state.db", Network::Regtest)
                .await
                .is_err()
        );
        assert_eq!(snapshot(&conn).await?, before);
        Ok(())
    }

    #[tokio::test]
    async fn real_native_publication_reopens_without_rewriting_provenance() -> Result<()> {
        let (runtime, dir, filename) = test_runtime().await?;
        let conn = runtime.get_storage_conn();
        conn.execute("INSERT INTO contract_provenance (contract_id, author_signer_id, height, tx_index, provenance) VALUES (1, 1, 0, 0, x'01')", ()).await?;
        let before = snapshot(&conn).await?;
        open_node_database(dir.path(), &filename, Network::Regtest).await?;
        assert_eq!(snapshot(&conn).await?, before);
        Ok(())
    }

    async fn empty_runtime(warm: &Runtime, dir: &Path) -> Result<Runtime> {
        let (_, writer) = open_node_database(dir, "state.db", Network::Regtest).await?;
        let conn = writer.connection();
        insert_block(
            &conn,
            BlockRow::builder()
                .height(0)
                .hash(new_mock_block_hash(0))
                .relevant(true)
                .build(),
        )
        .await?;
        // A receipt-stream epoch is node-local random metadata. Seed it identically
        // before execution so the comparison can include every logical table.
        conn.execute(
            "UPDATE receipt_stream_state SET epoch = ?",
            params!["a".repeat(64)],
        )
        .await?;
        // Direct publication here intentionally predates the coordinator's
        // journal. Reopening must preserve this same unavailable-history state.
        canonical_history::initialize(&conn).await?;
        assert_eq!(
            canonical_history::state(&conn).await?,
            HistoryState::Unavailable
        );
        runtime_on(warm, conn).await
    }

    async fn runtime_on(warm: &Runtime, conn: Connection) -> Result<Runtime> {
        let mut runtime = Runtime::new_with(
            warm.engine.clone(),
            warm.linkers.clone(),
            warm.component_cache.clone(),
            Storage::builder().height(0).conn(conn).build(),
        )
        .await?;
        runtime.network = Network::Regtest;
        Ok(runtime)
    }

    #[tokio::test]
    async fn interrupted_native_publication_resumes_to_the_same_state() -> Result<()> {
        let (warm, _warm_dir, _) = test_runtime().await?;
        let genesis = test_genesis(&[GenesisValidator {
            x_only_pubkey: random_x_only_pubkey(),
            ed25519_pubkey: vec![1; 32],
            stake: Decimal::from("100"),
        }]);
        let complete_dir = TempDir::new()?;
        let mut complete = empty_runtime(&warm, complete_dir.path()).await?;
        complete
            .publish_native_contracts_owned(&genesis, &OwnerService::new())
            .await?;
        assert_eq!(complete.id_generation_counter.get().await, 0);
        let expected = snapshot(&complete.get_storage_conn()).await?;

        for stage in [2, 5, 6, 7] {
            let interrupted_dir = TempDir::new()?;
            let mut interrupted = empty_runtime(&warm, interrupted_dir.path()).await?;
            interrupted
                .set_context(0, Some(TransactionContext::builder().build()), None, None)
                .await;
            interrupted.storage.create_core_signer().await?;
            let service = OwnerService::new();
            let core = Signer::Core(Box::new(Signer::Nobody));
            for (name, bytes) in NATIVE_CONTRACTS.iter().take(stage.min(5)) {
                let mut lease = service.begin_canonical(&mut interrupted, false).await?;
                interrupted.storage.savepoint().await?;
                interrupted
                    .publish(
                        &core,
                        interrupted.core_payment(),
                        name,
                        bytes,
                        &native_provenance()?,
                    )
                    .await?;
                lease.drain(&interrupted).await?;
                interrupted.storage.commit().await?;
                lease.complete(&mut interrupted).await?;
            }
            if stage >= 6 {
                let mut lease = service.begin_canonical(&mut interrupted, false).await?;
                interrupted.storage.savepoint().await?;
                staking::api::set_sigma_min(&mut interrupted, &core, genesis.sigma_min).await??;
                lease.drain(&interrupted).await?;
                interrupted.storage.commit().await?;
                lease.complete(&mut interrupted).await?;
            }
            if stage >= 7 {
                let mut lease = service.begin_canonical(&mut interrupted, false).await?;
                interrupted.storage.savepoint().await?;
                staking::api::set_genesis_set(
                    &mut interrupted,
                    &core,
                    genesis.validators.iter().cloned().map(Into::into).collect(),
                )
                .await?;
                lease.drain(&interrupted).await?;
                interrupted.storage.commit().await?;
                lease.complete(&mut interrupted).await?;
            }
            assert_eq!(interrupted.id_generation_counter.get().await, 0);
            drop(interrupted);
            for restart in 0..2 {
                let (_, writer) =
                    open_node_database(interrupted_dir.path(), "state.db", Network::Regtest)
                        .await?;
                let mut resumed = runtime_on(&warm, writer.connection()).await?;
                resumed
                    .publish_native_contracts_owned(&genesis, &OwnerService::new())
                    .await?;
                assert_eq!(resumed.id_generation_counter.get().await, 0);
                let actual = snapshot(&resumed.get_storage_conn()).await?;
                let different: Vec<_> = expected
                    .keys()
                    .filter(|key| expected.get(*key) != actual.get(*key))
                    .collect();
                assert!(
                    different.is_empty(),
                    "interrupted genesis differs after stage {stage}, restart {restart}, tables: {different:?}"
                );
                assert_eq!(actual.len(), expected.len());
            }
        }
        Ok(())
    }
}
