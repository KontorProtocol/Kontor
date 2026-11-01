//! Bounded execution checks using the same adapters as the production node.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use bitcoin::{BlockHash, hashes::Hash};
use indexer_types::{Block, BlockRow};
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::config::DEFAULT_VIEW_GAS_LIMIT;
use crate::database::connection::new_connection;
use crate::database::queries::insert_block;
use crate::protocol::coordinator::genesis::bind_identity;
#[cfg(kontor_linked)]
use crate::protocol::coordinator::linked::retained_session_factory;
#[cfg(not(kontor_linked))]
use crate::protocol::coordinator::linked::session_factory;
use crate::protocol::coordinator::linked::{
    begin_canonical_unit, derive_committee, execute_view, finish_canonical_unit, initialize,
    run_block_lifecycle,
};
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::protocol::operations::{AddressEnvelope, SessionOwner};
use crate::reactor::qualification;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::{LinkedSession, new_linked};

pub(crate) mod fixture;
mod migration;
#[cfg(kontor_linked)]
mod ownership;
pub(crate) mod snapshot;
#[cfg(kontor_linked)]
mod storage_contract;
mod transactions;

use fixture::{NETWORK, genesis, state};

type Factories = (&'static str, SessionFactory, SessionFactory);

fn factories() -> Result<Vec<Factories>> {
    #[cfg(kontor_linked)]
    {
        Ok(vec![
            (
                "first",
                retained_session_factory(
                    NETWORK,
                    None,
                    kontor_executor_first::factory,
                    kontor_executor_first::execution_definition(),
                )?,
                retained_session_factory(
                    NETWORK,
                    Some(DEFAULT_VIEW_GAS_LIMIT),
                    kontor_executor_first::factory,
                    kontor_executor_first::execution_definition(),
                )?,
            ),
            (
                "second",
                retained_session_factory(
                    NETWORK,
                    None,
                    kontor_executor_second::factory,
                    kontor_executor_second::execution_definition(),
                )?,
                retained_session_factory(
                    NETWORK,
                    Some(DEFAULT_VIEW_GAS_LIMIT),
                    kontor_executor_second::factory,
                    kontor_executor_second::execution_definition(),
                )?,
            ),
        ])
    }
    #[cfg(not(kontor_linked))]
    {
        Ok(vec![(
            "in-tree",
            session_factory(NETWORK, None)?,
            session_factory(NETWORK, Some(DEFAULT_VIEW_GAS_LIMIT))?,
        )])
    }
}

async fn exercise(
    _name: &str,
    service: &OwnerService,
    canonical: SessionFactory,
    read: SessionFactory,
) -> Result<Value> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "qualification.db").await?;
    bind_identity(&conn, NETWORK, 1, &genesis()).await?;
    for height in 0..=1 {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(BlockHash::from_byte_array([height as u8; 32]))
                .relevant(true)
                .build(),
        )
        .await?;
    }
    let session = LinkedSession::new(conn.clone(), canonical(conn.clone()).await?);
    initialize(service, &session, NETWORK, 1, genesis()).await?;
    let initialized = state(&conn).await?;
    ensure!(
        initialized["contracts"].0 == 5,
        "native genesis did not publish all contracts"
    );
    ensure!(
        initialized["contract_provenance"].0 == 5,
        "native provenance missing"
    );
    initialize(service, &session, NETWORK, 1, genesis()).await?;
    ensure!(
        state(&conn).await? == initialized,
        "resumed genesis changed persisted state"
    );

    let pool = new_linked(dir.path().to_path_buf(), "qualification.db".into(), read, 1)?;
    let address: AddressEnvelope = ("staking".into(), 0, 0);
    let active_set = execute_view(
        service,
        pool.get().await?,
        NETWORK,
        address.clone(),
        "get-active-set()".into(),
    )
    .await?;
    ensure!(
        active_set.is_ok(),
        "real staking view failed: {active_set:?}"
    );
    let missing = execute_view(
        service,
        pool.get().await?,
        NETWORK,
        address,
        "missing-function()".into(),
    )
    .await?;
    ensure!(
        matches!(missing, Err((true, _))),
        "missing function lost deterministic error classification"
    );
    let object = pool.get().await?;
    ensure!(
        object.conn.is_autocommit(),
        "view retained a SQL transaction"
    );
    ensure!(
        object
            .conn
            .execute("CREATE TABLE forbidden (id INTEGER)", ())
            .await
            .is_err(),
        "view connection acquired write authority"
    );
    drop(object);
    ensure!(
        state(&conn).await? == initialized,
        "view modified canonical state"
    );

    let selection = select_legacy_p1(&conn, NETWORK, ApplicationPosition::Committee).await?;
    ensure!(
        derive_committee(&session, &selection, NETWORK)
            .await
            .is_err(),
        "committee export bypassed owner admission"
    );
    let lease = begin_canonical_unit(service, &session, &selection, NETWORK, false).await?;
    let committee = derive_committee(&session, &selection, NETWORK).await;
    let committee = finish_canonical_unit(lease, committee, false).await?;
    ensure!(committee.validators.len() == 1, "genesis committee missing");

    let block = Block {
        height: 2,
        hash: BlockHash::from_byte_array([2; 32]),
        prev_hash: BlockHash::from_byte_array([1; 32]),
        transactions: Vec::new(),
    };
    let selection = select_legacy_p1(
        &conn,
        NETWORK,
        ApplicationPosition::Block {
            height: 2,
            hash: block.hash,
            consensus_height: 2,
        },
    )
    .await?;
    let malformed = (session.executor.operations.recognize)(selection.envelope(), vec![0xff])
        .map_err(|(code, message)| anyhow::anyhow!("recognition host error {code}: {message}"))?;
    ensure!(malformed.is_err(), "malformed transaction was accepted");
    let malformed = malformed
        .err()
        .context("missing malformed transaction error")?;
    let mut lifecycle = None;
    for commit in [false, true] {
        let lease = begin_canonical_unit(service, &session, &selection, NETWORK, false).await?;
        let result = async {
            insert_block(
                &conn,
                BlockRow::builder().height(2).hash(block.hash).build(),
            )
            .await?;
            run_block_lifecycle(&session, &selection, NETWORK, &block).await?;
            state(&conn).await
        }
        .await;
        let observed = finish_canonical_unit(lease, result, commit).await?;
        if let Some(previous) = &lifecycle {
            ensure!(
                previous == &observed,
                "replay after rollback changed lifecycle results"
            );
        } else {
            ensure!(
                observed != initialized,
                "lifecycle produced no persisted effects"
            );
            lifecycle = Some(observed.clone());
        }
        ensure!(
            state(&conn).await?
                == if commit {
                    observed
                } else {
                    initialized.clone()
                },
            "lifecycle settlement did not respect commit policy"
        );
        ensure!(
            conn.is_autocommit(),
            "canonical operation retained a SQL transaction"
        );
        ensure!(service.active_roots().await == 0, "owner root leaked");
    }
    let transactions = transactions::run(service, &session).await?;
    let address: AddressEnvelope = ("counter".into(), 3, 7);
    for (expression, expected) in [("get()", "2"), ("get-blob()", "\"\"")] {
        let result = execute_view(
            service,
            pool.get().await?,
            NETWORK,
            address.clone(),
            expression.into(),
        )
        .await?;
        ensure!(
            result == Ok(expected.into()),
            "committed counter state differs: {result:?}"
        );
    }
    // These are real graph-owned opaque sessions, not node-owned nominal wrappers.
    let foreign: SessionOwner = Arc::new(());
    ensure!(
        (session.executor.operations.initialize)(foreign, genesis()).is_err(),
        "executor accepted an unrelated opaque session"
    );
    #[cfg(kontor_linked)]
    let ownership = ownership::qualify_graph(_name, dir.path(), &conn).await?;
    #[cfg(not(kontor_linked))]
    let ownership = json!({});
    Ok(
        json!({"genesis": initialized, "active_set": active_set, "missing_function": missing,
        "committee": committee, "malformed_transaction": malformed, "lifecycle": lifecycle, "transactions": transactions,
        "ownership": ownership}),
    )
}

pub async fn run() -> Result<Value> {
    #[cfg(kontor_linked)]
    let storage_contracts = storage_contract::qualify()?;
    #[cfg(not(kontor_linked))]
    let storage_contracts = json!({});
    let factories = factories()?;
    let service = OwnerService::new();
    let mut outputs: Vec<Value> = Vec::new();
    let result = async {
        let migration_seed = migration::seed().await?;
        for (name, canonical, read) in factories {
            eprintln!("Qualifying actual executor: {name}");
            let migration =
                migration::qualify_graph(name, migration_seed.path(), canonical.clone()).await?;
            let mut observations = exercise(name, &service, canonical, read)
                .await
                .with_context(|| name)?;
            observations["migration"] = migration;
            if let Some(previous) = outputs.first() {
                ensure!(
                    observations == previous["observations"],
                    "retained executor outcomes differ"
                );
            }
            outputs.push(json!({"graph": name, "observations": observations}));
        }
        #[cfg(kontor_linked)]
        let node_capacity = ownership::qualify_node_capacity(&service).await?;
        #[cfg(not(kontor_linked))]
        let node_capacity = json!({});
        #[cfg(kontor_linked)]
        let export_panics = ownership::qualify_export_panics().await?;
        #[cfg(not(kontor_linked))]
        let export_panics = json!({});
        let cases = vec![
            "atomic-migration-and-retry",
            "migration-input-snapshot-and-work",
            "production-migration-registry-isolation",
            "native-genesis",
            "genesis-resume",
            "read-only-views",
            "committee",
            "malformed-recognition",
            "lifecycle-rollback-replay",
            "opaque-session-rejection",
            "transaction-recognition",
            "publication",
            "fees-and-deposits",
            "deterministic-failures",
            "simulation-inspection",
            "transaction-rollback-replay",
        ];
        #[cfg(kontor_linked)]
        let cases = {
            let mut cases = cases;
            cases.extend([
                "pending-host-callback-cancellation",
                "host-callback-failure-panic",
                "held-cursor-cancellation",
                "node-wide-capacity-shutdown",
                "export-panic-classification",
                "required-storage-contract-before-construction",
            ]);
            cases
        };
        Ok(json!({"schema": 1, "cases": cases, "executors": outputs,
            "node_capacity": node_capacity, "export_panics": export_panics,
            "storage_contracts": storage_contracts}))
    }
    .await;
    service.shutdown();
    result
}

pub async fn compare_baseline(archive: &Path) -> Result<Value> {
    let service = OwnerService::new();
    let result = async {
        let mut outputs = Vec::new();
        for (name, factory, _) in factories()? {
            eprintln!("Comparing actual executor with pre-extraction baseline: {name}");
            let observations = qualification::compare(archive, factory, &service)
                .await
                .context(name)?;
            outputs.push(json!({"graph":name,"observations":observations}));
        }
        Ok(json!({"schema":1,"executors":outputs}))
    }
    .await;
    service.shutdown();
    result
}
