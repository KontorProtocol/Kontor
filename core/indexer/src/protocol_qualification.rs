//! Bounded execution checks using the same adapters as the production node.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use bitcoin::{BlockHash, Network, hashes::Hash};
use indexer_types::{Block, BlockRow};
use libsql::{Connection, Value as SqlValue};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::config::DEFAULT_VIEW_GAS_LIMIT;
use crate::consensus::signing::PrivateKey;
use crate::database::connection::new_connection;
use crate::database::queries::insert_block;
#[cfg(kontor_linked)]
use crate::protocol::coordinator::linked::retained_session_factory;
#[cfg(not(kontor_linked))]
use crate::protocol::coordinator::linked::session_factory;
use crate::protocol::coordinator::linked::{
    begin_canonical_unit, derive_committee, execute_view, finish_canonical_unit, initialize,
    run_block_lifecycle,
};
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::protocol::operations::{AddressEnvelope, GenesisEnvelope, SessionOwner};
use crate::reactor::qualification;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::{LinkedSession, new_linked};

mod transactions;

const NETWORK: Network = Network::Regtest;
type Factories = (&'static str, SessionFactory, SessionFactory);

fn factories() -> Result<Vec<Factories>> {
    #[cfg(kontor_linked)]
    {
        Ok(vec![
            (
                "first",
                retained_session_factory(NETWORK, None, kontor_executor_first::factory)?,
                retained_session_factory(
                    NETWORK,
                    Some(DEFAULT_VIEW_GAS_LIMIT),
                    kontor_executor_first::factory,
                )?,
            ),
            (
                "second",
                retained_session_factory(NETWORK, None, kontor_executor_second::factory)?,
                retained_session_factory(
                    NETWORK,
                    Some(DEFAULT_VIEW_GAS_LIMIT),
                    kontor_executor_second::factory,
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

fn genesis() -> GenesisEnvelope {
    (
        "1".into(),
        vec![(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            "100.9999999".into(),
            PrivateKey::from([7; 32]).public_key().as_bytes().to_vec(),
        )],
    )
}

// Hash typed, length-delimited values rather than database file bytes, which
// include SQLite allocation and WAL details unrelated to execution semantics.
async fn state(conn: &Connection) -> Result<BTreeMap<String, (u64, String)>> {
    let mut state = BTreeMap::new();
    for table in [
        "blocks",
        "contracts",
        "contract_provenance",
        "contract_state",
        "current_contract_state",
        "transactions",
        "contract_results",
        "depositor_footprint",
        "block_execution_usage",
        "transaction_execution_usage",
        "signers",
        "x_only_pubkeys",
        "bls_keys",
        "nonces",
    ] {
        let order = if table == "current_contract_state" {
            "contract_id, path"
        } else {
            "rowid"
        };
        let mut rows = conn
            .query(&format!("SELECT * FROM {table} ORDER BY {order}"), ())
            .await?;
        let mut digest = Sha256::new();
        let mut count = 0;
        while let Some(row) = rows.next().await? {
            digest.update(rows.column_count().to_le_bytes());
            for i in 0..rows.column_count() {
                let (tag, bytes) = match row.get_value(i)? {
                    SqlValue::Null => (0u8, Vec::new()),
                    SqlValue::Integer(n) => (1, n.to_le_bytes().to_vec()),
                    SqlValue::Real(n) => (2, n.to_bits().to_le_bytes().to_vec()),
                    SqlValue::Text(s) => (3, s.into_bytes()),
                    SqlValue::Blob(b) => (4, b),
                };
                digest.update([tag]);
                digest.update((bytes.len() as u64).to_le_bytes());
                digest.update(bytes);
            }
            count += 1;
        }
        state.insert(table.into(), (count, hex::encode(digest.finalize())));
    }
    Ok(state)
}

async fn exercise(
    service: &OwnerService,
    canonical: SessionFactory,
    read: SessionFactory,
) -> Result<Value> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "qualification.db").await?;
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
    initialize(service, &session, NETWORK, genesis()).await?;
    let initialized = state(&conn).await?;
    ensure!(
        initialized["contracts"].0 == 5,
        "native genesis did not publish all contracts"
    );
    ensure!(
        initialized["contract_provenance"].0 == 5,
        "native provenance missing"
    );
    initialize(service, &session, NETWORK, genesis()).await?;
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
    Ok(
        json!({"genesis": initialized, "active_set": active_set, "missing_function": missing,
        "committee": committee, "malformed_transaction": malformed, "lifecycle": lifecycle, "transactions": transactions}),
    )
}

pub async fn run() -> Result<Value> {
    let factories = factories()?;
    let service = OwnerService::new();
    let mut outputs: Vec<Value> = Vec::new();
    let result = async {
        for (name, canonical, read) in factories {
            eprintln!("Qualifying actual executor: {name}");
            let observations = exercise(&service, canonical, read).await.with_context(|| name)?;
            if let Some(previous) = outputs.first() {
                ensure!(observations == previous["observations"], "retained executor outcomes differ");
            }
            outputs.push(json!({"graph": name, "observations": observations}));
        }
        Ok(json!({"schema": 1, "cases": ["native-genesis", "genesis-resume", "read-only-views",
            "committee", "malformed-recognition", "lifecycle-rollback-replay", "opaque-session-rejection", "transaction-recognition", "publication", "fees-and-deposits",
            "deterministic-failures", "simulation-inspection", "transaction-rollback-replay"],
            "executors": outputs}))
    }.await;
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
