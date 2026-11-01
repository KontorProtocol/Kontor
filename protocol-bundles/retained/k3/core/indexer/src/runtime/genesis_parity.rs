use std::collections::BTreeMap;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{Context, Result, bail};
use bitcoin::Network;
use indexer_types::BlockRow;
use libsql::{Connection, Value, params};
use serde_json::{Value as Json, json};
use tempfile::TempDir;

use super::numerics::decimal_to_string;
use super::ownership::OwnerService;
use super::pool::LinkedSession;
use super::{ComponentCache, Decimal, GenesisParameters, GenesisValidator, Runtime, Storage};
use crate::built_info::GIT_COMMIT_HASH;
use crate::database::canonical_history::{self, HistoryState};
use crate::database::connection::new_connection;
use crate::database::queries::insert_block;
use crate::protocol::coordinator::genesis::bind_identity;
use crate::protocol::coordinator::linked;
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::runtime::ownership::adapter::HostFailure;
use crate::test_utils::new_mock_block_hash;

async fn logical_state(conn: &Connection) -> Result<Json> {
    let mut names = conn
        .query(
            "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name",
            (),
        )
        .await?;
    let mut result = BTreeMap::new();
    while let Some(table) = names.next().await? {
        let name: String = table.get(0)?;
        let quoted = name.replace('"', "\"\"");
        let mut rows = conn
            .query(&format!("SELECT * FROM \"{quoted}\""), ())
            .await?;
        let columns = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            let mut fields = Vec::new();
            for column in 0..columns {
                fields.push(match row.get_value(column)? {
                    Value::Null => json!(["null"]),
                    Value::Integer(value) => json!(["integer", value]),
                    Value::Real(value) => json!(["real_bits", value.to_bits()]),
                    Value::Text(value) => json!(["text", value]),
                    Value::Blob(value) => json!(["blob", hex::encode(value)]),
                });
            }
            values.push(serde_json::to_string(&fields)?);
        }
        values.sort();
        result.insert(name, values);
    }
    Ok(serde_json::to_value(result)?)
}

#[tokio::test]
#[ignore = "writes fresh genesis evidence for comparison across two node revisions"]
async fn fresh_native_genesis_report() -> Result<()> {
    let output = env::var("KONTOR_NATIVE_GENESIS_REPORT").context("set report output path")?;
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "genesis.db").await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(0)
            .hash(new_mock_block_hash(0))
            .relevant(true)
            .build(),
    )
    .await?;
    // The receipt-stream epoch is node-local metadata. Both revisions receive
    // this identical input so every table can be compared without exclusions.
    conn.execute(
        "UPDATE receipt_stream_state SET epoch = ?",
        params!["a".repeat(64)],
    )
    .await?;
    let mut runtime = Runtime::new(
        ComponentCache::new(),
        Storage::builder().height(0).conn(conn.clone()).build(),
    )
    .await?;
    runtime.network = Network::Regtest;
    let genesis = GenesisParameters {
        sigma_min: Decimal::from("1"),
        validators: vec![GenesisValidator {
            x_only_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .into(),
            ed25519_pubkey: vec![1; 32],
            stake: Decimal::from("100"),
        }],
    };
    runtime
        .publish_native_contracts_owned(&genesis, &OwnerService::new())
        .await?;
    assert_eq!(runtime.id_generation_counter.get().await, 0);
    let report = json!({"source": GIT_COMMIT_HASH.context("missing node source revision")?, "state": logical_state(&conn).await?});
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?
        .write_all(&serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

#[tokio::test]
async fn linked_initializer_preserves_native_genesis_and_resume() -> Result<()> {
    let engine = Runtime::new_engine()?;
    let linkers = Runtime::new_linkers(&engine)?;
    let cache = ComponentCache::new();
    for network in [Network::Regtest, Network::Bitcoin] {
        let genesis = GenesisParameters {
            sigma_min: Decimal::from("1.25"),
            validators: vec![GenesisValidator {
                x_only_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    .into(),
                ed25519_pubkey: vec![1; 32],
                stake: Decimal::from("100.123456789"),
            }],
        };
        let envelope = (
            decimal_to_string(genesis.sigma_min),
            genesis
                .validators
                .iter()
                .map(|v| {
                    (
                        v.x_only_pubkey.clone(),
                        decimal_to_string(v.stake),
                        v.ed25519_pubkey.clone(),
                    )
                })
                .collect(),
        );
        let directory = TempDir::new()?;
        let mut states = Vec::new();
        for (filename, linked) in [("baseline.db", false), ("linked.db", true)] {
            let conn = new_connection(directory.path(), filename).await?;
            if linked {
                bind_identity(&conn, network, 1, &envelope).await?;
            }
            insert_block(
                &conn,
                BlockRow::builder()
                    .height(0)
                    .hash(new_mock_block_hash(0))
                    .relevant(true)
                    .build(),
            )
            .await?;
            conn.execute(
                "UPDATE receipt_stream_state SET epoch = ?",
                params!["a".repeat(64)],
            )
            .await?;
            let mut runtime = Runtime::new_with(
                engine.clone(),
                linkers.clone(),
                cache.clone(),
                Storage::builder().height(0).conn(conn.clone()).build(),
            )
            .await?;
            runtime.network = network;
            let service = OwnerService::new();
            let mut expected_stages = Vec::new();
            if linked {
                let session = LinkedSession::new(conn.clone(), linked::link_runtime(runtime, true));
                let before = logical_state(&conn).await?;
                let steps = (session.executor.operations.initialize)(
                    session.executor.owner.clone(),
                    envelope.clone(),
                )
                .map_err(HostFailure::from)?;
                expected_stages = steps.iter().map(|(commit, _)| *commit).collect();
                let mut steps = steps.into_iter();
                let _first = steps.next().context("missing prepare step")?;
                let (_, second) = steps.next().context("missing first publication")?;
                let selection = select_legacy_p1(
                    &conn,
                    network,
                    ApplicationPosition::Initialization { step: 1 },
                )
                .await?;
                let lease =
                    linked::begin_canonical_unit(&service, &session, &selection, network, false)
                        .await?;
                let result = second(session.executor.owner.clone(), selection.envelope())
                    .await
                    .map_err(HostFailure::from)
                    .map_err(Into::into);
                let error = linked::finish_canonical_unit(lease, result, false)
                    .await
                    .unwrap_err();
                assert!(format!("{error:#}").contains("initialization steps are out of order"));
                assert_eq!(logical_state(&conn).await?, before);
                linked::initialize(&service, &session, network, 1, envelope.clone()).await?;
                let fresh = logical_state(&conn).await?;
                linked::initialize(&service, &session, network, 1, envelope.clone()).await?;
                assert_eq!(
                    logical_state(&conn).await?,
                    fresh,
                    "restart changed genesis"
                );
            } else {
                runtime
                    .publish_native_contracts_owned(&genesis, &service)
                    .await?;
            }
            assert!(conn.is_autocommit());
            assert_eq!(service.active_roots().await, 0);
            let mut state = logical_state(&conn).await?;
            if linked {
                let HistoryState::Ready(cursor) = canonical_history::state(&conn).await? else {
                    bail!("linked genesis did not bind its chain");
                };
                assert!(cursor.ordinal > 0 && cursor.authentic);
                assert_eq!(
                    state["canonical_applications"].as_array().unwrap().len(),
                    cursor.ordinal as usize
                );
                assert_eq!(
                    state["genesis_applications"].as_array().unwrap().len(),
                    cursor.ordinal as usize
                );
                assert_eq!(
                    cursor.ordinal as usize,
                    expected_stages.iter().filter(|commit| **commit).count()
                );
                for (stage, commits) in expected_stages.iter().enumerate() {
                    assert_eq!(
                        canonical_history::genesis_stage_applied(&conn, stage as u32).await?,
                        *commits
                    );
                }
            } else {
                assert_eq!(
                    canonical_history::state(&conn).await?,
                    HistoryState::PendingGenesis
                );
                assert_eq!(state["canonical_applications"], json!([]));
                assert_eq!(state["genesis_applications"], json!([]));
            }
            assert_eq!(state["migration_applications"], json!([]));
            // Runtime parity compares every execution table. The new coordinator
            // journal is checked above because the legacy initializer lacks it.
            for name in [
                "canonical_history_state",
                "canonical_applications",
                "genesis_applications",
                "migration_applications",
            ] {
                state.as_object_mut().unwrap().remove(name).unwrap();
            }
            states.push(state);
        }
        assert_eq!(states[0], states[1], "native genesis differs on {network}");
    }
    Ok(())
}
