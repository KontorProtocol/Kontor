use std::collections::BTreeMap;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{Context, Result};
use bitcoin::Network;
use indexer_types::BlockRow;
use libsql::{Connection, Value, params};
use serde_json::{Value as Json, json};
use tempfile::TempDir;

use super::ownership::OwnerService;
use super::{ComponentCache, Decimal, GenesisParameters, GenesisValidator, Runtime, Storage};
use crate::built_info::GIT_COMMIT_HASH;
use crate::database::connection::new_connection;
use crate::database::queries::insert_block;
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
