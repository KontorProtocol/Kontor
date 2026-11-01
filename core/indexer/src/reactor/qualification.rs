//! Replay a preserved pre-extraction oracle through the actual linked coordinator.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::slice;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Block as BitcoinBlock, Network, Transaction, Witness};
use libsql::{Connection, Value};
use malachitebft_engine::node::NodeRef;
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use super::engine::EngineConfig;
use super::executor::{Executor, RuntimeExecutor};
use super::mempool_fee_index::MempoolFeeIndex;
use super::{PruneConfig, Reactor, start_linked_consensus};
use crate::bitcoin_client::Client;
use crate::bitcoin_follower::block::BlockInput;
use crate::bitcoin_helpers::new_mock_block_hash;
use crate::consensus::Height;
use crate::consensus::signing::PrivateKey;
use crate::database::connection::new_connection;
use crate::protocol::coordinator::selection::ApplicationPosition;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::LinkedSession;
use crate::stopper::Shutdown;

#[derive(Deserialize)]
struct Inputs {
    source: String,
    database_sha256: String,
    transaction_sha256: String,
}

#[derive(Deserialize, Serialize)]
struct Report {
    source: String,
    states: BTreeMap<String, Json>,
}

struct StopEngine(NodeRef);
impl Drop for StopEngine {
    fn drop(&mut self) {
        self.0.stop(None);
    }
}

fn checksum(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn raw_confirmation_block(tx: &Transaction, position: usize) -> Result<BlockInput> {
    assert!(position >= 2);
    let mut raw = genesis_block(Network::Regtest);
    raw.header.prev_blockhash = new_mock_block_hash(1);
    for index in 1..position {
        let mut unrelated = tx.clone();
        unrelated.input[0].witness = Witness::new();
        unrelated.lock_time = LockTime::from_consensus(index as u32);
        raw.txdata.push(unrelated);
    }
    raw.txdata.push(tx.clone());
    raw.header.merkle_root = raw.compute_merkle_root().context("fixture merkle root")?;
    let raw: BitcoinBlock = deserialize(&serialize(&raw))?;
    assert!(raw.txdata[0].is_coinbase());
    assert!(raw.check_merkle_root());
    let hash = raw.block_hash();
    Ok(BlockInput::new(
        2,
        hash,
        raw.header.prev_blockhash,
        raw.txdata,
    ))
}

async fn state(conn: &Connection) -> Result<Json> {
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
        let count = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            let mut fields = Vec::new();
            for column in 0..count {
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

async fn scenario(
    path: &Path,
    batched: bool,
    report: &mut Report,
    factory: SessionFactory,
    service: &OwnerService,
) -> Result<()> {
    let label = if batched { "batched" } else { "unbatched" };
    let dir = TempDir::new()?;
    fs::copy(path.join("seed.db"), dir.path().join("replay.db"))?;
    let conn = new_connection(dir.path(), "replay.db").await?;
    let session = LinkedSession::new(conn.clone(), factory(conn.clone()).await?);
    let raw: Transaction = deserialize(&fs::read(path.join("transaction.bin"))?)?;
    let consensus = start_linked_consensus(
        EngineConfig {
            private_key: PrivateKey::from([17; 32]),
            listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
            persistent_peers: Vec::new(),
            data_dir: dir.path().to_path_buf(),
            consensus_enabled: false,
            discovery: Default::default(),
        },
        &session,
        service,
        Network::Regtest,
        None,
        None,
        1,
        MempoolFeeIndex::new(None),
    )
    .await?;
    let shutdown = Shutdown::new();
    let (_block_tx, block_rx) = mpsc::channel(1);
    let (_mempool_tx, mempool_rx) = mpsc::channel(1);
    let (addr_tx, _addr_rx) = watch::channel(None);
    // These scenarios supply raw blocks directly and must not require Bitcoin RPC.
    let client = Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?;
    let mut reactor = Reactor::from_session(
        RuntimeExecutor::new(client),
        session,
        Network::Regtest,
        service.clone(),
        block_rx,
        mempool_rx,
        shutdown.signal(),
        None,
        None,
        None,
        consensus,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        1,
        Some(new_mock_block_hash(1)),
        addr_tx,
    );
    let cleanup = StopEngine(reactor.consensus.engine_handle.actor.clone());
    let result = async {
        let initial = state(&conn).await?;
        report
            .states
            .insert(format!("{label}/initial"), initial.clone());
        let selection = reactor.preparation_selection().await?;
        let recognized = reactor.recognizer.recognize(&selection, serialize(&raw))?
            .map_err(anyhow::Error::msg)?.context("recognized signed fixture")?;
        report.states.insert(format!("{label}/recognition"),
            json!({"index":recognized.index,"txid":recognized.txid.to_string(),"inputs":recognized.inputs}));
        let mut unrelated = raw.clone();
        unrelated.input[0].witness.clear();
        ensure!(reactor.simulate_raw(serialize(&unrelated)).await?.is_err());
        ensure!(
            state(&conn).await? == initial,
            "unrecognized input changed persisted state"
        );
        let simulated = reactor
            .simulate_raw(serialize(&raw))
            .await?
            .map_err(anyhow::Error::msg)
            .context("recognized simulation")?;
        report.states.insert(
            format!("{label}/simulation"),
            serde_json::to_value(simulated)?,
        );
        ensure!(
            state(&conn).await? == initial,
            "simulation changed persisted state"
        );

        if batched {
            reactor
                .process_decided_batch(
                    1,
                    new_mock_block_hash(1),
                    Height::new(1),
                    &[],
                    slice::from_ref(&raw),
                    None,
                )
                .await?;
            report
                .states
                .insert(format!("{label}/executed"), state(&conn).await?);
        }
        let block = reactor
            .executor
            .prepare_block(
                &reactor.recognizer,
                &reactor.preparation_selection().await?,
                raw_confirmation_block(&raw, 2)?,
            )
            .await?;
        let (count, ops, errors) = reactor
            .execute_block_unit(
                &reactor
                    .select_executor(ApplicationPosition::Block {
                        height: block.height,
                        hash: block.hash,
                        consensus_height: 0,
                    })
                    .await?,
                &block,
            )
            .await?;
        ensure!(count == usize::from(!batched) && ops == u64::from(!batched));
        ensure!(errors.iter().flatten().flatten().all(Option::is_none));
        report
            .states
            .insert(format!("{label}/confirmed"), state(&conn).await?);

        if batched {
            reactor.rollback(1).await?;
            report
                .states
                .insert(format!("{label}/rollback"), state(&conn).await?);
            let replacement = reactor
                .executor
                .prepare_block(
                    &reactor.recognizer,
                    &reactor.preparation_selection().await?,
                    raw_confirmation_block(&raw, 4)?,
                )
                .await?;
            let (count, ops, _) = reactor
                .execute_block_unit(
                    &reactor
                        .select_executor(ApplicationPosition::Block {
                            height: replacement.height,
                            hash: replacement.hash,
                            consensus_height: 0,
                        })
                        .await?,
                    &replacement,
                )
                .await?;
            ensure!(
                (count, ops) == (0, 0),
                "reconfirmation executed or charged again"
            );
            report
                .states
                .insert(format!("{label}/reconfirmed"), state(&conn).await?);
        }
        Ok(())
    }
    .await;
    cleanup.0.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut reactor.consensus.engine_handle.handle,
    )
    .await??;
    ensure!(conn.is_autocommit(), "baseline retained SQL transaction");
    ensure!(
        service.active_roots().await == 0,
        "baseline retained owner roots"
    );
    result
}

pub(crate) async fn compare(
    path: &Path,
    factory: SessionFactory,
    service: &OwnerService,
) -> Result<Json> {
    let inputs_bytes = fs::read(path.join("inputs.json"))?;
    let inputs: Inputs = serde_json::from_slice(&inputs_bytes)?;
    let baseline_bytes = fs::read(path.join("baseline.json"))?;
    let mut expected: Report = serde_json::from_slice(&baseline_bytes)?;
    ensure!(
        expected.source == inputs.source,
        "baseline and inputs source disagree"
    );
    ensure!(
        checksum(&fs::read(path.join("seed.db"))?) == inputs.database_sha256,
        "seed checksum mismatch"
    );
    ensure!(
        checksum(&fs::read(path.join("transaction.bin"))?) == inputs.transaction_sha256,
        "transaction checksum mismatch"
    );
    // Parsed instructions are opaque across graph boundaries. Compare exported
    // routing metadata here; full operation inspection is compared in simulation.
    for label in ["batched", "unbatched"] {
        let value = expected
            .states
            .get_mut(&format!("{label}/recognition"))
            .context("missing recognition baseline")?;
        let inputs = value["inputs"]
            .as_array()
            .context("baseline inputs")?
            .iter()
            .map(|input| {
                Ok(json!([
                    input["input_index"].as_u64().context("input index")?,
                    input["insts"]["ops"]
                        .as_array()
                        .context("baseline operations")?
                        .len()
                ]))
            })
            .collect::<Result<Vec<_>>>()?;
        *value = json!({"index": value["index"], "txid":value["txid"], "inputs":inputs});
    }
    let mut actual = Report {
        source: "linked-candidate".into(),
        states: BTreeMap::new(),
    };
    scenario(path, false, &mut actual, factory.clone(), service).await?;
    scenario(path, true, &mut actual, factory, service).await?;
    ensure!(
        actual.states.keys().eq(expected.states.keys()),
        "baseline stage set changed"
    );
    for (stage, value) in &actual.states {
        ensure!(
            Some(value) == expected.states.get(stage),
            "pre-extraction execution differs at {stage}"
        );
    }
    Ok(
        json!({"baseline_source":inputs.source,"baseline_sha256":checksum(&baseline_bytes),
        "inputs_sha256":checksum(&inputs_bytes),"database_sha256":inputs.database_sha256,
        "transaction_sha256":inputs.transaction_sha256,"states":actual.states}),
    )
}
