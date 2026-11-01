//! Replay a preserved pre-extraction oracle through the linked execution adapters.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::slice;

use anyhow::{Context, Result, ensure};
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Block as BitcoinBlock, Network, Transaction, Witness};
use libsql::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::PruneConfig;
use super::execution::ExecutionContext;
use super::executor::{Executor, RuntimeExecutor};
use crate::bitcoin_client::Client;
use crate::bitcoin_follower::block::BlockInput;
use crate::bitcoin_helpers::new_mock_block_hash;
use crate::consensus::Height;
use crate::database::canonical_history::{self, HistoryState};
use crate::database::connection::new_connection;
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::coordinator::linked::TransactionRecognizer;
use crate::protocol::coordinator::selection::ApplicationPosition;
use crate::protocol::identity::{ChainId, ProtocolId};
use crate::protocol_qualification::snapshot::full_state;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::LinkedSession;

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
    Ok(BlockInput::from_bitcoin(2, hash, raw))
}

async fn state(conn: &Connection) -> Result<Json> {
    // The archived oracle predates these tables. Its original state is preserved;
    // it cannot acquire authentic history merely by opening it in a newer node.
    ensure!(
        canonical_history::state(conn).await? == HistoryState::Unavailable,
        "legacy oracle unexpectedly acquired canonical lineage"
    );
    let mut snapshot = full_state(conn).await?;
    let tables = snapshot
        .as_object_mut()
        .context("SQL snapshot is not an object")?;
    for name in [
        "canonical_applications",
        "migration_applications",
        "genesis_applications",
    ] {
        ensure!(
            tables.get(name) == Some(&json!([])),
            "legacy oracle gained journal entries: {name}"
        );
        tables.remove(name);
    }
    ensure!(
        tables.remove("canonical_history_state").is_some(),
        "history status table missing"
    );
    Ok(snapshot)
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
    ensure!(canonical_history::state(&conn).await? == HistoryState::Unavailable);
    let client = Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?;
    // This context is never persisted or used for certification. The archive has
    // execution state only, so consensus and certified recovery must not start.
    let mut execution = ExecutionContext::new(
        RuntimeExecutor::new(client),
        session,
        Network::Regtest,
        service.clone(),
        EraContext {
            chain: ChainId([0; 32]),
            era: [0; 32],
            protocol: ProtocolId([0; 32]),
            codec: 1,
        },
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        1,
        Some(new_mock_block_hash(1)),
    );
    let result = async {
        let initial = state(&conn).await?;
        report
            .states
            .insert(format!("{label}/initial"), initial.clone());
        let selection = execution.select_executor(ApplicationPosition::Preparation { anchor_height: 1, anchor_hash: Some(new_mock_block_hash(1)) }).await?;
        let recognized = execution.recognizer.recognize(&selection, serialize(&raw))?
            .map_err(anyhow::Error::msg)?.context("recognized signed fixture")?;
        report.states.insert(format!("{label}/recognition"),
            json!({"index":recognized.index,"txid":recognized.txid.to_string(),"inputs":recognized.inputs}));
        let mut unrelated = raw.clone();
        unrelated.input[0].witness.clear();
        ensure!(execution.simulate_raw(serialize(&unrelated)).await?.is_err());
        ensure!(
            state(&conn).await? == initial,
            "unrecognized input changed persisted state"
        );
        let simulated = execution
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
            execution
                .execute_legacy_batch_unit(
                    1,
                    new_mock_block_hash(1),
                    Height::new(1),
                    slice::from_ref(&raw),
                )
                .await?;
            report
                .states
                .insert(format!("{label}/executed"), state(&conn).await?);
        }
        let block = execution.executor
            .prepare_block(
                &execution.recognizer,
                &execution.select_executor(ApplicationPosition::Preparation { anchor_height: 1, anchor_hash: Some(new_mock_block_hash(1)) }).await?,
                raw_confirmation_block(&raw, 2)?,
            )
            .await?;
        let (count, ops, errors) = execution.execute_block_unit(
                &execution
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
            execution.maintain_executor(Some(1)).await?;
            execution.recognizer = TransactionRecognizer::new(
                execution.session.origin(), execution.network,
                execution.session.executor.operations.recognize.clone(),
            );
            report
                .states
                .insert(format!("{label}/rollback"), state(&conn).await?);
            let replacement = execution.executor
                .prepare_block(
                    &execution.recognizer,
                    &execution.select_executor(ApplicationPosition::Preparation { anchor_height: 1, anchor_hash: Some(new_mock_block_hash(1)) }).await?,
                    raw_confirmation_block(&raw, 4)?,
                )
                .await?;
            let (count, ops, _) = execution.execute_block_unit(
                    &execution
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
