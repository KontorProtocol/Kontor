use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    Address, Block as BitcoinBlock, BlockHash, Network, OutPoint, Psbt, Transaction, TxOut,
};
use indexer_types::{
    Block, BuildProvenance, CommitId, CommitSource, ContractAddress, Forge, Inst, InstKind, Insts,
    OpStatus, Platform, ResultRow, Reveal, RevealOutput, RevealParticipant, Source,
};
use libsql::{Connection, Value as SqlValue, params};
use malachitebft_engine::node::NodeRef;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use super::{Snapshot, hash_file};
use crate::api::compose::compose;
use crate::bitcoin_client::Client;
use crate::bitcoin_client::client::RegtestRpc;
use crate::block::filter_map;
use crate::bls::taproot_derivation_path;
use crate::built_info::GIT_COMMIT_HASH;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Height, Value};
use crate::database::Writer;
use crate::database::queries::{
    PRUNE_WATERMARK_KEY, get_identity, get_meta_u64, get_results_paginated,
    select_latest_consensus_height,
};
use crate::database::types::{OrderDirection, ResultQuery};
use crate::reactor::consensus_state::DeferredDecision;
use crate::reactor::engine::EngineConfig;
use crate::reactor::executor::RuntimeExecutor;
use crate::reactor::mempool_fee_index::MempoolFeeIndex;
use crate::reactor::{PruneConfig, Reactor, create_runtime_executor, start_consensus};
use crate::reg_tester::{WorkloadBitcoin, derive_taproot_keypair_from_seed, workload_bitcoin};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ComponentCache, Decimal, GenesisParameters, GenesisValidator, Runtime, Storage,
    TransactionContext, from_wave_expr,
};
use crate::stopper::Shutdown;
use crate::test_utils::{participant_tap_script, sign_key_spend, sign_script_spend};

mod accounting;
mod capture;
mod diagnostic;
mod frozen;
mod populated;
mod report;

use accounting::Balances;

const START_HEIGHT: u64 = 93;
const ANCHOR_HEIGHT: u64 = 101;
const SMOKE_HEIGHT: u64 = 102;
const PRUNE_RETAIN: u64 = 6;
const GAS_LIMIT: u64 = 100_000;
const FUNDING_SEED: [u8; 64] = [41; 64];

struct BitcoinProcess(WorkloadBitcoin);

#[derive(Default)]
struct EngineCleanup(Vec<NodeRef>);

impl Drop for EngineCleanup {
    fn drop(&mut self) {
        for actor in &self.0 {
            actor.stop(None);
        }
    }
}

async fn stop_engine(reactor: &mut Reactor<RuntimeExecutor>) -> Result<()> {
    reactor.consensus.engine_handle.actor.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut reactor.consensus.engine_handle.handle,
    )
    .await
    .context("test consensus teardown timed out")??;
    Ok(())
}

fn test_provenance() -> Result<BuildProvenance> {
    let build: JsonValue = serde_json::from_str(include_str!(
        "../../../../../test-contracts/binaries/build.json"
    ))?;
    let mut commit = [0; 20];
    hex::decode_to_slice(
        GIT_COMMIT_HASH.context("missing source revision")?,
        &mut commit,
    )?;
    Ok(BuildProvenance {
        source: Source {
            forge: Forge::GitHub,
            owner: "KontorProtocol".into(),
            repo: "Kontor".into(),
            commit: CommitId::Sha1(commit),
        },
        image: build["image"]
            .as_str()
            .context("missing build image")?
            .into(),
        platform: Platform::parse(
            build["platform"]
                .as_str()
                .context("missing build platform")?,
        )?,
    })
}

fn decode_block(raw: &[u8], height: u64, hash: BlockHash, parent: BlockHash) -> Result<Block> {
    let block: BitcoinBlock = deserialize(raw)?;
    ensure!(block.block_hash() == hash, "block hash differs");
    ensure!(
        block.header.prev_blockhash == parent,
        "block parent differs"
    );
    ensure!(block.check_merkle_root(), "invalid transaction merkle root");
    ensure!(
        block.check_witness_commitment(),
        "invalid witness commitment"
    );
    ensure!(
        block.txdata.first().is_some_and(Transaction::is_coinbase),
        "missing coinbase"
    );
    Ok(Block {
        height,
        hash,
        prev_hash: parent,
        // Enumerate before filtering, as the production poller does.
        transactions: block
            .txdata
            .into_iter()
            .enumerate()
            .filter_map(filter_map)
            .collect(),
    })
}

async fn reactor(
    mut runtime: Runtime,
    client: Client,
    directory: &Path,
    height: u64,
    hash: Option<BlockHash>,
    prune: bool,
    cleanup: &mut EngineCleanup,
) -> Result<Reactor<RuntimeExecutor>> {
    let consensus = start_consensus(
        EngineConfig {
            private_key: PrivateKey::from([17; 32]),
            listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
            persistent_peers: Vec::new(),
            data_dir: directory.to_path_buf(),
            consensus_enabled: false,
            discovery: Default::default(),
        },
        &mut runtime,
        None,
        None,
        height,
        MempoolFeeIndex::new(None),
    )
    .await?;
    cleanup.0.push(consensus.engine_handle.actor.clone());
    let (_, blocks) = mpsc::channel(1);
    let (_, mempool) = mpsc::channel(1);
    let (address, _) = watch::channel(None);
    let mut reactor = Reactor::new(
        RuntimeExecutor::new(client),
        runtime,
        blocks,
        mempool,
        Shutdown::new().signal(),
        None,
        None,
        None,
        consensus,
        PruneConfig {
            enabled: prune,
            retain_blocks: PRUNE_RETAIN,
        },
        height,
        hash,
        address,
    );
    reactor.prune_watermark = get_meta_u64(&reactor.db_conn(), PRUNE_WATERMARK_KEY, 0).await?;
    Ok(reactor)
}

async fn apply(reactor: &mut Reactor<RuntimeExecutor>, block: Block) -> Result<()> {
    let next = select_latest_consensus_height(&reactor.db_conn())
        .await?
        .unwrap_or(0)
        .checked_add(1)
        .context("consensus height overflow")?;
    let decision = DeferredDecision {
        consensus_height: Height::new(next),
        value: Value::new_block(block.height, block.hash),
        certificate: Vec::new(),
        certified_txs: None,
    };
    reactor.handle_block(block, &decision).await
}

async fn signed_smoke(
    client: &Client,
    key: &Keypair,
    funding: (OutPoint, TxOut),
    addresses: &[ContractAddress; 2],
) -> Result<(Transaction, Transaction, JsonValue)> {
    let ops = [
        (0, "write-result-payload(1)"),
        (1, "scan-compound(false)"),
        (0, "write-result-payload(2)"),
    ]
    .into_iter()
    .map(|(index, expr)| Inst {
        gas_limit: GAS_LIMIT,
        kind: InstKind::Call {
            contract: addresses[index].clone(),
            expr: expr.into(),
        },
    })
    .collect();
    signed_instructions(client, key, funding, ops).await
}

async fn signed_instructions(
    client: &Client,
    key: &Keypair,
    funding: (OutPoint, TxOut),
    ops: Vec<Inst>,
) -> Result<(Transaction, Transaction, JsonValue)> {
    let (commit, reveal, record) = checked_signed_instructions(client, key, funding, ops).await?;
    for transaction in [&commit, &reveal] {
        client
            .send_raw_transaction(&hex::encode(serialize(transaction)))
            .await?;
    }
    Ok((commit, reveal, record))
}

async fn checked_signed_instructions(
    client: &Client,
    key: &Keypair,
    funding: (OutPoint, TxOut),
    ops: Vec<Inst>,
) -> Result<(Transaction, Transaction, JsonValue)> {
    ensure!(!ops.is_empty(), "workload reveal must contain operations");
    let secp = Secp256k1::new();
    let public_key = key.x_only_public_key().0;
    let address = Address::p2tr(&secp, public_key, None, Network::Regtest);
    let request = Reveal {
        sat_per_vbyte: Some(2),
        participants: vec![RevealParticipant {
            x_only_public_key: public_key.to_string(),
            commit_insts: Insts {
                ops,
                aggregate: None,
            },
            output: Some(RevealOutput::Change {
                script_pubkey: hex::encode(address.script_pubkey().as_bytes()),
            }),
            commit_source: CommitSource::build_resolved(&address, [funding.clone()]),
        }],
        extra_inputs: Vec::new(),
        extra_outputs: Vec::new(),
    };
    let (commits, reveal) = compose(request, Network::Regtest, client).await?;
    ensure!(commits.len() == 1, "expected one commit");
    let mut commit = commits[0].transaction.clone();
    let mut transaction = reveal.transaction.clone();
    sign_key_spend(&secp, &mut commit, &[funding.1], key, 0, None)?;
    let psbt = Psbt::deserialize(&hex::decode(&reveal.psbt_hex)?)?;
    let (script, _) = participant_tap_script(&psbt.inputs[0])?;
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())?
        .finalize(&secp, public_key)
        .map_err(|e| anyhow!("taproot finalize: {e:?}"))?;
    sign_script_spend(
        &secp,
        &spend,
        &script,
        &mut transaction,
        &[commit.output[0].clone()],
        key,
        0,
    )?;
    let raw = [
        hex::encode(serialize(&commit)),
        hex::encode(serialize(&transaction)),
    ];
    let verdicts = client.test_mempool_accept(&raw).await?;
    ensure!(
        verdicts.len() == 2 && verdicts.iter().all(|v| v.allowed),
        "bitcoind rejected smoke: {verdicts:?}"
    );
    let record = json!(
        verdicts
            .iter()
            .map(|verdict| json!({
                "txid":verdict.txid,"wtxid":verdict.wtxid,"allowed":verdict.allowed,
                "reject_reason":verdict.reject_reason,"vsize":verdict.vsize,
                "base_fee_sats":verdict.fees.as_ref().map(|fees| fees.base.to_sat()),
            }))
            .collect::<Vec<_>>()
    );
    Ok((commit, transaction, record))
}

async fn receipts(conn: &Connection, height: u64) -> Result<Vec<ResultRow>> {
    let mut result = Vec::new();
    let mut cursor = None;
    loop {
        let (rows, _) = get_results_paginated(
            conn,
            ResultQuery {
                cursor,
                offset: None,
                limit: Some(1000),
                count: false,
                order: OrderDirection::Asc,
                height: Some(height),
                start_height: None,
                contract: None,
                func: None,
                signer_id: None,
            },
        )
        .await?;
        if rows.is_empty() {
            break;
        }
        cursor = rows.last().map(|r| r.id);
        result.extend(rows.into_iter().map(ResultRow::from));
    }
    let count: u64 = conn
        .query(
            "SELECT count(*) FROM contract_results WHERE height = ?",
            params![height],
        )
        .await?
        .next()
        .await?
        .context("receipt count")?
        .get(0)?;
    ensure!(count == result.len() as u64, "public receipt join hid rows");
    Ok(result)
}

async fn database_projection(conn: &Connection) -> Result<JsonValue> {
    let mut tables = conn.query(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name", ()
    ).await?;
    let mut result = Vec::new();
    while let Some(table) = tables.next().await? {
        let name: String = table.get(0)?;
        let quoted = name.replace('"', "\"\"");
        let mut rows = conn
            .query(&format!("SELECT * FROM \"{quoted}\""), ())
            .await?;
        let count = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            let mut columns = Vec::new();
            for i in 0..count {
                columns.push(match row.get_value(i)? {
                    SqlValue::Null => JsonValue::Null,
                    SqlValue::Integer(v) => json!(v),
                    SqlValue::Text(v) => json!(v),
                    SqlValue::Blob(v) => json!({"blob": hex::encode(v)}),
                    SqlValue::Real(_) => {
                        return Err(anyhow!("unexpected floating-point database value"));
                    }
                });
            }
            values.push(serde_json::to_string(&columns)?);
        }
        values.sort();
        result.push(json!({"table":name,"rows":values}));
    }
    Ok(json!(result))
}

async fn retained_version(conn: &Connection, contract: u64, path: &[u8]) -> Result<Vec<SqlValue>> {
    let mut rows = conn
        .query(
            "SELECT height, value, deleted, depositor, deposited_gas FROM contract_state
         WHERE contract_id = ? AND path = ? AND height <= 95 ORDER BY height DESC LIMIT 1",
            params![contract, path],
        )
        .await?;
    let row = rows.next().await?.context("missing retained successor")?;
    (0..5)
        .map(|i| row.get_value(i).map_err(Into::into))
        .collect()
}

async fn state(runtime: &mut Runtime, address: &ContractAddress) -> Result<Vec<u64>> {
    Ok(from_wave_expr(
        &runtime
            .execute_system_view(address, "storage-state()")
            .await?,
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; development fixture generation, not frozen acceptance"]
async fn workload_real_block_smoke() -> Result<()> {
    let source = capture::source()?;
    let bitcoin_dir = TempDir::new()?;
    let (child, client) = workload_bitcoin(bitcoin_dir.path()).await?;
    let mut bitcoin = BitcoinProcess(child);
    let key = derive_taproot_keypair_from_seed(
        &FUNDING_SEED,
        &taproot_derivation_path(Network::Regtest),
    )?;
    let public_key = key.x_only_public_key().0;
    let address = Address::p2tr(&Secp256k1::new(), public_key, None, Network::Regtest);
    let mined = client
        .generate_to_address(ANCHOR_HEIGHT, &address.to_string())
        .await?;
    let funding_block = client.get_block(&BlockHash::from_str(&mined[0])?).await?;
    let funding = (
        OutPoint {
            txid: funding_block.txdata[0].compute_txid(),
            vout: 0,
        },
        funding_block.txdata[0].output[0].clone(),
    );
    let anchor = BlockHash::from_str(mined.last().context("no mined anchor")?)?;
    let directory = TempDir::new()?;
    let writer = Writer::new(directory.path(), "source.db").await?;
    let genesis = GenesisParameters {
        sigma_min: Decimal::from("1"),
        validators: vec![GenesisValidator {
            x_only_pubkey: public_key.to_string(),
            ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
            stake: Decimal::from("100"),
        }],
    };
    let (_, mut runtime, last_height, last_hash) = create_runtime_executor(
        START_HEIGHT,
        &writer,
        client.clone(),
        None,
        &genesis,
        Network::Regtest,
    )
    .await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    token::issue_to(
        &mut runtime,
        &core,
        HolderRef::XOnlyPubkey(public_key.to_string()),
        Decimal::from("100"),
    )
    .await??;
    let addresses = ["smokea", "smokeb"].map(|name| ContractAddress {
        name: name.into(),
        height: 0,
        tx_index: 1,
    });
    runtime
        .set_context(
            0,
            Some(TransactionContext::builder().tx_index(1).build()),
            None,
            None,
        )
        .await;
    for address in &addresses {
        runtime
            .publish(
                &core,
                runtime.core_payment(),
                &address.name,
                include_bytes!("../../../../../test-contracts/binaries/error_test.wasm.br"),
                &test_provenance()?,
            )
            .await?;
        ensure!(state(&mut runtime, address).await? == [0, 0, 0, 0]);
    }
    let mut engine_cleanup = EngineCleanup::default();
    let history_engine_dir = TempDir::new_in(directory.path())?;
    let mut history = reactor(
        runtime,
        client.clone(),
        history_engine_dir.path(),
        last_height,
        last_hash,
        false,
        &mut engine_cleanup,
    )
    .await?;
    for height in START_HEIGHT..=ANCHOR_HEIGHT {
        let hash = client.get_block_hash(height).await?;
        let block = client.get_block(&hash).await?;
        apply(
            &mut history,
            decode_block(
                &serialize(&block),
                height,
                hash,
                block.header.prev_blockhash,
            )?,
        )
        .await?;
    }
    let conn = history.db_conn();
    let payer_id = get_identity(&conn, &public_key.to_string())
        .await?
        .context("missing funded payer identity")?
        .signer_id();
    let balances_before = Balances::capture(&mut history.runtime, &public_key.to_string()).await?;
    let before = database_projection(&conn).await?;
    let (old_id, old_path, old_height) = {
        let mut rows = conn.query(
            "SELECT s.contract_id, s.path, s.height FROM contract_state s WHERE s.height BETWEEN 93 AND 94
             AND EXISTS (SELECT 1 FROM contract_state n WHERE n.contract_id = s.contract_id AND n.path = s.path
             AND n.height > s.height AND n.height <= 95) ORDER BY s.contract_id, s.path, s.height LIMIT 1", ()
        ).await?;
        let old = rows
            .next()
            .await?
            .context("history has no useful pruning candidate")?;
        (
            old.get::<u64>(0)?,
            old.get::<Vec<u8>>(1)?,
            old.get::<u64>(2)?,
        )
    };
    let retained = retained_version(&conn, old_id, &old_path).await?;
    let next_consensus_height = select_latest_consensus_height(&conn)
        .await?
        .unwrap_or(0)
        .checked_add(1)
        .context("consensus height overflow")?;
    let (schema, schema_sha256) = capture::schema(&conn).await?;
    let reporter = report::Reporter {
        payer: public_key.to_string(),
        addresses: addresses.clone(),
        prune_contract: old_id,
        prune_path: old_path.clone(),
    };
    let before_report = reporter
        .capture(&mut history.runtime, ANCHOR_HEIGHT, anchor, &[])
        .await?;
    let snapshot = Snapshot::export(&conn, &directory.path().join("frozen.db")).await?;
    stop_engine(&mut history).await?;
    let (commit, reveal, mempool_verdicts) =
        signed_smoke(&client, &key, funding, &addresses).await?;
    let smoke_hash =
        BlockHash::from_str(&client.generate_to_address(1, &address.to_string()).await?[0])?;
    let raw_block = client.get_block(&smoke_hash).await?;
    ensure!(
        raw_block.txdata.len() == 3
            && raw_block.txdata[1] == commit
            && raw_block.txdata[2] == reveal,
        "unexpected mined transaction inventory"
    );
    let raw = serialize(&raw_block);
    let block = decode_block(&raw, SMOKE_HEIGHT, smoke_hash, anchor)?;
    ensure!(block.transactions.len() == 1 && block.transactions[0].index == 2);
    ensure!(
        block.transactions[0].inputs.len() == 1
            && block.transactions[0].inputs[0].insts.ops.len() == 3
    );
    let output = std::env::var_os("KONTOR_WORKLOAD_CANDIDATE_DIR").map(PathBuf::from);
    if let Some(output) = &output {
        fs::create_dir(output).context("candidate directory must not already exist")?;
        snapshot.copy_to(&output.join("snapshot.db"))?;
        fs::write(output.join("block.bin"), &raw)?;
        fs::write(
            output.join("before-projection.json"),
            serde_json::to_vec_pretty(&before)?,
        )?;
        fs::write(
            output.join("before-report.json"),
            serde_json::to_vec_pretty(&before_report)?,
        )?;
        capture::write(output, "source.json", &source)?;
        capture::write(output, "schema.json", &schema)?;
        capture::write(
            output,
            "lifecycle-parameters.json",
            &capture::lifecycle(&genesis)?,
        )?;
        let artifacts = capture::artifacts(
            output,
            &addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )?;
        capture::write(output, "artifacts.json", &artifacts)?;
        fs::write(
            output.join("Cargo.lock"),
            include_bytes!("../../../../Cargo.lock"),
        )?;
        let node: JsonValue = client.call("getnetworkinfo", vec![]).await?;
        let chain: JsonValue = client.call("getblockchaininfo", vec![]).await?;
        ensure!(chain["chain"] == "regtest" && chain["bestblockhash"] == smoke_hash.to_string());
        ensure!(chain["blocks"].as_u64() == Some(SMOKE_HEIGHT));
        let mut funding_chain = Vec::new();
        for hash in &mined {
            funding_chain.push(hex::encode(serialize(
                &client.get_block(&BlockHash::from_str(hash)?).await?,
            )));
        }
        capture::write(
            output,
            "bitcoin-validation.json",
            &json!({
                "network":"regtest","bitcoind_version":node["version"].as_u64().context("missing bitcoind version")?.to_string(),
                "subversion":node["subversion"].as_str().context("missing bitcoind subversion")?,
                "accepted_block_hash":smoke_hash,"accepted_height":SMOKE_HEIGHT,
                "test_mempool_accept":mempool_verdicts,"funding_chain_blocks_hex":funding_chain,
            }),
        )?;
    }
    let raw_block_sha256 = hex::encode(Sha256::digest(&raw));
    let numeric = diagnostic::generate(
        &snapshot,
        directory.path(),
        &block,
        &addresses,
        &raw_block_sha256,
    )
    .await?;
    if let Some(output) = &output {
        fs::write(
            output.join("numeric-check.json"),
            serde_json::to_vec_pretty(&numeric.report)?,
        )?;
    }
    let mut final_projection = None;
    let mut final_report = None;
    let mut accounting_reports = Vec::new();
    for name in ["trial-one.db", "trial-two.db"] {
        snapshot.copy_to(&directory.path().join(name))?;
        let writer = Writer::new(directory.path(), name).await?;
        ensure!(
            database_projection(&writer.connection()).await? == before,
            "reset projection differs"
        );
        let storage = Storage::builder()
            .height(ANCHOR_HEIGHT)
            .conn(writer.connection())
            .build();
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.network = Network::Regtest;
        let trial_engine_dir = TempDir::new_in(directory.path())?;
        let mut trial = reactor(
            runtime,
            client.clone(),
            trial_engine_dir.path(),
            ANCHOR_HEIGHT,
            Some(anchor),
            true,
            &mut engine_cleanup,
        )
        .await?;
        ensure!(
            reporter
                .capture(&mut trial.runtime, ANCHOR_HEIGHT, anchor, &[])
                .await?
                == before_report,
            "restored typed report differs"
        );
        trial.runtime.component_cache.clear();
        apply(&mut trial, block.clone()).await?;
        let rows = receipts(&trial.db_conn(), SMOKE_HEIGHT).await?;
        numeric.compare(&trial.db_conn(), &rows).await?;
        let txid = reveal.compute_txid().to_string();
        let paid: Vec<_> = rows
            .iter()
            .filter(|r| r.txid.as_ref() == Some(&txid))
            .collect();
        ensure!(paid.len() == 3, "missing or extra paid root receipts");
        for (i, row) in paid.iter().enumerate() {
            ensure!(
                row.op_index == Some(i as u32)
                    && row.tx_index == Some(0)
                    && row.input_index == Some(0)
            );
            ensure!(
                row.status
                    == if i == 1 {
                        OpStatus::Other
                    } else {
                        OpStatus::Ok
                    }
            );
            ensure!(row.gas > 0 && row.gas <= GAS_LIMIT);
            ensure!(row.contract == addresses[usize::from(i == 1)].to_string());
            ensure!(
                row.func
                    == if i == 1 {
                        "scan-compound"
                    } else {
                        "write-result-payload"
                    }
            );
            ensure!(row.signer_id == payer_id && row.payer_signer_id == Some(payer_id));
            // set_context resets the result counter for each operation. These
            // calls have no guest subcalls and fee receipts are suppressed.
            ensure!(row.result_index == 0);
        }
        ensure!(paid[0].value.as_deref() == Some("\"é\\n\""));
        ensure!(paid[1].value.is_none());
        ensure!(paid[2].value.as_deref() == Some("\"é\\né\\n\""));
        let projection = database_projection(&trial.db_conn()).await?;
        let accounting = accounting::check(
            &mut trial.runtime,
            &balances_before,
            &public_key.to_string(),
            &txid,
            &rows,
        )
        .await?;
        accounting_reports.push(accounting);
        ensure!(state(&mut trial.runtime, &addresses[0]).await? == [1, 0, 0, 1]);
        ensure!(state(&mut trial.runtime, &addresses[1]).await? == [0, 0, 0, 0]);
        ensure!(
            database_projection(&trial.db_conn()).await? == projection,
            "observation mutated persistent state"
        );
        ensure!(get_meta_u64(&trial.db_conn(), PRUNE_WATERMARK_KEY, 0).await? == 95);
        ensure!(trial.db_conn().query("SELECT 1 FROM contract_state WHERE contract_id = ? AND path = ? AND height = ?",
            params![old_id, old_path.clone(), old_height]).await?.next().await?.is_none(), "obsolete version survived pruning");
        ensure!(
            retained_version(&trial.db_conn(), old_id, &old_path).await? == retained,
            "pruning changed the retained successor"
        );
        let raw_positions = block
            .transactions
            .iter()
            .map(|transaction| (transaction.txid.to_string(), transaction.index))
            .collect::<Vec<_>>();
        let report = reporter
            .capture(&mut trial.runtime, SMOKE_HEIGHT, smoke_hash, &raw_positions)
            .await?;
        if let Some(output) = &output {
            fs::write(
                output.join(format!("{name}-report.json")),
                serde_json::to_vec_pretty(&report)?,
            )?;
            fs::write(
                output.join(format!("{name}-receipts.json")),
                serde_json::to_vec_pretty(&rows)?,
            )?;
            fs::write(
                output.join(format!("{name}-projection.json")),
                serde_json::to_vec_pretty(&projection)?,
            )?;
        }
        if let Some(expected) = &final_projection {
            ensure!(&projection == expected, "replays differ");
        } else {
            final_projection = Some(projection);
        }
        if let Some(expected) = &final_report {
            ensure!(&report == expected, "typed replay reports differ");
        } else {
            final_report = Some(report);
        }
        stop_engine(&mut trial).await?;
    }
    ensure!(hash_file(&snapshot.path)? == snapshot.sha256);
    ensure!(
        capture::source()? == source,
        "source identity changed during candidate generation"
    );
    let candidate = json!({
        "source_commit":GIT_COMMIT_HASH,
        "payer_x_only_pubkey":public_key.to_string(),"schema_sha256":schema_sha256,
        "next_consensus_height":next_consensus_height,
        "funding_seed_hex":hex::encode(FUNDING_SEED),
        "starting_block_height":START_HEIGHT,"anchor_height":ANCHOR_HEIGHT,"anchor_hash":anchor,
        "effective_retain_blocks":7,
        "block_height":SMOKE_HEIGHT,"block_hash":smoke_hash,"raw_block_sha256":hex::encode(Sha256::digest(&raw)),
        "raw_txids":raw_block.txdata.iter().map(|tx|tx.compute_txid().to_string()).collect::<Vec<_>>(),
        "maturity_chain_hashes":mined,"snapshot_sha256":snapshot.sha256,
        "contracts":addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "removed_version":{"contract_id":old_id,"path_hex":hex::encode(&old_path),"height":old_height},
        "accounting":accounting_reports,"replays":2,"frozen_acceptance":false,
    });
    if let Some(output) = &output {
        fs::write(
            output.join("candidate.json"),
            serde_json::to_vec_pretty(&candidate)?,
        )?;
    }
    println!("WORKLOAD_DEVELOPMENT_SMOKE {candidate}");
    client.stop().await?;
    bitcoin.0.wait().await?;
    Ok(())
}
