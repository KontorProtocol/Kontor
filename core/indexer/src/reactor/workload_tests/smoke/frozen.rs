use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail, ensure};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Block as BitcoinBlock, BlockHash, Network};
use brotli::Decompressor;
use indexer_types::{Block, ContractAddress, InstKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::accounting::Balances;
use super::diagnostic::money;
use super::report::Reporter;
use super::{
    BitcoinProcess, EngineCleanup, Snapshot, accounting, capture, database_projection,
    decode_block, diagnostic, hash_file, reactor, receipts, stop_engine,
};
use crate::bitcoin_client::Client;
use crate::bls::taproot_derivation_path;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Height, Value as ConsensusValue};
use crate::database::Writer;
use crate::database::native_contracts::NATIVE_CONTRACTS;
use crate::database::queries::select_latest_consensus_height;
use crate::reactor::consensus_state::DeferredDecision;
use crate::reg_tester::{derive_taproot_keypair_from_seed, workload_bitcoin};
use crate::runtime::{
    ComponentCache, Decimal, GenesisParameters, GenesisValidator, Runtime, Storage,
};

pub(super) fn text(value: &Value) -> Result<&str> {
    value.as_str().context("expected fixture string")
}

pub(super) fn number(value: &Value) -> Result<u64> {
    value.as_u64().context("expected fixture u64")
}

fn contract(value: &Value) -> Result<ContractAddress> {
    text(value)?.parse().map_err(|error: String| anyhow!(error))
}

pub(super) struct Frozen {
    root: PathBuf,
    pub documents: Value,
    pub sha256: String,
}

impl Frozen {
    pub(super) fn load(path: &Path, expected_sha256: &str) -> Result<Self> {
        let path = path.canonicalize()?;
        let raw = fs::read(&path)?;
        ensure!(
            hex::encode(Sha256::digest(&raw)) == expected_sha256,
            "manifest SHA-256 differs"
        );
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/native-stack/workload_manifest.py");
        // The shared closed-schema validator checks duplicate keys and exact
        // numbers before Rust consumes its output. Ignore Python environment
        // and site hooks; -B keeps the checkout clean.
        let result = Command::new("python3")
            .args(["-E", "-S", "-B"])
            .arg(script)
            .arg(&path)
            .args(["--sha256", expected_sha256])
            .output()?;
        ensure!(
            result.status.success(),
            "frozen document validation failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let documents: Value = serde_json::from_slice(&result.stdout)?;
        ensure!(documents["manifest_sha256"] == expected_sha256);
        ensure!(documents["manifest"] == serde_json::from_slice::<Value>(&raw)?);
        Ok(Self {
            root: path.parent().context("manifest parent")?.to_path_buf(),
            documents,
            sha256: expected_sha256.into(),
        })
    }

    pub(super) fn manifest(&self) -> &Value {
        &self.documents["manifest"]
    }

    fn path(&self, reference: &Value) -> Result<PathBuf> {
        let path = self.root.join(text(&reference["path"])?).canonicalize()?;
        ensure!(
            path.starts_with(&self.root) && path.is_file(),
            "fixture path escaped its root"
        );
        Ok(path)
    }

    pub(super) fn bytes(&self, reference: &Value) -> Result<Vec<u8>> {
        let bytes = fs::read(self.path(reference)?)?;
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == text(&reference["sha256"])?,
            "fixture file hash differs"
        );
        Ok(bytes)
    }

    pub(super) fn snapshot(&self) -> Result<Snapshot> {
        let reference = &self.manifest()["snapshot"]["database"];
        let path = self.path(reference)?;
        let sha256 = text(&reference["sha256"])?.to_owned();
        ensure!(hash_file(&path)? == sha256, "snapshot changed");
        Ok(Snapshot { path, sha256 })
    }

    pub(super) fn check_source(&self) -> Result<Value> {
        let actual = capture::source()?;
        let expected = &self.manifest()["source"];
        ensure!(
            actual["embedded_source_commit"] == expected["kontor_commit"],
            "frozen source revision differs"
        );
        for field in ["rustc_verbose", "target", "profile", "features"] {
            ensure!(
                actual[field] == expected[field],
                "frozen source {field} differs"
            );
        }
        let lockfile = self.bytes(&expected["core_lockfile"])?;
        ensure!(
            lockfile == include_bytes!("../../../../../Cargo.lock"),
            "compiled lockfile differs"
        );
        ensure!(actual["core_lockfile_sha256"] == expected["core_lockfile"]["sha256"]);
        Ok(actual)
    }

    pub(super) fn block(&self) -> Result<Block> {
        let input = &self.manifest()["input"];
        let raw = self.bytes(&input["raw_block"])?;
        let bitcoin: BitcoinBlock = deserialize(&raw)?;
        let raw_txids: Vec<_> = bitcoin
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect();
        ensure!(
            json!(raw_txids) == input["raw_txids"],
            "raw transaction inventory differs"
        );
        let block = decode_block(
            &raw,
            number(&input["height"])?,
            text(&input["block_hash"])?.parse()?,
            text(&input["previous_hash"])?.parse()?,
        )?;
        ensure!(block.transactions.len() == 1 && block.transactions[0].inputs.len() == 1);
        let tx = &block.transactions[0];
        ensure!(json!([tx.txid.to_string()]) == input["kontor_txids"]);
        let decoded = &tx.inputs[0];
        ensure!(decoded.x_only_pubkey.to_string() == text(&input["payer_x_only_pubkey"])?);
        ensure!(!decoded.insts.is_aggregate() && decoded.insts.ops.len() == 3);
        for (index, instruction) in decoded.insts.ops.iter().enumerate() {
            let InstKind::Call { contract, expr } = &instruction.kind else {
                bail!("frozen input contains a non-call operation");
            };
            ensure!(
                json!({"txid":tx.txid.to_string(),"tx_index":tx.index,"input_index":decoded.input_index,
                "op_index":index,"contract":contract.to_string(),"expression":expr,"gas_limit":instruction.gas_limit})
                    == input["operations"][index],
                "decoded operation differs from frozen context"
            );
        }
        Ok(block)
    }

    fn check_lifecycle(&self) -> Result<()> {
        let seed: [u8; 64] = hex::decode(text(&self.manifest()["funding_seed_hex"])?)?
            .try_into()
            .map_err(|_| anyhow!("funding seed length differs"))?;
        let payer =
            derive_taproot_keypair_from_seed(&seed, &taproot_derivation_path(Network::Regtest))?
                .x_only_public_key()
                .0
                .to_string();
        ensure!(payer == text(&self.manifest()["input"]["payer_x_only_pubkey"])?);
        let genesis = GenesisParameters {
            sigma_min: Decimal::from("1"),
            validators: vec![GenesisValidator {
                x_only_pubkey: payer,
                ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
                stake: Decimal::from("100"),
            }],
        };
        ensure!(
            capture::lifecycle(&genesis)? == self.documents["lifecycle"],
            "frozen lifecycle parameters differ"
        );
        Ok(())
    }

    pub(super) async fn bitcoin(&self, client: &Client) -> Result<()> {
        let record = &self.documents["bitcoin"];
        let input = &self.manifest()["input"];
        ensure!(
            record["network"] == "regtest" && record["accepted_block_hash"] == input["block_hash"]
        );
        ensure!(record["bitcoind_version"] == input["bitcoin_validation"]["bitcoind_version"]);
        let info: Value = client.call("getnetworkinfo", vec![]).await?;
        ensure!(number(&info["version"])?.to_string() == text(&record["bitcoind_version"])?);
        let chain = record["funding_chain_blocks_hex"]
            .as_array()
            .context("funding chain blocks")?;
        ensure!(chain.len() as u64 == number(&self.manifest()["snapshot"]["anchor_height"])?);
        for raw in chain {
            let block: BitcoinBlock = deserialize(&hex::decode(text(raw)?)?)?;
            client.submit_workload_block(&block).await?;
        }
        let anchor: Value = client.call("getblockchaininfo", vec![]).await?;
        ensure!(
            anchor["chain"] == "regtest"
                && anchor["bestblockhash"] == self.manifest()["snapshot"]["anchor_hash"]
        );
        ensure!(anchor["blocks"] == self.manifest()["snapshot"]["anchor_height"]);
        let raw = self.bytes(&input["raw_block"])?;
        client.submit_workload_block(&deserialize(&raw)?).await?;
        let tip: Value = client.call("getblockchaininfo", vec![]).await?;
        ensure!(tip["bestblockhash"] == input["block_hash"] && tip["blocks"] == input["height"]);
        let fetched = client
            .get_block(&text(&input["block_hash"])?.parse::<BlockHash>()?)
            .await?;
        ensure!(
            serialize(&fetched) == raw,
            "bitcoind returned different block bytes"
        );
        Ok(())
    }

    pub(super) async fn restored(&self, runtime: &mut Runtime) -> Result<Reporter> {
        let manifest = self.manifest();
        let source = &manifest["source"];
        ensure!(
            runtime.engine.is_pulley()
                && runtime.engine.get_target().as_deref() == Some("pulley64-unknown-unknown-elf")
                && runtime.engine.get_max_wasm_stack() as u64
                    == number(&source["pulley_stack_bytes"])?
                && runtime.engine.get_async_stack_size() as u64
                    == number(&source["native_fiber_bytes"])?
        );
        ensure!(
            runtime.gas_to_fuel_multiplier
                == number(&manifest["execution"]["gas_to_fuel_multiplier"])?
        );
        ensure!(
            money(runtime.pricing.execution_fee(1)?)?
                == text(&manifest["execution"]["execution_price"])?
        );
        ensure!(
            runtime.pricing.storage_deposit_gas(1)
                == Some(number(&manifest["execution"]["storage_gas_per_byte"])?)
        );
        let conn = runtime.get_storage_conn();
        let (_, schema) = capture::schema(&conn).await?;
        ensure!(
            schema == text(&manifest["snapshot"]["schema_sha256"])?,
            "restored schema differs"
        );
        for artifact in manifest["artifacts"].as_array().context("artifacts")? {
            let name = text(&artifact["id"])?;
            let bytes = self.bytes(&artifact["compressed"])?;
            let native = NATIVE_CONTRACTS.iter().position(|(id, _)| *id == name);
            let embedded = if let Some(index) = native {
                NATIVE_CONTRACTS[index].1
            } else {
                ensure!(name == "error_test");
                include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br")
                    .as_slice()
            };
            ensure!(bytes == embedded, "compiled artifact differs: {name}");
            let mut raw = Vec::new();
            Decompressor::new(bytes.as_slice(), 4096).read_to_end(&mut raw)?;
            ensure!(hex::encode(Sha256::digest(raw)) == text(&artifact["raw_sha256"])?);
            for address in artifact["addresses"]
                .as_array()
                .context("artifact addresses")?
            {
                let address = contract(address)?;
                let id = runtime
                    .storage
                    .contract_id(&address)
                    .await?
                    .context("missing stored artifact")?;
                if let Some(index) = native {
                    ensure!(id == index as u64 + 1, "native artifact ID differs");
                }
                let row = conn
                    .query("SELECT bytes FROM contracts WHERE id = ?", [id])
                    .await?
                    .next()
                    .await?
                    .context("stored contract")?;
                ensure!(row.get::<Vec<u8>>(0)? == bytes, "stored artifact differs");
            }
        }
        let start = number(&manifest["execution"]["starting_block_height"])?;
        let anchor = number(&manifest["snapshot"]["anchor_height"])?;
        let row = conn
            .query(
                "SELECT MIN(height), MAX(height), COUNT(*) FROM blocks WHERE height > 0",
                (),
            )
            .await?
            .next()
            .await?
            .context("indexed range")?;
        ensure!(
            row.get::<u64>(0)? == start
                && row.get::<u64>(1)? == anchor
                && row.get::<u64>(2)? == anchor - start + 1
        );
        let addresses: [ContractAddress; 2] = [
            contract(&manifest["input"]["operations"][0]["contract"])?,
            contract(&manifest["input"]["operations"][1]["contract"])?,
        ];
        let versions = self.documents["before"]["state_versions"]
            .as_array()
            .context("before versions")?;
        let pruning: Vec<_> = versions
            .iter()
            .filter(|version| {
                !addresses
                    .iter()
                    .any(|address| version["contract"] == address.to_string())
            })
            .collect();
        let first = pruning.first().context("missing pruning path")?;
        ensure!(
            pruning
                .iter()
                .all(|version| version["contract"] == first["contract"]
                    && version["path_hex"] == first["path_hex"])
        );
        let prune_address = contract(&first["contract"])?;
        Ok(Reporter {
            payer: text(&manifest["input"]["payer_x_only_pubkey"])?.into(),
            addresses,
            prune_contract: runtime
                .storage
                .contract_id(&prune_address)
                .await?
                .context("prune contract")?,
            prune_path: hex::decode(text(&first["path_hex"])?)?,
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a pinned workload manifest and local bitcoind"]
async fn workload_frozen_replay() -> Result<()> {
    let path =
        std::env::var_os("KONTOR_WORKLOAD_MANIFEST").context("missing KONTOR_WORKLOAD_MANIFEST")?;
    let digest = std::env::var("KONTOR_WORKLOAD_MANIFEST_SHA256")
        .context("missing KONTOR_WORKLOAD_MANIFEST_SHA256")?;
    let frozen = Frozen::load(Path::new(&path), &digest)?;
    let source = frozen.check_source()?;
    frozen.check_lifecycle()?;
    let block = frozen.block()?;
    let anchor_height = number(&frozen.manifest()["snapshot"]["anchor_height"])?;
    let anchor_hash: BlockHash = text(&frozen.manifest()["snapshot"]["anchor_hash"])?.parse()?;
    let snapshot = frozen.snapshot()?;
    let directory = TempDir::new()?;
    let bitcoin_dir = TempDir::new()?;
    let (child, client) = workload_bitcoin(bitcoin_dir.path()).await?;
    let mut bitcoin = BitcoinProcess(child);
    frozen.bitcoin(&client).await?;
    let addresses: [ContractAddress; 2] = [
        contract(&frozen.manifest()["input"]["operations"][0]["contract"])?,
        contract(&frozen.manifest()["input"]["operations"][1]["contract"])?,
    ];
    let numeric = diagnostic::generate(
        &snapshot,
        directory.path(),
        &block,
        &addresses,
        text(&frozen.manifest()["input"]["raw_block"]["sha256"])?,
    )
    .await?;
    ensure!(
        numeric.report == frozen.documents["numeric"],
        "independent numeric replay differs from frozen report"
    );
    let mut engine_cleanup = EngineCleanup::default();
    let mut initial_projection = None;
    let mut final_projection = None;
    let raw_positions = block
        .transactions
        .iter()
        .map(|transaction| (transaction.txid.to_string(), transaction.index))
        .collect::<Vec<_>>();
    for name in ["frozen-one.db", "frozen-two.db"] {
        snapshot.copy_to(&directory.path().join(name))?;
        let writer = Writer::new(directory.path(), name).await?;
        let conn = writer.connection();
        let before = database_projection(&conn).await?;
        if let Some(expected) = &initial_projection {
            ensure!(&before == expected, "restored databases differ");
        } else {
            initial_projection = Some(before.clone());
        }
        let storage = Storage::builder()
            .height(anchor_height)
            .conn(conn.clone())
            .build();
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.network = Network::Regtest;
        let reporter = frozen.restored(&mut runtime).await?;
        let engine_dir = TempDir::new_in(directory.path())?;
        let mut trial = reactor(
            runtime,
            client.clone(),
            engine_dir.path(),
            anchor_height,
            Some(anchor_hash),
            true,
            &mut engine_cleanup,
        )
        .await?;
        ensure!(
            reporter
                .capture(
                    &mut *trial.test_runtime().await,
                    anchor_height,
                    anchor_hash,
                    &[]
                )
                .await?
                == frozen.documents["before"],
            "restored report differs from frozen report"
        );
        let balances = Balances::capture(&mut *trial.test_runtime().await, &reporter.payer).await?;
        ensure!(
            database_projection(&conn).await? == before,
            "restore validation mutated state"
        );
        let next = select_latest_consensus_height(&conn)
            .await?
            .unwrap_or(0)
            .checked_add(1)
            .context("consensus height overflow")?;
        let decision = &frozen.manifest()["decision"];
        ensure!(
            next == number(&decision["consensus_height"])?,
            "decision does not follow restored history"
        );
        let decision = DeferredDecision {
            consensus_height: Height::new(next),
            value: ConsensusValue::new_block(
                number(&decision["block_height"])?,
                text(&decision["block_hash"])?.parse()?,
            ),
            certificate: hex::decode(text(&decision["certificate_hex"])?)?,
            certified_txs: None,
        };
        trial.test_runtime().await.component_cache.clear();
        trial.handle_block(block.clone(), &decision).await?;
        let rows = receipts(&conn, block.height).await?;
        numeric.compare(&conn, &rows).await?;
        let projection = database_projection(&conn).await?;
        accounting::check(
            &mut *trial.test_runtime().await,
            &balances,
            &reporter.payer,
            &block.transactions[0].txid.to_string(),
            &rows,
        )
        .await?;
        let report = reporter
            .capture(
                &mut *trial.test_runtime().await,
                block.height,
                block.hash,
                &raw_positions,
            )
            .await?;
        ensure!(
            report == frozen.documents["after"],
            "replay differs from frozen expected report"
        );
        ensure!(
            database_projection(&conn).await? == projection,
            "replay observation mutated state"
        );
        if let Some(expected) = &final_projection {
            ensure!(&projection == expected, "replay databases differ");
        } else {
            final_projection = Some(projection);
        }
        stop_engine(&mut trial).await?;
    }
    ensure!(
        hash_file(&snapshot.path)? == snapshot.sha256,
        "frozen snapshot changed"
    );
    ensure!(
        frozen.check_source()? == source,
        "source identity changed during replay"
    );
    // Re-validate the input closure after replay so changed sidecars cannot be
    // silently associated with the successful run.
    ensure!(
        Frozen::load(Path::new(&path), &digest)?.documents == frozen.documents,
        "frozen inputs changed during replay"
    );
    client.stop().await?;
    bitcoin.0.wait().await?;
    println!(
        "WORKLOAD_FROZEN_REPLAY {}",
        json!({"manifest_sha256":frozen.sha256,
            "source":source,"python_version":frozen.documents["python_version"],
            "independent_resets":2,"scope":"paid-success-failure-success-v1",
        "report_sha256":frozen.manifest()["expected_report"]["sha256"],"result":"pass"})
    );
    Ok(())
}
