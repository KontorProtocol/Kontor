use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Block as BitcoinBlock, BlockHash, Network};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir};

use super::super::{
    ANCHOR_HEIGHT, BitcoinProcess, EngineCleanup, SMOKE_HEIGHT, Snapshot, apply, capture,
    database_projection, decode_block, hash_file, reactor, stop_engine,
};
use super::PopulationConfig;
use super::configuration::MixedConfig;
use crate::bitcoin_client::Client;
use crate::database::Writer;
use crate::reg_tester::workload_bitcoin;
use crate::runtime::{ComponentCache, Runtime, Storage};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Files {
    snapshot: String,
    block: String,
    chain: String,
    before: String,
    after: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    source: Value,
    binary_sha256: String,
    population: PopulationConfig,
    mixed: MixedConfig,
    bitcoin_version: u64,
    anchor_hash: BlockHash,
    block_hash: BlockHash,
    files: Files,
}

pub(super) struct Output {
    root: PathBuf,
    source: Value,
    binary_sha256: String,
    population: PopulationConfig,
    mixed: MixedConfig,
}

fn write_new(root: &Path, name: &str, bytes: &[u8]) -> Result<String> {
    let mut file = NamedTempFile::new_in(root)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(root.join(name))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

impl Output {
    pub(super) fn from_env(
        population: PopulationConfig,
        mixed: MixedConfig,
    ) -> Result<Option<Self>> {
        let Some(root) = std::env::var_os("KONTOR_WORKLOAD_SAVED_DIR") else {
            return Ok(None);
        };
        let source = capture::source()?;
        let root = PathBuf::from(root);
        fs::create_dir(&root).context("saved workload directory must not already exist")?;
        Ok(Some(Self {
            root,
            source,
            binary_sha256: hash_file(&std::env::current_exe()?)?,
            population,
            mixed,
        }))
    }

    pub(super) async fn write(
        self,
        snapshot: &Snapshot,
        client: &Client,
        block: &BitcoinBlock,
        before: &Value,
        after: &Value,
    ) -> Result<()> {
        ensure!(
            capture::source()? == self.source,
            "source changed during fixture generation"
        );
        ensure!(
            hash_file(&std::env::current_exe()?)? == self.binary_sha256,
            "binary changed during generation"
        );
        snapshot.copy_to(&self.root.join("snapshot.db"))?;
        let info: Value = client.call("getnetworkinfo", vec![]).await?;
        let anchor_hash = client.get_block_hash(ANCHOR_HEIGHT).await?;
        ensure!(block.header.prev_blockhash == anchor_hash);
        ensure!(client.get_block_hash(SMOKE_HEIGHT).await? == block.block_hash());
        let mut chain = Vec::new();
        for height in 1..=ANCHOR_HEIGHT {
            let hash = client.get_block_hash(height).await?;
            chain.push(hex::encode(serialize(&client.get_block(&hash).await?)));
        }
        let files = Files {
            snapshot: snapshot.sha256.clone(),
            block: write_new(&self.root, "block.bin", &serialize(block))?,
            chain: write_new(&self.root, "chain.json", &serde_json::to_vec(&chain)?)?,
            before: write_new(&self.root, "before.json", &serde_json::to_vec(before)?)?,
            after: write_new(&self.root, "after.json", &serde_json::to_vec(after)?)?,
        };
        let manifest = Manifest {
            schema_version: 1,
            source: self.source,
            binary_sha256: self.binary_sha256,
            population: self.population,
            mixed: self.mixed,
            bitcoin_version: info["version"]
                .as_u64()
                .context("missing Bitcoin version")?,
            anchor_hash,
            block_hash: block.block_hash(),
            files,
        };
        // The manifest is the completion marker. Failed generation leaves its
        // partial directory for diagnosis, never an apparently complete input.
        let digest = write_new(
            &self.root,
            "manifest.json",
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
        eprintln!(
            "workload_saved_manifest={}",
            self.root.join("manifest.json").display()
        );
        eprintln!("workload_saved_manifest_sha256={digest}");
        Ok(())
    }
}

struct Saved {
    root: PathBuf,
    manifest: Manifest,
}

impl Saved {
    fn load(path: &Path, expected_sha256: &str) -> Result<Self> {
        let path = path.canonicalize()?;
        ensure!(
            path.file_name().and_then(|name| name.to_str()) == Some("manifest.json"),
            "saved manifest name differs"
        );
        let root = path.parent().context("missing saved directory")?;
        let names = fs::read_dir(root)?
            .map(|entry| {
                entry?
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow!("non-UTF-8 saved file"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            names
                == [
                    "manifest.json",
                    "snapshot.db",
                    "block.bin",
                    "chain.json",
                    "before.json",
                    "after.json"
                ]
                .into_iter()
                .map(String::from)
                .collect(),
            "saved file inventory differs"
        );
        let bytes = fs::read(&path)?;
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == expected_sha256,
            "saved manifest hash differs"
        );
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        ensure!(
            manifest.schema_version == 1,
            "unsupported saved workload schema"
        );
        ensure!(
            hash_file(&std::env::current_exe()?)? == manifest.binary_sha256,
            "saved workload binary differs"
        );
        manifest.population.validate()?;
        manifest.mixed.validate()?;
        ensure!(
            capture::source()? == manifest.source,
            "saved workload source/build differs"
        );
        Ok(Self {
            root: path
                .parent()
                .context("missing saved directory")?
                .to_path_buf(),
            manifest,
        })
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        let path = self.root.join(name).canonicalize()?;
        ensure!(
            path.starts_with(&self.root) && path.is_file(),
            "saved input escaped its directory"
        );
        Ok(path)
    }

    fn bytes(&self, name: &str, expected: &str) -> Result<Vec<u8>> {
        let bytes = fs::read(self.path(name)?)?;
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == expected,
            "saved input hash differs: {name}"
        );
        Ok(bytes)
    }

    fn snapshot(&self) -> Result<Snapshot> {
        let path = self.path("snapshot.db")?;
        ensure!(
            hash_file(&path)? == self.manifest.files.snapshot,
            "saved snapshot hash differs"
        );
        Ok(Snapshot {
            path,
            sha256: self.manifest.files.snapshot.clone(),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires KONTOR_WORKLOAD_SAVED_MANIFEST, its SHA256 and local bitcoind; not performance acceptance"]
async fn workload_saved_configured_replay() -> Result<()> {
    let path = std::env::var_os("KONTOR_WORKLOAD_SAVED_MANIFEST")
        .context("missing saved manifest path")?;
    let expected = std::env::var("KONTOR_WORKLOAD_SAVED_MANIFEST_SHA256")
        .context("missing saved manifest digest")?;
    let saved = Saved::load(Path::new(&path), &expected)?;
    let manifest = &saved.manifest;
    let snapshot = saved.snapshot()?;
    let raw = saved.bytes("block.bin", &manifest.files.block)?;
    let chain: Vec<String> =
        serde_json::from_slice(&saved.bytes("chain.json", &manifest.files.chain)?)?;
    let before: Value =
        serde_json::from_slice(&saved.bytes("before.json", &manifest.files.before)?)?;
    let after: Value = serde_json::from_slice(&saved.bytes("after.json", &manifest.files.after)?)?;
    ensure!(chain.len() == usize::try_from(ANCHOR_HEIGHT)?);
    let block = decode_block(
        &raw,
        SMOKE_HEIGHT,
        manifest.block_hash,
        manifest.anchor_hash,
    )?;
    ensure!(block.transactions.len() == manifest.mixed.transactions);
    ensure!(
        block
            .transactions
            .iter()
            .all(|transaction| transaction.inputs.len() == 1
                && transaction.inputs[0].insts.ops.len() == 2)
    );
    let bitcoin_dir = TempDir::new()?;
    let (child, client) = workload_bitcoin(bitcoin_dir.path()).await?;
    let mut bitcoin = BitcoinProcess(child);
    let info: Value = client.call("getnetworkinfo", vec![]).await?;
    ensure!(
        info["version"].as_u64() == Some(manifest.bitcoin_version),
        "Bitcoin version differs"
    );
    for encoded in chain {
        client
            .submit_workload_block(&deserialize(&hex::decode(encoded)?)?)
            .await?;
    }
    ensure!(client.get_block_hash(ANCHOR_HEIGHT).await? == manifest.anchor_hash);
    client.submit_workload_block(&deserialize(&raw)?).await?;
    ensure!(client.get_block_hash(SMOKE_HEIGHT).await? == manifest.block_hash);
    ensure!(serialize(&client.get_block(&manifest.block_hash).await?) == raw);
    let directory = TempDir::new()?;
    let mut cleanup = EngineCleanup::default();
    for name in ["saved-one.db", "saved-two.db"] {
        snapshot.copy_to(&directory.path().join(name))?;
        let writer = Writer::new(directory.path(), name).await?;
        ensure!(
            database_projection(&writer.connection()).await? == before,
            "saved prestate differs"
        );
        let storage = Storage::builder()
            .height(ANCHOR_HEIGHT)
            .conn(writer.connection())
            .build();
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.network = Network::Regtest;
        let engine_dir = TempDir::new_in(directory.path())?;
        let mut trial = reactor(
            runtime,
            client.clone(),
            engine_dir.path(),
            ANCHOR_HEIGHT,
            Some(manifest.anchor_hash),
            true,
            &mut cleanup,
        )
        .await?;
        ensure!(
            database_projection(&trial.db_conn()).await? == before,
            "startup changed saved prestate"
        );
        let start = Instant::now();
        apply(&mut trial, block.clone()).await?;
        let service_ns = u64::try_from(start.elapsed().as_nanos())?;
        ensure!(
            database_projection(&trial.db_conn()).await? == after,
            "saved execution result differs"
        );
        stop_engine(&mut trial).await?;
        eprintln!(
            "workload_saved_trial={}",
            json!({"trial": name, "manifest_sha256": expected,
            "service_ns": service_ns, "timing_claim": "diagnostic_only"})
        );
    }
    ensure!(
        hash_file(&snapshot.path)? == snapshot.sha256,
        "saved baseline changed"
    );
    ensure!(
        capture::source()? == manifest.source,
        "source changed during replay"
    );
    bitcoin.0.kill().await?;
    Ok(())
}
