use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::consensus::deserialize;
use bitcoin::{Block as BitcoinBlock, BlockHash, OutPoint, Txid};
use serde::{Deserialize, Serialize};

use super::super::super::{ANCHOR_HEIGHT, decode_block, hash_file};
use super::super::PopulationConfig;
use super::super::configuration::MixedConfig;
use super::super::replay_identity::SourceIdentity;
use super::super::sequence_inputs::BlockInput;
use super::super::simulation_requests::SimulationRequests;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileRef {
    pub(super) name: String,
    pub(super) sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointRef {
    pub(super) before: String,
    pub(super) state: FileRef,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Batch {
    pub(super) anchor_height: u64,
    pub(super) anchor_hash: BlockHash,
    pub(super) transaction_ids: Vec<Txid>,
    pub(super) checkpoint: CheckpointRef,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Step {
    pub(super) height: u64,
    pub(super) hash: BlockHash,
    pub(super) parent: BlockHash,
    pub(super) block: FileRef,
    pub(super) batches: Vec<Batch>,
    pub(super) simulations: Option<FileRef>,
    pub(super) checkpoint: CheckpointRef,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) schema_version: u32,
    pub(super) source: SourceIdentity,
    pub(super) binary_sha256: String,
    pub(super) population: PopulationConfig,
    pub(super) mixed: MixedConfig,
    pub(super) bitcoin_version: u64,
    pub(super) anchor_height: u64,
    pub(super) anchor_hash: BlockHash,
    pub(super) snapshot: FileRef,
    pub(super) chain: FileRef,
    pub(super) initial: FileRef,
    pub(super) steps: Vec<Step>,
}

fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid SHA256 digest"
    );
    Ok(())
}

impl Manifest {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 2 * 1024 * 1024,
            "sequence manifest exceeds size bound"
        );
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.inventory()?;
        Ok(manifest)
    }

    pub(super) fn inventory(&self) -> Result<BTreeMap<String, String>> {
        ensure!(self.schema_version == 2, "unsupported sequence schema");
        ensure!(
            self.anchor_height == ANCHOR_HEIGHT,
            "sequence anchor height differs"
        );
        ensure!(
            matches!(self.steps.len(), 2 | 6 | 7),
            "invalid sequence length"
        );
        self.population.validate()?;
        self.mixed.validate()?;
        digest(&self.binary_sha256)?;
        let mut files = BTreeMap::new();
        let mut add = |file: &FileRef, name: &str| -> Result<()> {
            ensure!(file.name == name, "sequence file name differs: {name}");
            digest(&file.sha256)?;
            ensure!(
                files
                    .insert(file.name.clone(), file.sha256.clone())
                    .is_none(),
                "duplicate sequence file"
            );
            Ok(())
        };
        add(&self.snapshot, "snapshot.db")?;
        add(&self.chain, "chain.json")?;
        add(&self.initial, "initial.json")?;
        let mut parent = self.anchor_hash;
        let mut previous = &self.initial.sha256;
        let mut txids = BTreeSet::new();
        for (ordinal, step) in self.steps.iter().enumerate() {
            let height = ANCHOR_HEIGHT + u64::try_from(ordinal)? + 1;
            ensure!(
                step.height == height && step.parent == parent,
                "sequence block order differs"
            );
            add(&step.block, &format!("block-{ordinal:03}.bin"))?;
            ensure!(
                step.simulations.is_some() == (self.mixed.simulation_operations > 0),
                "sequence simulation inventory differs"
            );
            if let Some(file) = &step.simulations {
                add(file, &format!("simulation-{ordinal:03}.json"))?;
            }
            let batch_size = self.mixed.batch_operations / 2;
            let batch_count = if batch_size == 0 {
                0
            } else {
                self.mixed.transactions / batch_size
            };
            ensure!(
                step.batches.len() == batch_count,
                "sequence batch count differs"
            );
            for (index, batch) in step.batches.iter().enumerate() {
                ensure!(
                    batch.anchor_height == height - 1 && batch.anchor_hash == parent,
                    "sequence batch anchor differs"
                );
                ensure!(
                    batch.transaction_ids.len() == batch_size,
                    "sequence batch size differs"
                );
                for txid in &batch.transaction_ids {
                    ensure!(txids.insert(*txid), "duplicate sequence batch transaction");
                }
                ensure!(
                    batch.checkpoint.before == *previous,
                    "sequence predecessor checkpoint differs"
                );
                add(
                    &batch.checkpoint.state,
                    &format!("step-{ordinal:03}-batch-{index:03}.json"),
                )?;
                previous = &batch.checkpoint.state.sha256;
            }
            ensure!(
                step.checkpoint.before == *previous,
                "sequence block predecessor checkpoint differs"
            );
            add(
                &step.checkpoint.state,
                &format!("step-{ordinal:03}-block.json"),
            )?;
            previous = &step.checkpoint.state.sha256;
            parent = step.hash;
        }
        Ok(files)
    }
}

pub(super) struct Saved {
    pub(super) root: PathBuf,
    pub(super) manifest: Manifest,
    manifest_digest: String,
}

impl Saved {
    pub(super) fn load(path: &Path, expected: &str) -> Result<Self> {
        digest(expected)?;
        ensure!(
            fs::symlink_metadata(path)?.file_type().is_file(),
            "manifest must be a regular file"
        );
        let path = path.canonicalize()?;
        ensure!(
            path.file_name().and_then(|name| name.to_str()) == Some("manifest.json"),
            "sequence manifest name differs"
        );
        ensure!(
            fs::metadata(&path)?.len() <= 2 * 1024 * 1024,
            "sequence manifest exceeds size bound"
        );
        ensure!(
            hash_file(&path)? == expected,
            "sequence manifest hash differs"
        );
        let manifest = Manifest::parse(&fs::read(&path)?)?;
        let saved = Self {
            root: path
                .parent()
                .context("missing sequence directory")?
                .to_path_buf(),
            manifest,
            manifest_digest: expected.to_owned(),
        };
        saved.verify()?;
        Ok(saved)
    }

    pub(super) fn pending(root: PathBuf, manifest: Manifest) -> Result<Self> {
        let saved = Self {
            root,
            manifest,
            manifest_digest: String::new(),
        };
        saved.verify_files(false)?;
        Ok(saved)
    }

    fn verify_files(&self, sealed: bool) -> Result<()> {
        let files = self.manifest.inventory()?;
        let mut expected: BTreeSet<_> = files.keys().cloned().collect();
        if sealed {
            expected.insert("manifest.json".into());
        }
        let mut actual = BTreeSet::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_file(),
                "sequence contains a non-regular file"
            );
            actual.insert(
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow!("non-UTF-8 sequence file"))?,
            );
        }
        ensure!(actual == expected, "sequence file inventory differs");
        for (name, expected) in files {
            ensure!(
                hash_file(&self.root.join(&name))? == expected,
                "sequence file hash differs: {name}"
            );
        }
        Ok(())
    }

    pub(super) fn verify(&self) -> Result<()> {
        self.verify_files(true)?;
        ensure!(
            hash_file(&self.root.join("manifest.json"))? == self.manifest_digest,
            "sequence manifest changed"
        );
        Ok(())
    }

    pub(super) fn bytes(&self, file: &FileRef) -> Result<Vec<u8>> {
        // inventory() accepts only role-derived leaf names before any path is used.
        Ok(fs::read(self.root.join(&file.name))?)
    }

    pub(super) fn inputs(
        &self,
    ) -> Result<(
        Vec<BitcoinBlock>,
        Vec<BlockInput>,
        Vec<Option<SimulationRequests>>,
    )> {
        let encoded: Vec<String> = serde_json::from_slice(&self.bytes(&self.manifest.chain)?)?;
        ensure!(
            encoded.len() == usize::try_from(ANCHOR_HEIGHT)?,
            "sequence setup chain length differs"
        );
        let chain = encoded
            .iter()
            .map(|block| Ok(deserialize::<BitcoinBlock>(&hex::decode(block)?)?))
            .collect::<Result<Vec<_>>>()?;
        let mut unspent = BTreeMap::new();
        for (ordinal, block) in chain.iter().enumerate() {
            ensure!(block.check_merkle_root(), "setup block merkle root differs");
            if ordinal > 0 {
                ensure!(
                    block.header.prev_blockhash == chain[ordinal - 1].block_hash(),
                    "setup block order differs"
                );
            }
            for transaction in &block.txdata {
                for input in &transaction.input {
                    unspent.remove(&input.previous_output);
                }
                for (index, output) in transaction.output.iter().enumerate() {
                    unspent.insert(
                        OutPoint {
                            txid: transaction.compute_txid(),
                            vout: u32::try_from(index)?,
                        },
                        output.clone(),
                    );
                }
            }
        }
        ensure!(
            chain.last().context("empty setup chain")?.block_hash() == self.manifest.anchor_hash,
            "setup anchor differs"
        );
        let mut inputs = Vec::new();
        let mut simulations = Vec::new();
        let mut seen = BTreeSet::new();
        let mut sequence_signer = None;
        for step in &self.manifest.steps {
            let raw = self.bytes(&step.block)?;
            let bitcoin: BitcoinBlock = deserialize(&raw)?;
            ensure!(
                bitcoin.block_hash() == step.hash && bitcoin.check_merkle_root(),
                "sequence raw block identity differs"
            );
            ensure!(
                bitcoin.txdata.len() == self.manifest.mixed.transactions * 2 + 1,
                "sequence raw transaction count differs"
            );
            let block = decode_block(&raw, step.height, step.hash, step.parent)?;
            ensure!(
                block.transactions.len() == self.manifest.mixed.transactions,
                "sequence decoded transaction count differs"
            );
            let signer = block
                .transactions
                .first()
                .and_then(|tx| tx.inputs.first())
                .context("missing sequence signer")?
                .x_only_pubkey;
            ensure!(
                sequence_signer.is_none_or(|expected| expected == signer),
                "sequence signer differs"
            );
            sequence_signer = Some(signer);
            let mut funding = Vec::new();
            let mut instructions = Vec::new();
            for (ordinal, transaction) in block.transactions.iter().enumerate() {
                ensure!(
                    transaction.inputs.len() == 1 && transaction.inputs[0].insts.ops.len() == 2,
                    "sequence operation shape differs"
                );
                ensure!(
                    seen.insert(transaction.txid),
                    "sequence repeats a transaction"
                );
                let commit = &bitcoin.txdata[ordinal * 2 + 1];
                ensure!(
                    commit.input.len() == 1,
                    "sequence commit input count differs"
                );
                let outpoint = commit.input[0].previous_output;
                let output = unspent
                    .remove(&outpoint)
                    .context("sequence reused or unknown initial funding")?;
                funding.push((outpoint, output));
                instructions.extend(transaction.inputs[0].insts.ops.clone());
            }
            // Bitcoin import subsequently verifies consensus validity and signatures.
            // This preflight binds workload shape and prevents reusing setup funding.
            let input = BlockInput::decode(
                raw,
                step.height,
                step.parent,
                &funding,
                &instructions,
                signer,
            )?;
            if !step.batches.is_empty() {
                for (batch, transactions) in step.batches.iter().zip(
                    input
                        .reveals
                        .chunks(self.manifest.mixed.batch_operations / 2),
                ) {
                    ensure!(
                        batch.transaction_ids
                            == transactions
                                .iter()
                                .map(|tx| tx.compute_txid())
                                .collect::<Vec<_>>(),
                        "sequence batch transaction association differs"
                    );
                }
            }
            let requests = step
                .simulations
                .as_ref()
                .map(|file| {
                    SimulationRequests::load(
                        &self.bytes(file)?,
                        self.manifest.mixed.simulation_operations,
                    )
                })
                .transpose()?;
            if let Some(requests) = &requests {
                requests.validate(&input.reveals)?;
            }
            inputs.push(input);
            simulations.push(requests);
        }
        Ok((chain, inputs, simulations))
    }
}
