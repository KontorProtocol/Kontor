use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use bitcoin::Block as BitcoinBlock;
use bitcoin::consensus::{deserialize, serialize};
use serde_json::Value;

use super::super::{ANCHOR_HEIGHT, Snapshot, capture, hash_file};
use super::PopulationConfig;
use super::checkpoint::Checkpoint;
use super::configuration::MixedConfig;
use super::replay_identity::SourceIdentity;
use super::saved::write_new;
use super::sequence_inputs::BlockInput;
use super::simulation_requests::SimulationRequests;
use crate::bitcoin_client::Client;

mod format;
mod replay;
mod tests;

use format::{Batch, CheckpointRef, FileRef, Manifest, Saved, Step};

pub(super) struct Output {
    root: PathBuf,
    source: Value,
    binary_sha256: String,
    population: PopulationConfig,
    mixed: MixedConfig,
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
        let _: SourceIdentity = serde_json::from_value(source.clone())?;
        let root = PathBuf::from(root);
        fs::create_dir(&root).context("saved sequence directory must not already exist")?;
        Ok(Some(Self {
            root,
            source,
            binary_sha256: hash_file(&std::env::current_exe()?)?,
            population,
            mixed,
        }))
    }

    fn file(&self, name: String, bytes: &[u8]) -> Result<FileRef> {
        Ok(FileRef {
            sha256: write_new(&self.root, &name, bytes)?,
            name,
        })
    }

    fn checkpoint(
        &self,
        name: String,
        checkpoint: &Checkpoint,
        previous: &mut String,
    ) -> Result<CheckpointRef> {
        let sha256 = checkpoint.export(&self.root, &name)?;
        Ok(CheckpointRef {
            before: std::mem::replace(previous, sha256.clone()),
            state: FileRef { name, sha256 },
        })
    }

    pub(super) async fn write(
        self,
        snapshot: &Snapshot,
        client: &Client,
        inputs: &[BlockInput],
        initial: &Value,
        checkpoints: &[Checkpoint],
        simulations: &[Option<SimulationRequests>],
    ) -> Result<()> {
        ensure!(
            capture::source()? == self.source,
            "source changed during sequence generation"
        );
        ensure!(
            hash_file(&std::env::current_exe()?)? == self.binary_sha256,
            "binary changed during sequence generation"
        );
        ensure!(matches!(inputs.len(), 2 | 6 | 7) && simulations.len() == inputs.len());
        let batch_size = self.mixed.batch_operations / 2;
        let batches_per_step = if batch_size == 0 {
            0
        } else {
            self.mixed.transactions / batch_size
        };
        ensure!(
            checkpoints.len() == inputs.len() * (batches_per_step + 1),
            "sequence checkpoint count differs"
        );
        snapshot.copy_to(&self.root.join("snapshot.db"))?;
        let mut chain = Vec::new();
        for height in 1..=ANCHOR_HEIGHT {
            let hash = client.get_block_hash(height).await?;
            chain.push(hex::encode(serialize(&client.get_block(&hash).await?)));
        }
        let initial = self.file("initial.json".into(), &serde_json::to_vec(initial)?)?;
        let mut previous = initial.sha256.clone();
        let mut checkpoint_index = 0;
        let mut steps = Vec::new();
        for (ordinal, input) in inputs.iter().enumerate() {
            let raw: BitcoinBlock = deserialize(&input.raw)?;
            ensure!(client.get_block_hash(input.block.height).await? == raw.block_hash());
            let mut batches = Vec::new();
            if batch_size > 0 {
                for (index, transactions) in input.reveals.chunks(batch_size).enumerate() {
                    let checkpoint = self.checkpoint(
                        format!("step-{ordinal:03}-batch-{index:03}.json"),
                        &checkpoints[checkpoint_index],
                        &mut previous,
                    )?;
                    checkpoint_index += 1;
                    batches.push(Batch {
                        anchor_height: input.block.height - 1,
                        anchor_hash: input.block.prev_hash,
                        transaction_ids: transactions.iter().map(|tx| tx.compute_txid()).collect(),
                        checkpoint,
                    });
                }
            }
            let checkpoint = self.checkpoint(
                format!("step-{ordinal:03}-block.json"),
                &checkpoints[checkpoint_index],
                &mut previous,
            )?;
            checkpoint_index += 1;
            steps.push(Step {
                height: input.block.height,
                hash: input.block.hash,
                parent: input.block.prev_hash,
                block: self.file(format!("block-{ordinal:03}.bin"), &input.raw)?,
                batches,
                simulations: simulations[ordinal]
                    .as_ref()
                    .map(|requests| {
                        self.file(format!("simulation-{ordinal:03}.json"), &requests.bytes()?)
                    })
                    .transpose()?,
                checkpoint,
            });
        }
        let info: Value = client.call("getnetworkinfo", vec![]).await?;
        let manifest = Manifest {
            schema_version: 2,
            source: serde_json::from_value(self.source.clone())?,
            binary_sha256: self.binary_sha256.clone(),
            population: self.population,
            mixed: self.mixed,
            bitcoin_version: info["version"]
                .as_u64()
                .context("missing Bitcoin version")?,
            anchor_height: ANCHOR_HEIGHT,
            anchor_hash: client.get_block_hash(ANCHOR_HEIGHT).await?,
            snapshot: FileRef {
                name: "snapshot.db".into(),
                sha256: snapshot.sha256.clone(),
            },
            chain: self.file("chain.json".into(), &serde_json::to_vec(&chain)?)?,
            initial,
            steps,
        };
        let pending = Saved::pending(self.root.clone(), manifest)?;
        pending.inputs()?;
        ensure!(
            capture::source()? == self.source,
            "source changed while exporting sequence"
        );
        ensure!(
            hash_file(&std::env::current_exe()?)? == self.binary_sha256,
            "binary changed while exporting sequence"
        );
        // All semantic checks and both restores precede this completion marker.
        let digest = write_new(
            &self.root,
            "manifest.json",
            &serde_json::to_vec_pretty(&pending.manifest)?,
        )?;
        Saved::load(&self.root.join("manifest.json"), &digest)?;
        eprintln!(
            "workload_saved_sequence_manifest={}",
            self.root.join("manifest.json").display()
        );
        eprintln!("workload_saved_sequence_manifest_sha256={digest}");
        Ok(())
    }
}
