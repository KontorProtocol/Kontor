use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use bitcoin::consensus::serialize;
use indexer_types::OpWithResult;
use serde_json::Value;

use super::super::super::{ANCHOR_HEIGHT, Snapshot, capture, hash_file};
use super::super::checkpoint::Checkpoint;
use super::super::replay_identity::SourceIdentity;
use super::super::saved::write_new;
use super::Action;
use super::run::Settings;
use super::work::InputPlan;
use crate::bitcoin_client::Client;

mod controls;
mod format;
mod replay;
mod tests;

use format::{BlockRef, EncodedRequest, EventRef, FileRef, Manifest, Saved};

pub(super) struct Output {
    root: PathBuf,
    source: Value,
    binary: String,
    settings: Settings,
}

impl Output {
    pub(super) fn from_env(settings: &Settings) -> Result<Option<Self>> {
        let Some(root) = std::env::var_os("KONTOR_WORKLOAD_TIMED_SAVED_DIR") else {
            return Ok(None);
        };
        settings.validate()?;
        let source = capture::source()?;
        let _: SourceIdentity = serde_json::from_value(source.clone())?;
        let root = PathBuf::from(root);
        fs::create_dir(&root).context("timed archive directory must not already exist")?;
        Ok(Some(Self {
            root,
            source,
            binary: hash_file(&std::env::current_exe()?)?,
            settings: settings.clone(),
        }))
    }

    fn file(&self, name: &str, bytes: &[u8]) -> Result<FileRef> {
        Ok(FileRef {
            name: name.to_owned(),
            sha256: write_new(&self.root, name, bytes)?,
        })
    }

    fn unchanged(&self) -> Result<()> {
        ensure!(
            capture::source()? == self.source,
            "source changed during timed archive generation"
        );
        ensure!(
            hash_file(&std::env::current_exe()?)? == self.binary,
            "binary changed during timed archive generation"
        );
        Ok(())
    }

    pub(super) async fn write(
        self,
        snapshot: &Snapshot,
        client: &Client,
        plan: &InputPlan,
        initial: (&Value, u64),
        checkpoints: &[Checkpoint],
        api_results: &[Vec<OpWithResult>],
    ) -> Result<()> {
        self.unchanged()?;
        let (initial, initial_consensus_height) = initial;
        plan.validate()?;
        ensure!(
            checkpoints.len() == plan.schedule.events.len()
                && api_results.len() == plan.requests.len(),
            "cannot seal an incomplete timed trace"
        );
        snapshot.copy_to(&self.root.join("snapshot.db"))?;
        let initial = self.file("initial.json", &serde_json::to_vec(initial)?)?;
        let mut chain = Vec::new();
        for height in 1..=ANCHOR_HEIGHT {
            let hash = client.get_block_hash(height).await?;
            chain.push(hex::encode(serialize(&client.get_block(&hash).await?)));
        }
        let chain = self.file("chain.json", &serde_json::to_vec(&chain)?)?;
        let mut blocks = Vec::new();
        for (ordinal, input) in plan.blocks.iter().enumerate() {
            ensure!(client.get_block_hash(input.block.height).await? == input.block.hash);
            blocks.push(BlockRef {
                hash: input.block.hash,
                parent: input.block.prev_hash,
                input: self.file(&format!("block-{ordinal:03}.bin"), &input.raw)?,
            });
        }
        let requests: Vec<_> = plan
            .requests
            .iter()
            .enumerate()
            .map(|(ordinal, input)| EncodedRequest {
                ordinal,
                commit: hex::encode(serialize(&input.commit)),
                reveal: hex::encode(serialize(&input.reveal)),
            })
            .collect();
        let requests = self.file("api-inputs.json", &serde_json::to_vec(&requests)?)?;
        let info: Value = client.call("getnetworkinfo", vec![]).await?;
        let mut manifest = Manifest {
            schema_version: 3,
            source: serde_json::from_value(self.source.clone())?,
            binary_sha256: self.binary.clone(),
            settings: self.settings.clone(),
            schedule: plan.schedule.clone(),
            bitcoin_version: info["version"]
                .as_u64()
                .context("Bitcoin version missing")?,
            initial_consensus_height,
            anchor_hash: client.get_block_hash(ANCHOR_HEIGHT).await?,
            canonical_signer: plan.canonical_signer.clone(),
            api_signer: plan.api_signer.clone(),
            snapshot: FileRef {
                name: "snapshot.db".into(),
                sha256: snapshot.sha256.clone(),
            },
            initial,
            chain,
            requests,
            blocks,
            events: Vec::new(),
        };
        let mut previous = manifest.initial.sha256.clone();
        let mut consensus = initial_consensus_height;
        for (ordinal, (event, checkpoint)) in
            plan.schedule.events.iter().zip(checkpoints).enumerate()
        {
            if !matches!(event.action, Action::Simulation { .. }) {
                consensus = consensus
                    .checked_add(1)
                    .context("consensus height overflow")?;
            }
            let name = format!("event-{ordinal:06}.json");
            let state = FileRef {
                sha256: checkpoint.export(&self.root, &name)?,
                name,
            };
            let api_result = if let Action::Simulation { request, .. } = event.action {
                Some(self.file(
                    &format!("api-result-{request:06}.json"),
                    &serde_json::to_vec(&api_results[request])?,
                )?)
            } else {
                None
            };
            let anchor_hash = manifest.anchor(event)?;
            manifest.events.push(EventRef {
                event: event.clone(),
                consensus_height: consensus,
                anchor_hash,
                before: std::mem::replace(&mut previous, state.sha256.clone()),
                state,
                api_result,
            });
        }
        let pending = Saved {
            root: self.root.clone(),
            manifest,
            digest: None,
        };
        pending.inputs()?;
        self.unchanged()?;
        // Publish only after both complete semantic restores and all exported bytes validate.
        let digest = write_new(
            &self.root,
            "manifest.json",
            &serde_json::to_vec_pretty(&pending.manifest)?,
        )?;
        Saved::load(&self.root.join("manifest.json"), &digest)?;
        eprintln!(
            "workload_saved_timed_manifest={}",
            self.root.join("manifest.json").display()
        );
        eprintln!("workload_saved_timed_manifest_sha256={digest}");
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires bitcoind and KONTOR_WORKLOAD_TIMED_MANIFEST with its SHA256"]
async fn workload_saved_timed_events_replay() -> Result<()> {
    let path = PathBuf::from(
        std::env::var_os("KONTOR_WORKLOAD_TIMED_MANIFEST")
            .context("timed manifest path missing")?,
    );
    let digest = std::env::var("KONTOR_WORKLOAD_TIMED_MANIFEST_SHA256")?;
    replay::run(Saved::load(&path, &digest)?).await
}
