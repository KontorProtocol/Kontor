use std::path::Path;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use bitcoin::consensus::{deserialize, serialize};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::super::super::{
    ANCHOR_HEIGHT, BitcoinProcess, EngineCleanup, Snapshot, apply, database_projection, reactor,
    stop_engine,
};
use super::super::batch::BatchProof;
use super::super::checkpoint::Checkpoint;
use super::super::replay_identity::ReplayIdentity;
use super::super::views;
use super::format::{FileRef, Inputs, Saved};
use crate::database::Writer;
use crate::reactor::Reactor;
use crate::reactor::executor::RuntimeExecutor;
use crate::reg_tester::workload_bitcoin;
use crate::runtime::{ComponentCache, Runtime, Storage};

async fn check(
    trial: &Reactor<RuntimeExecutor>,
    saved: &Saved,
    file: &FileRef,
    temporary: &Path,
) -> Result<()> {
    Checkpoint::capture(temporary, &database_projection(&trial.db_conn()).await?)?
        .check_file(&saved.root.join(&file.name))
        .with_context(|| format!("saved sequence checkpoint differs: {}", file.name))
}

pub(super) async fn run(saved: Saved, digest: &str) -> Result<()> {
    let manifest = &saved.manifest;
    let identity = ReplayIdentity::load(
        &saved.root,
        digest,
        &serde_json::to_value(&manifest.source)?,
        &manifest.binary_sha256,
    )?;
    let Inputs {
        chain,
        blocks: inputs,
        simulations,
    } = saved.inputs()?;
    let initial: Value = serde_json::from_slice(&saved.bytes(&manifest.initial)?)?;
    let snapshot = Snapshot {
        path: saved.root.join(&manifest.snapshot.name),
        sha256: manifest.snapshot.sha256.clone(),
    };
    let bitcoin_dir = TempDir::new()?;
    let (child, client) = workload_bitcoin(bitcoin_dir.path()).await?;
    let mut bitcoin = BitcoinProcess(child);
    let info: Value = client.call("getnetworkinfo", vec![]).await?;
    ensure!(
        info["version"].as_u64() == Some(manifest.bitcoin_version),
        "Bitcoin version differs"
    );
    for block in chain {
        client.submit_workload_block(&block).await?;
    }
    ensure!(client.get_block_hash(ANCHOR_HEIGHT).await? == manifest.anchor_hash);
    for input in &inputs {
        client
            .submit_workload_block(&deserialize(&input.raw)?)
            .await?;
        ensure!(client.get_block_hash(input.block.height).await? == input.block.hash);
        ensure!(serialize(&client.get_block(&input.block.hash).await?) == input.raw);
    }
    let directory = TempDir::new()?;
    let checkpoints = Checkpoint::directory()?;
    let mut cleanup = EngineCleanup::default();
    for name in ["sequence-one.db", "sequence-two.db"] {
        snapshot.copy_to(&directory.path().join(name))?;
        let writer = Writer::new(directory.path(), name).await?;
        Checkpoint::capture(
            checkpoints.path(),
            &database_projection(&writer.connection()).await?,
        )?
        .check_file(&saved.root.join(&manifest.initial.name))?;
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
        check(&trial, &saved, &manifest.initial, checkpoints.path()).await?;
        let work = async {
            let mut predecessor = &manifest.initial;
            let mut checked = 0;
            for (ordinal, (step, input)) in manifest.steps.iter().zip(&inputs).enumerate() {
                ensure!(
                    trial.execution.last_height == step.height - 1
                        && trial.execution.last_hash == Some(step.parent),
                    "replay tip differs from action anchor"
                );
                if let Some(requests) = &simulations[ordinal] {
                    requests
                        .execute(&mut trial, manifest.mixed.warm_simulation_cache)
                        .await?;
                }
                let mut proofs = Vec::new();
                let batch_size = manifest.mixed.batch_operations / 2;
                for (index, batch) in step.batches.iter().enumerate() {
                    check(&trial, &saved, predecessor, checkpoints.path()).await?;
                    let first = index * batch_size;
                    let proof = BatchProof::execute_many(
                        &mut trial,
                        &input.reveals[first..first + batch_size],
                        first,
                        checkpoints.path(),
                    )
                    .await?;
                    proof
                        .checkpoint()
                        .check_file(&saved.root.join(&batch.checkpoint.state.name))?;
                    predecessor = &batch.checkpoint.state;
                    proofs.push(proof);
                    checked += 1;
                }
                check(&trial, &saved, predecessor, checkpoints.path()).await?;
                apply(&mut trial, input.block.clone()).await?;
                check(&trial, &saved, &step.checkpoint.state, checkpoints.path()).await?;
                for proof in proofs {
                    proof.check(&trial).await?;
                }
                // Confirmation observations must not change the complete persisted state.
                check(&trial, &saved, &step.checkpoint.state, checkpoints.path()).await?;
                predecessor = &step.checkpoint.state;
                checked += 1;
                eprintln!(
                    "workload_saved_sequence_step={}",
                    json!({"trial":name,"ordinal":ordinal,"height":step.height,"checkpoints":checked})
                );
            }
            Ok(checked)
        };
        let count = views::run_steps(
            directory.path(),
            name,
            Some(manifest.mixed),
            &initial,
            manifest.steps.len(),
            work,
        )
        .await?;
        stop_engine(&mut trial).await?;
        eprintln!(
            "workload_saved_sequence_trial={}",
            json!({"trial":name,"manifest_sha256":digest,"steps":manifest.steps.len(),"checkpoints":count,"timing_claim":"none"})
        );
    }
    saved.verify()?;
    bitcoin.0.kill().await?;
    identity.finish()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires saved sequence manifest and SHA256 plus local bitcoind; correctness only"]
async fn workload_saved_sequence_replay() -> Result<()> {
    let path = std::env::var_os("KONTOR_WORKLOAD_SAVED_MANIFEST")
        .context("missing saved sequence manifest")?;
    let digest = std::env::var("KONTOR_WORKLOAD_SAVED_MANIFEST_SHA256")
        .context("missing saved sequence digest")?;
    run(Saved::load(Path::new(&path), &digest)?, &digest).await
}
