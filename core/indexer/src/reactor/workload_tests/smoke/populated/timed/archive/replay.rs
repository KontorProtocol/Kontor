use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use bitcoin::consensus::{deserialize, serialize};
use indexer_types::OpWithResult;
use serde_json::Value;
use tempfile::TempDir;

use super::super::super::super::super::validators::Population as ValidatorPopulation;
use super::super::super::super::{
    ANCHOR_HEIGHT, BitcoinProcess, EngineCleanup, Snapshot, database_projection, reactor,
    stop_engine,
};
use super::super::super::checkpoint::Checkpoint;
use super::super::super::history::HistoryPopulation;
use super::super::super::mixed::{ApiRecipe, MixedLayout, MixedWorkload};
use super::super::super::oracle::Before;
use super::super::super::replay_identity::ReplayIdentity;
use super::super::super::views::{self, CounterProgress};
use super::super::Action;
use super::super::dispatch;
use super::super::dispatch::historical;
use super::super::run::warm;
use super::super::work::{InputPlan, TimedWork};
use super::format::{Inputs, Saved};
use crate::database::Writer;
use crate::database::queries::{get_identity, select_latest_consensus_height};
use crate::reg_tester::workload_bitcoin;
use crate::runtime::staking::api as staking;
use crate::runtime::{ComponentCache, Runtime, Storage};

pub(super) async fn run(saved: Saved) -> Result<()> {
    run_mode(saved, false).await
}

pub(super) async fn run_historical(saved: Saved) -> Result<()> {
    ensure!(
        saved.manifest.schedule.spec.fresh_backlog == 0,
        "historical replay requires complete mixed intervals"
    );
    run_mode(saved, true).await
}

async fn run_mode(saved: Saved, paced_api: bool) -> Result<()> {
    let manifest = &saved.manifest;
    let digest = saved
        .digest
        .as_deref()
        .context("timed archive is incomplete")?;
    let identity = ReplayIdentity::load(
        &saved.root,
        digest,
        &serde_json::to_value(&manifest.source)?,
        &manifest.binary_sha256,
    )?;
    let Inputs {
        chain,
        blocks,
        requests,
    } = saved.inputs()?;
    let projection: Value = serde_json::from_slice(&saved.bytes(&manifest.initial)?)?;
    let snapshot = Snapshot {
        path: saved.root.join(&manifest.snapshot.name),
        sha256: manifest.snapshot.sha256.clone(),
    };
    let bitcoin_directory = TempDir::new()?;
    let (child, client) = workload_bitcoin(bitcoin_directory.path()).await?;
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
    for request in &requests {
        let raw = [
            hex::encode(serialize(&request.commit)),
            hex::encode(serialize(&request.reveal)),
        ];
        let verdicts = client.test_mempool_accept(&raw).await?;
        ensure!(
            verdicts.len() == 2 && verdicts.iter().all(|verdict| verdict.allowed),
            "saved API Bitcoin admission failed: {verdicts:?}"
        );
    }
    for block in &blocks {
        client
            .submit_workload_block(&deserialize(&block.raw)?)
            .await?;
        ensure!(client.get_block_hash(block.block.height).await? == block.block.hash);
        ensure!(serialize(&client.get_block(&block.block.hash).await?) == block.raw);
    }
    eprintln!("workload_saved_timed_bitcoin_admitted=true");
    let directory = TempDir::new()?;
    let checkpoints = Checkpoint::directory()?;
    let expected = manifest
        .events
        .iter()
        .map(|event| Checkpoint::import(checkpoints.path(), &saved.root.join(&event.state.name)))
        .collect::<Result<Vec<_>>>()?;
    let expected_api = manifest
        .events
        .iter()
        .filter_map(|event| event.api_result.as_ref())
        .map(|file| {
            Ok(serde_json::from_slice::<Vec<OpWithResult>>(
                &saved.bytes(file)?,
            )?)
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(expected_api.len() == requests.len());
    let validators = ValidatorPopulation::new(
        manifest.settings.population.active_validators,
        manifest.settings.population.replacements,
        [73; 32],
    )?;
    let mut cleanup = EngineCleanup::default();
    for name in ["timed-one.db", "timed-two.db"] {
        snapshot.copy_to(&directory.path().join(name))?;
        let writer = Writer::new(directory.path(), name).await?;
        ensure!(database_projection(&writer.connection()).await? == projection);
        ensure!(
            select_latest_consensus_height(&writer.connection()).await?
                == Some(manifest.initial_consensus_height)
        );
        let storage = Storage::builder()
            .height(ANCHOR_HEIGHT)
            .conn(writer.connection())
            .build();
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.network = Network::Regtest;
        let payer = get_identity(&writer.connection(), &manifest.canonical_signer)
            .await?
            .context("saved canonical signer missing")?
            .signer_id();
        let api_payer = get_identity(&writer.connection(), &manifest.api_signer)
            .await?
            .context("saved API signer missing")?
            .signer_id();
        ensure!(
            payer != api_payer
                && staking::get_stake(&mut runtime, &api_payer.to_string())
                    .await?
                    .is_none()
        );
        let layout = MixedLayout::Single {
            payer,
            operations_per_transaction: 2,
        };
        let first = MixedWorkload::restore_timed(
            &mut runtime,
            payer,
            manifest.schedule.blocks[0].transactions().len(),
            manifest.settings.mixed,
        )
        .await?;
        let mut recipes = vec![first];
        for block in &manifest.schedule.blocks[1..] {
            recipes.push(recipes.last().context("missing prior recipe")?.next_timed(
                layout,
                block.transactions().len(),
                block.fresh.len(),
            )?);
        }
        let api = ApiRecipe::new(
            &recipes[0],
            api_payer,
            requests.len(),
            manifest.settings.mixed.simulation_operations,
        )?;
        let history = HistoryPopulation::restore(&mut runtime, manifest.settings.mixed).await?;
        let model = Before::capture(
            &mut runtime,
            &validators,
            &manifest.canonical_signer,
            manifest.settings.population,
        )
        .await?;
        let txids = blocks
            .iter()
            .map(|block| {
                block
                    .reveals
                    .iter()
                    .map(|tx| tx.compute_txid().to_string())
                    .collect()
            })
            .collect();
        let plan = InputPlan {
            schedule: manifest.schedule.clone(),
            blocks: blocks.clone(),
            recipes,
            txids,
            api,
            requests: requests.clone(),
            canonical_signer: manifest.canonical_signer.clone(),
            api_signer: manifest.api_signer.clone(),
            layout,
        };
        plan.validate()?;
        ensure!(
            database_projection(&writer.connection()).await? == projection,
            "recipe restoration mutated initial state"
        );
        let maximum = plan
            .recipes
            .last()
            .context("missing last recipe")?
            .counter_after(
                plan.blocks
                    .last()
                    .context("missing last block")?
                    .reveals
                    .len()
                    * 2,
            )?;
        let engine_directory = TempDir::new_in(directory.path())?;
        // Model reconstruction performs contract views. Its cache and transient
        // execution state must not leak into the declared replay setup.
        drop(runtime);
        let storage = Storage::builder()
            .height(ANCHOR_HEIGHT)
            .conn(writer.connection())
            .build();
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.network = Network::Regtest;
        warm(&mut runtime, manifest.settings.mixed.warm_simulation_cache).await?;
        let mut trial = reactor(
            runtime,
            client.clone(),
            engine_directory.path(),
            ANCHOR_HEIGHT,
            Some(manifest.anchor_hash),
            true,
            &mut cleanup,
        )
        .await?;
        ensure!(database_projection(&trial.db_conn()).await? == projection);
        let counter = Arc::new(AtomicU64::new(0));
        let work_counter = counter.clone();
        eprintln!("workload_saved_timed_execution_started={name}");
        let work = async {
            let mut adapter = TimedWork::new(
                &mut trial,
                &plan,
                model,
                checkpoints.path(),
                Some(&expected),
                work_counter,
                history.as_ref(),
            )
            .await?;
            if paced_api {
                let report = historical::run(plan.schedule.clone(), &mut adapter).await?;
                ensure!(adapter.api_results.is_empty());
                eprintln!(
                    "workload_historical_replay={}",
                    serde_json::json!({"restore":name,"report":report})
                );
            } else {
                for event in &plan.schedule.events {
                    let timing = dispatch::replay_event(event, &mut adapter).await?;
                    if let Action::Simulation { request, .. } = event.action {
                        ensure!(
                            adapter.api_results.get(request) == expected_api.get(request),
                            "saved timed API result differs at request {request}"
                        );
                    }
                    eprintln!(
                        "workload_replay_service={}",
                        serde_json::json!({"restore":name,"timing":timing})
                    );
                }
                ensure!(adapter.api_results.len() == expected_api.len());
            }
            ensure!(adapter.checkpoints.len() == expected.len());
            Ok(())
        };
        views::run_progress(
            directory.path(),
            name,
            Some(manifest.settings.mixed),
            &projection,
            CounterProgress {
                maximum,
                completed: counter,
            },
            work,
        )
        .await?;
        stop_engine(&mut trial).await?;
    }
    saved.verify()?;
    identity.finish()?;
    bitcoin.0.kill().await?;
    if paced_api {
        eprintln!(
            "workload_saved_timed_historical_replay_passed={}",
            serde_json::json!({"events":manifest.events.len(),"archived_api_inputs":expected_api.len(),"restores":2,"manifest_sha256":digest})
        );
    } else {
        eprintln!(
            "workload_saved_timed_replay_passed={}",
            serde_json::json!({"events": manifest.events.len(), "api_requests": expected_api.len(), "restores":2,"manifest_sha256":digest})
        );
    }
    Ok(())
}
