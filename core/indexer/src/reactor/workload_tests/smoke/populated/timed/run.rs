use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::{Context, Result, ensure};
use bitcoin::consensus::serialize;
use bitcoin::key::Secp256k1;
use bitcoin::{Address, BlockHash, Network, OutPoint};
use indexer_types::OpWithResult;
use serde::Deserialize;
use tempfile::TempDir;

use super::super::super::super::storage::Population as StoragePopulation;
use super::super::super::super::validators::Population as ValidatorPopulation;
use super::super::super::{
    ANCHOR_HEIGHT, BitcoinProcess, EngineCleanup, FUNDING_SEED, Snapshot, apply,
    checked_signed_instructions, database_projection, decode_block, reactor, stop_engine,
};
use super::super::PopulationConfig;
use super::super::checkpoint::Checkpoint;
use super::super::configuration::MixedConfig;
use super::super::history::HistoryPopulation;
use super::super::mixed::{ApiRecipe, MixedLayout, MixedWorkload};
use super::super::oracle::Before;
use super::super::views::{self, CounterProgress};
use super::super::{sequence_funding, sequence_inputs};
use super::dispatch::{self, Work};
use super::work::{ApiInput, InputPlan, TimedWork};
use super::{Action, Schedule, Spec};
use crate::bitcoin_client::client::RegtestRpc;
use crate::bls::taproot_derivation_path;
use crate::database::Writer;
use crate::database::queries::get_identity;
use crate::reactor::create_runtime_executor;
use crate::reg_tester::{derive_taproot_keypair_from_seed, workload_bitcoin};
use crate::runtime::staking::api as staking;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ComponentCache, Decimal, Runtime, Storage};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    population: PopulationConfig,
    mixed: MixedConfig,
    schedule: Spec,
    #[serde(default)]
    real_clock_drain: bool,
}

impl Settings {
    fn validate(&self) -> Result<Schedule> {
        self.population.validate()?;
        self.mixed.validate()?;
        let profile = self.schedule.profile;
        ensure!(
            self.mixed.transactions == profile.fresh_transactions()
                && self.mixed.new_files
                    == if self.mixed.transactions == 50 {
                        5
                    } else {
                        100
                    }
                && self.mixed.batch_operations == profile.batch_transactions() * 2
                && self.mixed.simulation_operations == profile.simulation_operations()
                && self.mixed.view_concurrency == 8
        );
        ensure!(!self.real_clock_drain || self.schedule.fresh_backlog == 6);
        let schedule = Schedule::new(self.schedule)?;
        ensure!(
            schedule.funding_counts()?.iter().sum::<usize>() < 20_000,
            "timed funding must reserve one output for the independent API signer"
        );
        Ok(schedule)
    }
}

#[test]
fn workload_timed_settings_reserve_api_funding() -> Result<()> {
    let mut settings: Settings = serde_json::from_str(
        r#"{
            "population": {"active_validators":4,"replacements":2,"agreements":2,"members_per_agreement":3},
            "mixed": {"transactions":50,"live_keys":257,"new_files":5,"batch_operations":20,"simulation_operations":2,"view_concurrency":8},
            "schedule": {"profile":"representative","fresh_backlog":0,"intervals":79}
        }"#,
    )?;
    ensure!(settings.validate()?.funding_counts()?.iter().sum::<usize>() == 19_750);
    settings.schedule.intervals = 80;
    ensure!(
        Schedule::new(settings.schedule)?
            .funding_counts()?
            .iter()
            .sum::<usize>()
            == 20_000
    );
    ensure!(settings.validate().is_err());
    Ok(())
}

async fn warm(runtime: &mut Runtime, enabled: bool) -> Result<()> {
    if !enabled {
        return Ok(());
    }
    let before = database_projection(&runtime.get_storage_conn()).await?;
    let mut rows = runtime
        .get_storage_conn()
        .query("SELECT id FROM contracts ORDER BY id", ())
        .await?;
    let mut ids = Vec::new();
    while let Some(row) = rows.next().await? {
        ids.push(row.get::<u64>(0)?);
    }
    drop(rows);
    for id in ids {
        runtime.load_component(id).await?;
        ensure!(runtime.component_cache.get_admitted(&id).await.is_some());
    }
    ensure!(database_projection(&runtime.get_storage_conn()).await? == before);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind and KONTOR_WORKLOAD_TIMED_CONFIG; real clock only when requested"]
async fn workload_timed_mixed_event_replay() -> Result<()> {
    let input = std::env::var("KONTOR_WORKLOAD_TIMED_CONFIG")
        .context("timed replay requires KONTOR_WORKLOAD_TIMED_CONFIG")?;
    let settings: Settings = serde_json::from_str(&input)?;
    let schedule = settings.validate()?;
    let bitcoin_directory = TempDir::new()?;
    let (child, client) = workload_bitcoin(bitcoin_directory.path()).await?;
    let mut bitcoin = BitcoinProcess(child);
    let key = derive_taproot_keypair_from_seed(
        &FUNDING_SEED,
        &taproot_derivation_path(Network::Regtest),
    )?;
    let api_key =
        derive_taproot_keypair_from_seed(&[99; 64], &taproot_derivation_path(Network::Regtest))?;
    let public = key.x_only_public_key().0;
    let api_public = api_key.x_only_public_key().0;
    ensure!(public != api_public);
    let address = Address::p2tr(&Secp256k1::new(), public, None, Network::Regtest);
    let api_address = Address::p2tr(&Secp256k1::new(), api_public, None, Network::Regtest);
    let mined = client
        .generate_to_address(ANCHOR_HEIGHT - 1, &address.to_string())
        .await?;
    let first = client.get_block(&BlockHash::from_str(&mined[0])?).await?;
    let funding = (
        OutPoint {
            txid: first.txdata[0].compute_txid(),
            vout: 0,
        },
        first.txdata[0].output[0].clone(),
    );
    let mut fundings = sequence_funding::prepare_with_api(
        &client,
        &key,
        &address,
        funding,
        &schedule.funding_counts()?,
        &api_address,
    )
    .await?;
    let api_funding = fundings
        .pop()
        .context("missing API funding group")?
        .pop()
        .context("missing API funding")?;
    ensure!(api_funding.1.script_pubkey == api_address.script_pubkey());
    let anchor = client.get_block_hash(ANCHOR_HEIGHT).await?;
    let directory = TempDir::new()?;
    let writer = Writer::new(directory.path(), "source.db").await?;
    let validators = ValidatorPopulation::new(
        settings.population.active_validators,
        settings.population.replacements,
        [73; 32],
    )?;
    let (_, mut runtime, last_height, last_hash) = create_runtime_executor(
        89,
        &writer,
        client.clone(),
        None,
        &validators.genesis,
        Network::Regtest,
    )
    .await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    for public in [public, api_public] {
        token::issue_to(
            &mut runtime,
            &core,
            HolderRef::XOnlyPubkey(public.to_string()),
            Decimal::from("100"),
        )
        .await??;
    }
    let retained_history = HistoryPopulation::prepare(&mut runtime, settings.mixed).await?;
    let mut cleanup = EngineCleanup::default();
    let engine_directory = TempDir::new_in(directory.path())?;
    let mut history = reactor(
        runtime,
        client.clone(),
        engine_directory.path(),
        last_height,
        last_hash,
        false,
        &mut cleanup,
    )
    .await?;
    for height in 89..=ANCHOR_HEIGHT {
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
        if let Some(population) = &retained_history {
            population.seed_height(&mut history.runtime, height).await?;
        }
        if height == 90 {
            ensure!(validators.schedule(&mut history.runtime).await?.due == ANCHOR_HEIGHT + 1);
        }
    }
    StoragePopulation::prepare(
        &mut history.runtime,
        settings.population.agreements,
        settings.population.members_per_agreement,
        [81; 32],
    )
    .await?;
    let payer = get_identity(&history.db_conn(), &public.to_string())
        .await?
        .context("missing payer")?
        .signer_id();
    let api_payer = get_identity(&history.db_conn(), &api_public.to_string())
        .await?
        .context("missing API payer")?
        .signer_id();
    ensure!(
        payer != api_payer
            && staking::get_stake(&mut history.runtime, &api_payer.to_string())
                .await?
                .is_none()
    );
    let layout = MixedLayout::Single {
        payer,
        operations_per_transaction: 2,
    };
    let first_recipe = MixedWorkload::prepare_timed(
        &mut history.runtime,
        payer,
        schedule.blocks[0].transactions().len(),
    )
    .await?
    .with_pagination(
        &mut history.runtime,
        settings.mixed.live_keys,
        retained_history
            .as_ref()
            .map(|population| population.contract.clone()),
    )
    .await?
    .with_timed_files(
        &mut history.runtime,
        settings.mixed.new_files,
        settings.mixed.transactions,
    )
    .await?;
    let mut recipes = vec![first_recipe];
    for block in &schedule.blocks[1..] {
        recipes.push(
            recipes
                .last()
                .context("missing previous recipe")?
                .next_timed(layout, block.transactions().len(), block.fresh.len())?,
        );
    }
    let requests = schedule
        .events
        .iter()
        .filter(|event| matches!(event.action, Action::Simulation { .. }))
        .count();
    let api = ApiRecipe::new(
        &recipes[0],
        api_payer,
        requests,
        settings.mixed.simulation_operations,
    )?;
    let projection = database_projection(&history.db_conn()).await?;
    let model = Before::capture(
        &mut history.runtime,
        &validators,
        &public.to_string(),
        settings.population,
    )
    .await?;
    ensure!(database_projection(&history.db_conn()).await? == projection);
    let snapshot = Snapshot::export(&history.db_conn(), &directory.path().join("timed.db")).await?;
    stop_engine(&mut history).await?;
    let mut api_inputs = Vec::with_capacity(requests);
    for request in 0..requests {
        let (commit, reveal, _) = checked_signed_instructions(
            &client,
            &api_key,
            api_funding.clone(),
            api.instructions(request)?.to_vec(),
        )
        .await?;
        api_inputs.push(ApiInput { commit, reveal });
    }
    let instructions: Vec<_> = recipes.iter().map(MixedWorkload::instructions).collect();
    let blocks =
        sequence_inputs::generate_groups(&client, &key, &address, &fundings, &instructions).await?;
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
        schedule,
        blocks,
        recipes,
        txids,
        api,
        requests: api_inputs,
        canonical_signer: public.to_string(),
        api_signer: api_public.to_string(),
        layout,
    };
    plan.validate()?;
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
    let checkpoints_directory = Checkpoint::directory()?;
    let mut expected: Option<Vec<Checkpoint>> = None;
    let mut expected_api: Option<Vec<Vec<OpWithResult>>> = None;
    let mut names = vec!["first.db", "second.db"];
    if settings.real_clock_drain {
        names.push("drain.db");
    }
    for name in names {
        snapshot.copy_to(&directory.path().join(name))?;
        let writer = Writer::new(directory.path(), name).await?;
        ensure!(database_projection(&writer.connection()).await? == projection);
        let storage = Storage::builder()
            .height(ANCHOR_HEIGHT)
            .conn(writer.connection())
            .build();
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.network = Network::Regtest;
        warm(&mut runtime, settings.mixed.warm_simulation_cache).await?;
        let engine_directory = TempDir::new_in(directory.path())?;
        let mut trial = reactor(
            runtime,
            client.clone(),
            engine_directory.path(),
            ANCHOR_HEIGHT,
            Some(anchor),
            true,
            &mut cleanup,
        )
        .await?;
        ensure!(database_projection(&trial.db_conn()).await? == projection);
        let counter = Arc::new(AtomicU64::new(0));
        let work_counter = counter.clone();
        let work = async {
            let mut adapter = TimedWork::new(
                &mut trial,
                &plan,
                model.clone(),
                checkpoints_directory.path(),
                expected.as_deref(),
                work_counter,
                retained_history.as_ref(),
            )
            .await?;
            if name == "drain.db" {
                let report = dispatch::drain(plan.schedule.clone(), &mut adapter).await?;
                eprintln!("workload_timed_drain={}", serde_json::to_string(&report)?);
            } else {
                for event in &plan.schedule.events {
                    adapter.check_before(event).await?;
                    adapter.execute(event).await?;
                    adapter.check(event).await?;
                }
                ensure!(adapter.checkpoints.len() == plan.schedule.events.len());
            }
            Ok((adapter.checkpoints, adapter.api_results))
        };
        let (actual, api_results) = views::run_progress(
            directory.path(),
            name,
            Some(settings.mixed),
            &projection,
            CounterProgress {
                maximum,
                completed: counter,
            },
            work,
        )
        .await?;
        if let Some(expected_api) = &expected_api {
            ensure!(
                expected_api.get(..api_results.len()) == Some(api_results.as_slice()),
                "timed API replay results differ"
            );
            if name != "drain.db" {
                ensure!(api_results.len() == expected_api.len());
            }
        } else {
            expected_api = Some(api_results);
        }
        if name != "drain.db" {
            expected = Some(actual);
        }
        stop_engine(&mut trial).await?;
    }
    ensure!(database_projection(&history.db_conn()).await? == projection);
    bitcoin.0.kill().await?;
    eprintln!(
        "workload_timed_replay_passed={}",
        serde_json::json!({"events":plan.schedule.events.len(),"blocks":plan.blocks.len(),"api_requests":plan.requests.len(),"real_clock_drain":settings.real_clock_drain})
    );
    Ok(())
}
