use std::str::FromStr;

use anyhow::{Context, Result, ensure};
use bitcoin::consensus::serialize;
use bitcoin::key::Secp256k1;
use bitcoin::{Address, BlockHash, Network, OutPoint};
use indexer_types::{ContractAddress, OpStatus};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use super::super::storage::Population as StoragePopulation;
use super::super::validators::Population as ValidatorPopulation;
use super::{
    ANCHOR_HEIGHT, BitcoinProcess, EngineCleanup, FUNDING_SEED, GAS_LIMIT, SMOKE_HEIGHT, Snapshot,
    apply, database_projection, decode_block, reactor, receipts, signed_instructions, signed_smoke,
    state, stop_engine, test_provenance,
};
use crate::bitcoin_client::client::RegtestRpc;
use crate::bls::taproot_derivation_path;
use crate::database::Writer;
use crate::database::queries::get_identity;
use crate::reactor::create_runtime_executor;
use crate::reg_tester::{derive_taproot_keypair_from_seed, workload_bitcoin};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ComponentCache, Decimal, Runtime, Storage, TransactionContext};

mod batch;
mod mixed;
mod oracle;
mod pruning;
mod simulation;

use batch::BatchProof;
use mixed::MixedWorkload;
use oracle::{PaidEffects, root_receipts};
use pruning::PruningProof;
use simulation::SimulationProof;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    FreshBlock,
    BatchThenConfirmation,
    SimulationsThenBatch,
    MixedBlock,
}

impl Delivery {
    fn batched(self) -> bool {
        matches!(
            self,
            Self::BatchThenConfirmation | Self::SimulationsThenBatch
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PopulationConfig {
    active_validators: usize,
    replacements: usize,
    agreements: usize,
    members_per_agreement: usize,
}

impl PopulationConfig {
    fn validate(self) -> Result<Self> {
        ensure!(
            self.active_validators > self.replacements && self.replacements > 0,
            "fixture requires replacements and at least one unchanged reward recipient"
        );
        ensure!(self.agreements > 0 && self.members_per_agreement >= 3);
        self.active_validators
            .checked_add(self.replacements)
            .context("validator population overflow")?;
        self.replacements
            .checked_mul(2)
            .context("transition count overflow")?;
        let storage_calls = self
            .agreements
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .context("storage fixture call count overflow")?;
        u64::try_from(storage_calls).context("storage fixture call count exceeds u64")?;
        Ok(self)
    }
}

#[test]
fn workload_population_configuration_rejects_ambiguous_or_invalid_input() -> Result<()> {
    let valid =
        r#"{"active_validators":16,"replacements":1,"agreements":4,"members_per_agreement":5}"#;
    let config: PopulationConfig = serde_json::from_str(valid)?;
    config.validate()?;
    for invalid in [
        valid.replace("\"replacements\":1", "\"replacements\":0"),
        valid.replace("\"replacements\":1", "\"replacements\":16"),
        valid.replace("\"agreements\":4", "\"agreements\":0"),
        valid.replace("\"members_per_agreement\":5", "\"members_per_agreement\":2"),
    ] {
        ensure!(
            serde_json::from_str::<PopulationConfig>(&invalid)?
                .validate()
                .is_err()
        );
    }
    for invalid in [
        valid.replace("\"agreements\":4", "\"agreements\":4,\"agreements\":5"),
        valid.replace("\"agreements\":4", "\"agreement\":4"),
        valid.replace("\"agreements\":4", "\"agreements\":4,\"extra\":true"),
        valid.replace("\"agreements\":4", "\"agreements\":-1"),
    ] {
        ensure!(serde_json::from_str::<PopulationConfig>(&invalid).is_err());
    }
    ensure!(
        PopulationConfig {
            active_validators: usize::MAX,
            replacements: 1,
            ..config
        }
        .validate()
        .is_err()
    );
    ensure!(
        PopulationConfig {
            agreements: usize::MAX,
            ..config
        }
        .validate()
        .is_err()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; populated development replay, not performance acceptance"]
async fn workload_populated_block_replays_transitions_and_rewards() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::FreshBlock,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; real batch/confirmation replay, not performance acceptance"]
async fn workload_batch_confirmation_preserves_execution_and_charges() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::BatchThenConfirmation,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; simulation rollback then canonical replay, not API load qualification"]
async fn workload_simulations_rollback_before_batch_confirmation() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::SimulationsThenBatch,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind and explicit KONTOR_WORKLOAD_POPULATION JSON; not performance acceptance"]
async fn workload_configured_population_replays_transitions_and_rewards() -> Result<()> {
    let config = serde_json::from_str(
        &std::env::var("KONTOR_WORKLOAD_POPULATION")
            .context("configured replay requires KONTOR_WORKLOAD_POPULATION")?,
    )?;
    replay(config, Delivery::FreshBlock).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; 100 mixed operations in one reveal, not full W_op qualification"]
async fn workload_mixed_operations_preserve_accounting_and_rollback() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::MixedBlock,
    )
    .await
}

async fn replay(config: PopulationConfig, delivery: Delivery) -> Result<()> {
    let config = config.validate()?;
    eprintln!("workload_population={}", serde_json::to_string(&config)?);
    eprintln!("workload_delivery={delivery:?}");
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
    let anchor = BlockHash::from_str(mined.last().context("missing anchor")?)?;
    let validators =
        ValidatorPopulation::new(config.active_validators, config.replacements, [73; 32])?;
    let directory = TempDir::new()?;
    let writer = Writer::new(directory.path(), "source.db").await?;
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
    token::issue_to(
        &mut runtime,
        &core,
        HolderRef::XOnlyPubkey(public_key.to_string()),
        Decimal::from("100"),
    )
    .await??;
    let addresses = ["populateda", "populatedb"].map(|name| ContractAddress {
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
                include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br"),
                &test_provenance()?,
            )
            .await?;
        ensure!(state(&mut runtime, address).await? == [0, 0, 0, 0]);
    }
    let mut cleanup = EngineCleanup::default();
    let history_dir = TempDir::new_in(directory.path())?;
    let mut history = reactor(
        runtime,
        client.clone(),
        history_dir.path(),
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
        if height == 90 {
            let scheduled = validators.schedule(&mut history.runtime).await?;
            ensure!(scheduled.due == SMOKE_HEIGHT);
        }
    }
    StoragePopulation::prepare(
        &mut history.runtime,
        config.agreements,
        config.members_per_agreement,
        [81; 32],
    )
    .await?;
    let payer = get_identity(&history.db_conn(), &public_key.to_string())
        .await?
        .context("missing payer identity")?
        .signer_id();
    let mixed = if delivery == Delivery::MixedBlock {
        Some(MixedWorkload::prepare(&mut history.runtime, payer).await?)
    } else {
        None
    };
    let projection_before = database_projection(&history.db_conn()).await?;
    let pruning = PruningProof::capture(&history.db_conn(), 89, 96).await?;
    let before = oracle::Before::capture(
        &mut history.runtime,
        &validators,
        &public_key.to_string(),
        config,
    )
    .await?;
    ensure!(
        database_projection(&history.db_conn()).await? == projection_before,
        "prestate observations mutated state"
    );
    let snapshot =
        Snapshot::export(&history.db_conn(), &directory.path().join("populated.db")).await?;
    stop_engine(&mut history).await?;
    let (commit, reveal, _) = if let Some(mixed) = &mixed {
        signed_instructions(&client, &key, funding, mixed.instructions()).await?
    } else {
        signed_smoke(&client, &key, funding, &addresses).await?
    };
    let hash = BlockHash::from_str(&client.generate_to_address(1, &address.to_string()).await?[0])?;
    let raw = client.get_block(&hash).await?;
    ensure!(raw.txdata.len() == 3 && raw.txdata[1] == commit && raw.txdata[2] == reveal);
    let block = decode_block(&serialize(&raw), SMOKE_HEIGHT, hash, anchor)?;
    ensure!(block.transactions.len() == 1 && block.transactions[0].index == 2);
    let txid = reveal.compute_txid().to_string();
    let mut expected_projection = None;
    for name in ["first.db", "second.db"] {
        snapshot.copy_to(&directory.path().join(name))?;
        let writer = Writer::new(directory.path(), name).await?;
        ensure!(database_projection(&writer.connection()).await? == projection_before);
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
            Some(anchor),
            true,
            &mut cleanup,
        )
        .await?;
        ensure!(
            database_projection(&trial.db_conn()).await? == projection_before,
            "reactor startup changed restored state"
        );
        let simulations = if delivery == Delivery::SimulationsThenBatch {
            Some(SimulationProof::execute(&mut trial, &reveal).await?)
        } else {
            None
        };
        let batch = if delivery.batched() {
            Some(BatchProof::execute(&mut trial, &reveal).await?)
        } else {
            None
        };
        apply(&mut trial, block.clone()).await?;
        let projection = database_projection(&trial.db_conn()).await?;
        pruning.check(&trial.db_conn()).await?;
        let mut rows = receipts(&trial.db_conn(), SMOKE_HEIGHT).await?;
        if let Some(batch) = batch {
            // Execution remains at the batch anchor. Only confirmation metadata
            // moves to the new block, whose lifecycle still runs exactly once.
            rows.extend(batch.check(&trial).await?);
            rows.sort_by_key(|row| row.id);
        }
        let all_paid: Vec<_> = rows
            .iter()
            .filter(|row| row.txid.as_deref() == Some(&txid))
            .collect();
        ensure!(
            rows.iter()
                .all(|row| row.txid.is_none() || row.txid.as_deref() == Some(&txid))
        );
        let paid = root_receipts(&rows, &txid)?;
        let effects = if let Some(mixed) = &mixed {
            mixed
                .check(&mut trial.runtime, &all_paid, &paid, payer)
                .await?;
            mixed.effects()?
        } else {
            ensure!(paid.len() == 3 && all_paid.len() == 3);
            if let Some(simulations) = simulations {
                simulations.check(&paid)?;
            }
            for (index, row) in paid.iter().enumerate() {
                ensure!(
                    row.height
                        == if delivery.batched() {
                            ANCHOR_HEIGHT
                        } else {
                            SMOKE_HEIGHT
                        }
                );
                // Stored receipt positions currently use the filtered transaction index.
                ensure!(
                    row.tx_index == Some(0)
                        && row.input_index == Some(0)
                        && row.op_index == Some(index as u32)
                        && row.result_index == 0
                );
                ensure!(row.signer_id == payer && row.payer_signer_id == Some(payer));
                ensure!(row.contract == addresses[usize::from(index == 1)].to_string());
                ensure!(
                    row.func
                        == if index == 1 {
                            "scan-compound"
                        } else {
                            "write-result-payload"
                        }
                );
                ensure!(row.gas > 0 && row.gas <= GAS_LIMIT);
            }
            ensure!(
                paid.iter().map(|row| row.status).collect::<Vec<_>>()
                    == [OpStatus::Ok, OpStatus::Other, OpStatus::Ok]
            );
            ensure!(
                paid[0].value.as_deref() == Some("\"é\\n\"")
                    && paid[1].value.is_none()
                    && paid[2].value.as_deref() == Some("\"é\\né\\n\"")
            );
            ensure!(state(&mut trial.runtime, &addresses[0]).await? == [1, 0, 0, 1]);
            ensure!(state(&mut trial.runtime, &addresses[1]).await? == [0, 0, 0, 0]);
            PaidEffects::default()
        };
        before.check(&mut trial, &rows, &txid, &effects).await?;
        ensure!(
            database_projection(&trial.db_conn()).await? == projection,
            "observations mutated state"
        );
        if let Some(expected) = &expected_projection {
            ensure!(&projection == expected, "populated replay differs");
        }
        expected_projection = Some(projection);
        stop_engine(&mut trial).await?;
    }
    ensure!(database_projection(&history.db_conn()).await? == projection_before);
    bitcoin.0.kill().await?;
    eprintln!(
        "workload_population_replays_passed={}",
        serde_json::to_string(&config)?
    );
    Ok(())
}
