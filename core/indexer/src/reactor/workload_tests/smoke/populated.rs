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
use crate::database::confirmation::get_confirmation_position;
use crate::database::queries::{get_identity, get_transaction_by_txid};
use crate::reactor::create_runtime_executor;
use crate::reg_tester::{derive_taproot_keypair_from_seed, workload_bitcoin};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ComponentCache, Decimal, Runtime, Storage, TransactionContext};

mod batch;
mod configuration;
mod files;
mod history;
mod many;
mod mixed;
mod oracle;
mod pagination;
mod pruning;
mod saved;
mod shapes;
mod simulation;

use batch::BatchProof;
use configuration::MixedConfig;
use history::HistoryPopulation;
use mixed::{MixedLayout, MixedWorkload};
use oracle::{PaidEffects, root_receipts};
use pruning::PruningProof;
use shapes::ShapeSigners;
use simulation::SimulationProof;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    FreshBlock,
    BatchThenConfirmation,
    SimulationsThenBatch,
    MixedBlock,
    MixedTransactions(usize),
    MixedMultiInput,
    MixedAggregate,
    MixedPagination,
    MixedFiles,
    Configured(MixedConfig),
}

impl Delivery {
    fn mixed_rounds(self) -> Option<usize> {
        match self {
            Self::MixedBlock
            | Self::MixedMultiInput
            | Self::MixedAggregate
            | Self::MixedPagination
            | Self::MixedFiles => Some(5),
            Self::MixedTransactions(count) => Some(count / 10),
            Self::Configured(config) => Some(config.transactions / 10),
            _ => None,
        }
    }

    fn transaction_count(self) -> Option<usize> {
        match self {
            Self::MixedTransactions(count) => Some(count),
            Self::Configured(config) => Some(config.transactions),
            _ => None,
        }
    }

    fn batched(self) -> bool {
        matches!(
            self,
            Self::BatchThenConfirmation | Self::SimulationsThenBatch
        ) || matches!(self, Self::Configured(config) if config.batch_operations > 0)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; 50 real signed reveals, not performance acceptance"]
async fn workload_fifty_transactions_preserve_mixed_accounting() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::MixedTransactions(50),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; 500 real signed reveals, not performance acceptance"]
async fn workload_five_hundred_transactions_preserve_mixed_accounting() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::MixedTransactions(500),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; signed multi-input mixed workload, not performance acceptance"]
async fn workload_multi_input_preserves_signers_and_sponsorship() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::MixedMultiInput,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; signed BLS mixed workload, not performance acceptance"]
async fn workload_aggregate_preserves_signers_and_nonces() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::MixedAggregate,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; bounded storage cursor replay, not full W_op qualification"]
async fn workload_pagination_preserves_order_and_boundaries() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::MixedPagination,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; signed file creation and registry append, not full W_op qualification"]
async fn workload_signed_files_preserve_registry_and_accounting() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::MixedFiles,
    )
    .await
}

async fn replay(config: PopulationConfig, delivery: Delivery) -> Result<()> {
    let config = config.validate()?;
    let saved = if let Delivery::Configured(mixed) = delivery {
        saved::Output::from_env(config, mixed)?
    } else {
        None
    };
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
        .generate_to_address(
            ANCHOR_HEIGHT
                - u64::from(
                    delivery.transaction_count().is_some() || delivery == Delivery::MixedMultiInput,
                ),
            &address.to_string(),
        )
        .await?;
    let funding_block = client.get_block(&BlockHash::from_str(&mined[0])?).await?;
    let funding = (
        OutPoint {
            txid: funding_block.txdata[0].compute_txid(),
            vout: 0,
        },
        funding_block.txdata[0].output[0].clone(),
    );
    let fundings = if let Some(count) = delivery.transaction_count() {
        many::fund(&client, &key, &address, funding.clone(), count).await?
    } else if delivery == Delivery::MixedMultiInput {
        many::fund_to(
            &client,
            &key,
            &address,
            funding.clone(),
            &[address.clone(), shapes::address(&shapes::secondary_key()?)],
        )
        .await?
    } else {
        vec![funding.clone()]
    };
    let anchor = client.get_block_hash(ANCHOR_HEIGHT).await?;
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
    let retained_history = if let Delivery::Configured(mixed) = delivery {
        HistoryPopulation::prepare(&mut runtime, mixed).await?
    } else {
        None
    };
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
        if let Some(population) = &retained_history {
            population.seed_height(&mut history.runtime, height).await?;
        }
        if height == 90 {
            let scheduled = validators.schedule(&mut history.runtime).await?;
            ensure!(scheduled.due == SMOKE_HEIGHT);
        }
    }
    if let Some(population) = &retained_history {
        population.check(&history.db_conn(), false).await?;
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
    let shape_signers = if matches!(
        delivery,
        Delivery::MixedMultiInput | Delivery::MixedAggregate
    ) {
        Some(
            ShapeSigners::prepare(
                &mut history.runtime,
                key,
                delivery == Delivery::MixedAggregate,
            )
            .await?,
        )
    } else {
        None
    };
    let layout = shape_signers.as_ref().map_or(
        MixedLayout::Single {
            payer,
            operations_per_transaction: if delivery.transaction_count().is_some() {
                2
            } else {
                100
            },
        },
        ShapeSigners::layout,
    );
    ensure!(layout.payer() == payer);
    let mixed = if let Some(rounds) = delivery.mixed_rounds() {
        let workload = MixedWorkload::prepare(&mut history.runtime, payer, rounds).await?;
        let (entries, files) = match delivery {
            Delivery::MixedPagination => (Some(257), 0),
            Delivery::MixedFiles => (Some(257), 5),
            Delivery::Configured(config) => (Some(config.live_keys), config.new_files),
            _ => (None, 0),
        };
        let workload = if let Some(entries) = entries {
            workload
                .with_pagination(
                    &mut history.runtime,
                    entries,
                    retained_history
                        .as_ref()
                        .map(|population| population.contract.clone()),
                )
                .await?
        } else {
            workload
        };
        Some(if files > 0 {
            workload.with_files(&mut history.runtime, files).await?
        } else {
            workload
        })
    } else {
        None
    };
    if let Some(mixed) = &mixed {
        eprintln!("workload_operation_mix={}", mixed.operation_counts());
    }
    let projection_before = database_projection(&history.db_conn()).await?;
    let pruning = PruningProof::capture(&history.db_conn(), 89, history::prune_height()).await?;
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
    let (raw, reveals) = if let Some(shape_signers) = &shape_signers {
        shape_signers
            .block(
                &client,
                fundings,
                mixed
                    .as_ref()
                    .context("missing mixed fixture")?
                    .instructions(),
            )
            .await?
    } else if delivery.transaction_count().is_some() {
        many::block(
            &client,
            &key,
            &address,
            fundings,
            mixed
                .as_ref()
                .context("missing mixed fixture")?
                .instructions(),
        )
        .await?
    } else {
        let (commit, reveal, _) = if let Some(mixed) = &mixed {
            signed_instructions(&client, &key, funding, mixed.instructions()).await?
        } else {
            signed_smoke(&client, &key, funding, &addresses).await?
        };
        let hash =
            BlockHash::from_str(&client.generate_to_address(1, &address.to_string()).await?[0])?;
        let raw = client.get_block(&hash).await?;
        ensure!(raw.txdata.len() == 3 && raw.txdata[1] == commit && raw.txdata[2] == reveal);
        (raw, vec![reveal])
    };
    let hash = raw.block_hash();
    let block = decode_block(&serialize(&raw), SMOKE_HEIGHT, hash, anchor)?;
    ensure!(block.transactions.len() == reveals.len());
    let raw_position = |index: usize| -> Result<u32> {
        Ok(u32::try_from(if delivery == Delivery::MixedMultiInput {
            3
        } else {
            index * 2 + 2
        })?)
    };
    for (index, (decoded, reveal)) in block.transactions.iter().zip(&reveals).enumerate() {
        ensure!(decoded.index == raw_position(index)? && decoded.txid == reveal.compute_txid());
        if delivery.transaction_count().is_some() {
            ensure!(decoded.inputs.len() == 1 && decoded.inputs[0].insts.ops.len() == 2);
        }
        if let Some(shape_signers) = &shape_signers {
            shape_signers.check_inputs(
                &decoded.inputs,
                mixed
                    .as_ref()
                    .context("missing mixed fixture")?
                    .instructions(),
            )?;
        }
    }
    let txids: Vec<_> = reveals
        .iter()
        .map(|tx| tx.compute_txid().to_string())
        .collect();
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
            Some(SimulationProof::execute(&mut trial, &reveals[0]).await?)
        } else {
            None
        };
        let batches = match delivery {
            Delivery::Configured(config) if config.batch_operations > 0 => {
                BatchProof::execute_chunks(&mut trial, &reveals, config.batch_operations).await?
            }
            _ if delivery.batched() => vec![BatchProof::execute(&mut trial, &reveals[0]).await?],
            _ => Vec::new(),
        };
        apply(&mut trial, block.clone()).await?;
        let projection = database_projection(&trial.db_conn()).await?;
        for (index, txid) in txids.iter().enumerate() {
            let transaction = get_transaction_by_txid(&trial.db_conn(), txid)
                .await?
                .context("missing workload transaction")?;
            ensure!(
                transaction.confirmed_height == Some(SMOKE_HEIGHT)
                    && transaction.tx_index == Some(u32::try_from(index)?)
                    && get_confirmation_position(&trial.db_conn(), txid).await?
                        == Some(raw_position(index)?),
                "wrong persisted confirmation position for workload transaction {index}"
            );
            ensure!(
                transaction.height
                    == if delivery.batched() {
                        ANCHOR_HEIGHT
                    } else {
                        SMOKE_HEIGHT
                    }
            );
            if !delivery.batched() {
                ensure!(transaction.batch_height.is_none());
            }
        }
        pruning.check(&trial.db_conn()).await?;
        if let Some(population) = &retained_history {
            population.check(&trial.db_conn(), true).await?;
        }
        let mut rows = receipts(&trial.db_conn(), SMOKE_HEIGHT).await?;
        for batch in batches {
            // Execution remains at the batch anchor. Only confirmation metadata
            // moves to the new block, whose lifecycle still runs exactly once.
            rows.extend(batch.check(&trial).await?);
        }
        rows.sort_by_key(|row| row.id);
        let all_paid: Vec<_> = rows
            .iter()
            .filter(|row| row.txid.as_ref().is_some_and(|txid| txids.contains(txid)))
            .collect();
        ensure!(
            rows.iter()
                .all(|row| row.txid.as_ref().is_none_or(|txid| txids.contains(txid)))
        );
        let mut paid = Vec::new();
        for txid in &txids {
            paid.extend(root_receipts(&rows, txid)?);
        }
        let effects = if let Some(mixed) = &mixed {
            mixed
                .check(
                    &mut trial.runtime,
                    &all_paid,
                    &paid,
                    layout,
                    if delivery.batched() {
                        ANCHOR_HEIGHT
                    } else {
                        SMOKE_HEIGHT
                    },
                )
                .await?;
            mixed
                .check_file_lifecycle(&mut trial.runtime, &rows)
                .await?;
            if let Some(shape_signers) = &shape_signers {
                shape_signers.check(&mut trial.runtime, mixed).await?;
            }
            mixed.effects(layout)?
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
        before.check(&mut trial, &rows, &txids, &effects).await?;
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
    if let Some(saved) = saved {
        saved
            .write(
                &snapshot,
                &client,
                &raw,
                &projection_before,
                expected_projection
                    .as_ref()
                    .context("missing final projection")?,
            )
            .await?;
    }
    bitcoin.0.kill().await?;
    eprintln!(
        "workload_population_replays_passed={}",
        serde_json::to_string(&config)?
    );
    Ok(())
}
