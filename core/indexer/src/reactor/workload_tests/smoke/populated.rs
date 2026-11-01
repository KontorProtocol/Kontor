use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::key::Secp256k1;
use bitcoin::{Address, BlockHash, Network, OutPoint};
use indexer_types::{ContractAddress, Inst, OpStatus};
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
use crate::runtime::ownership::OwnerService;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::workload_telemetry::WorkloadTelemetry;
use crate::runtime::{ComponentCache, Decimal, Runtime, Storage, TransactionContext};

mod aggregate_boundary;
mod batch;
mod capacity;
mod challenges;
mod checkpoint;
#[cfg(target_os = "linux")]
mod clock;
mod configuration;
mod files;
mod history;
mod many;
mod measurement;
mod mixed;
mod oracle;
mod pagination;
mod pruning;
mod replay_identity;
mod saved;
mod saved_sequence;
mod sequence_funding;
mod sequence_inputs;
mod shapes;
mod simulation;
mod simulation_requests;
mod timed;
mod views;

use aggregate_boundary::{BoundaryOperation, BoundaryWorkload};
use batch::BatchProof;
use batch::pending::Pending;
use checkpoint::Checkpoint;
use configuration::MixedConfig;
use history::HistoryPopulation;
use measurement::TrialMemory;
use mixed::{MixedLayout, MixedWorkload, Progress};
use oracle::{PaidEffects, root_receipts};
use pruning::PruningProof;
use sequence_inputs::BlockInput;
use shapes::ShapeSigners;
use simulation::SimulationProof;
use simulation_requests::SimulationRequests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    FreshBlock,
    BatchThenConfirmation,
    BatchAfterInterveningBlock,
    SimulationsThenBatch,
    MixedBlock,
    MixedTransactions(usize),
    MixedMultiInput,
    MixedAggregate,
    AggregateBoundary,
    BlockCapacity,
    MaxGasBlock,
    PublicationBlock,
    MixedPagination,
    MixedFiles,
    Configured(MixedConfig),
}

impl Delivery {
    fn full_block(self) -> bool {
        matches!(
            self,
            Self::BlockCapacity | Self::MaxGasBlock | Self::PublicationBlock
        )
    }

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
            Self::BatchThenConfirmation
                | Self::BatchAfterInterveningBlock
                | Self::SimulationsThenBatch
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
#[ignore = "requires local bitcoind; real pending confirmation across an intervening block"]
async fn workload_pending_confirmation_survives_intervening_block() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::BatchAfterInterveningBlock,
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
#[ignore = "requires local bitcoind; actual 10,000-op aggregate diagnostic, not performance acceptance"]
async fn workload_aggregate_operation_limit_preserves_accounting() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::AggregateBoundary,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; full admitted block diagnostic, not performance acceptance"]
async fn workload_full_block_capacity_preserves_accounting() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::BlockCapacity,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; all-max-gas full block diagnostic, not performance acceptance"]
async fn workload_full_block_gas_exhaustion_preserves_accounting() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::MaxGasBlock,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; full publication block diagnostic, not performance acceptance"]
async fn workload_full_publication_block_preserves_accounting() -> Result<()> {
    replay(
        PopulationConfig {
            active_validators: 4,
            replacements: 2,
            agreements: 2,
            members_per_agreement: 3,
        },
        Delivery::PublicationBlock,
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
    replay_steps(config, delivery, 1).await
}

async fn replay_steps(config: PopulationConfig, delivery: Delivery, steps: usize) -> Result<()> {
    ensure!(matches!(steps, 1 | 2 | 6 | 7));
    ensure!(steps == 1 || matches!(delivery, Delivery::Configured(_)));
    let config = config.validate()?;
    let saved = if let Delivery::Configured(mixed) = delivery
        && steps == 1
    {
        saved::Output::from_env(config, mixed)?
    } else {
        None
    };
    let saved_sequence = if let Delivery::Configured(mixed) = delivery
        && steps > 1
    {
        saved_sequence::Output::from_env(config, mixed)?
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
                    delivery.transaction_count().is_some()
                        || delivery == Delivery::MixedMultiInput
                        || delivery.full_block(),
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
    let sequence_fundings = if steps > 1 {
        Some(
            sequence_funding::prepare(
                &client,
                &key,
                &address,
                funding.clone(),
                steps,
                delivery
                    .transaction_count()
                    .context("sequence requires configured transactions")?,
            )
            .await?,
        )
    } else {
        None
    };
    let fundings = if let Some(fundings) = &sequence_fundings {
        fundings[0].clone()
    } else if delivery.full_block() {
        sequence_funding::prepare_groups(
            &client,
            &key,
            &address,
            funding.clone(),
            &[capacity::FUNDING_OUTPUTS],
        )
        .await?
        .pop()
        .context("missing capacity funding group")?
    } else if let Some(count) = delivery.transaction_count() {
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
    let owner_service = OwnerService::new();
    let (_, mut runtime, last_height, last_hash) = create_runtime_executor(
        89,
        &writer,
        &owner_service,
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
            population
                .seed_height(&mut *history.execution.test_runtime().await, height)
                .await?;
        }
        if height == 90 {
            let scheduled = validators
                .schedule(&mut *history.execution.test_runtime().await)
                .await?;
            ensure!(scheduled.due == SMOKE_HEIGHT);
        }
    }
    if let Some(population) = &retained_history {
        population.check(&history.db_conn(), false).await?;
    }
    StoragePopulation::prepare(
        &mut *history.execution.test_runtime().await,
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
        Delivery::MixedMultiInput | Delivery::MixedAggregate | Delivery::AggregateBoundary
    ) {
        Some(
            ShapeSigners::prepare(
                &mut *history.execution.test_runtime().await,
                key,
                delivery != Delivery::MixedMultiInput,
                if delivery == Delivery::AggregateBoundary {
                    10_000
                } else {
                    100
                },
            )
            .await?,
        )
    } else {
        None
    };
    let layout = shape_signers.as_ref().map_or(
        MixedLayout::Single {
            payer,
            operations_per_transaction: if delivery.full_block() {
                1
            } else if delivery.transaction_count().is_some() {
                2
            } else {
                100
            },
        },
        ShapeSigners::layout,
    );
    ensure!(layout.payer() == payer);
    let mixed = if let Some(rounds) = delivery.mixed_rounds() {
        let workload =
            MixedWorkload::prepare(&mut *history.execution.test_runtime().await, payer, rounds)
                .await?;
        let (entries, files) = match delivery {
            Delivery::MixedPagination => (Some(257), 0),
            Delivery::MixedFiles => (Some(257), 5),
            Delivery::Configured(config) => (Some(config.live_keys), config.new_files),
            _ => (None, 0),
        };
        let workload = if let Some(entries) = entries {
            workload
                .with_pagination(
                    &mut *history.execution.test_runtime().await,
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
            workload
                .with_files(&mut *history.execution.test_runtime().await, files)
                .await?
        } else {
            workload
        })
    } else {
        None
    };
    if let Some(mixed) = &mixed {
        eprintln!("workload_operation_mix={}", mixed.operation_counts());
    }
    let counter_boundary = if delivery == Delivery::AggregateBoundary || delivery.full_block() {
        Some(
            BoundaryWorkload::prepare(
                &mut *history.execution.test_runtime().await,
                match delivery {
                    Delivery::MaxGasBlock => BoundaryOperation::ExhaustFuel(addresses[0].clone()),
                    Delivery::PublicationBlock => BoundaryOperation::Publish,
                    _ => BoundaryOperation::Increment,
                },
            )
            .await?,
        )
    } else {
        None
    };
    let projection_before = database_projection(&history.db_conn()).await?;
    let before = oracle::Before::capture(
        &mut *history.execution.test_runtime().await,
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
    let mut workloads = vec![mixed];
    for _ in 1..steps {
        let next = workloads
            .last()
            .and_then(Option::as_ref)
            .context("sequence requires mixed workload")?
            .next_step(layout)?;
        workloads.push(Some(next));
    }
    // Sign simulation alternatives before mining any canonical sequence input.
    // Each step uses its own still-unspent funding output from the initial snapshot.
    let mut simulation_requests = Vec::new();
    for (ordinal, mixed) in workloads.iter().enumerate() {
        simulation_requests.push(
            if let Delivery::Configured(config) = delivery
                && config.simulation_operations > 0
            {
                let funding = sequence_fundings
                    .as_ref()
                    .map_or(&fundings, |all| &all[ordinal]);
                Some(
                    SimulationRequests::prepare(
                        &client,
                        &key,
                        funding
                            .first()
                            .context("missing simulation funding")?
                            .clone(),
                        mixed
                            .as_ref()
                            .context("missing mixed fixture")?
                            .instructions(),
                        config.simulation_operations,
                    )
                    .await?,
                )
            } else {
                None
            },
        );
    }
    let intervening = if delivery == Delivery::BatchAfterInterveningBlock {
        let hash =
            BlockHash::from_str(&client.generate_to_address(1, &address.to_string()).await?[0])?;
        let raw = client.get_block(&hash).await?;
        let block = decode_block(&serialize(&raw), SMOKE_HEIGHT, hash, anchor)?;
        ensure!(block.transactions.is_empty());
        Some(block)
    } else {
        None
    };
    let inputs = if let Some(fundings) = &sequence_fundings {
        let instructions = workloads
            .iter()
            .map(|mixed| {
                Ok(mixed
                    .as_ref()
                    .context("missing sequence workload")?
                    .instructions())
            })
            .collect::<Result<Vec<_>>>()?;
        sequence_inputs::generate(&client, &key, &address, fundings, &instructions).await?
    } else {
        let mixed = &workloads[0];
        let shape_instructions = || -> Result<Vec<Inst>> {
            counter_boundary.as_ref().map_or_else(
                || {
                    Ok(mixed
                        .as_ref()
                        .context("missing mixed fixture")?
                        .instructions())
                },
                |boundary| Ok(boundary.instructions()),
            )
        };
        let (raw, reveals) = if delivery.full_block() {
            capacity::block(
                &client,
                &key,
                &address,
                fundings,
                counter_boundary
                    .as_ref()
                    .context("missing capacity counter")?
                    .instruction(),
            )
            .await?
        } else if let Some(shape_signers) = &shape_signers {
            shape_signers
                .block(&client, fundings, shape_instructions()?)
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
            let hash = BlockHash::from_str(
                &client.generate_to_address(1, &address.to_string()).await?[0],
            )?;
            let raw = client.get_block(&hash).await?;
            ensure!(raw.txdata.len() == 3 && raw.txdata[1] == commit && raw.txdata[2] == reveal);
            (raw, vec![reveal])
        };
        let hash = raw.block_hash();
        let (height, parent) = intervening
            .as_ref()
            .map_or((SMOKE_HEIGHT, anchor), |block| {
                (block.height + 1, block.hash)
            });
        let block = decode_block(&serialize(&raw), height, hash, parent)?;
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
            if delivery.full_block() {
                ensure!(decoded.inputs.len() == 1);
                ensure!(decoded.inputs[0].insts.aggregate.is_none());
                ensure!(decoded.inputs[0].x_only_pubkey == public_key);
                ensure!(
                    decoded.inputs[0].insts.ops
                        == [counter_boundary
                            .as_ref()
                            .context("missing capacity counter")?
                            .instruction()]
                );
            }
            if let Some(shape_signers) = &shape_signers {
                shape_signers.check_inputs(&decoded.inputs, shape_instructions()?)?;
            }
        }
        vec![BlockInput {
            raw: serialize(&raw),
            block,
            reveals,
        }]
    };
    ensure!(inputs.len() == steps && simulation_requests.len() == steps);
    for (input, requests) in inputs.iter().zip(&simulation_requests) {
        if let Some(requests) = requests {
            requests.validate(&input.reveals)?;
        }
    }
    let raw_position = |index: usize| -> Result<u32> {
        Ok(u32::try_from(if delivery == Delivery::MixedMultiInput {
            3
        } else {
            index * 2 + 2
        })?)
    };
    let checkpoint_directory = Checkpoint::directory()?;
    let mut expected_projection: Option<Vec<Checkpoint>> = None;
    for name in ["first.db", "second.db"] {
        snapshot.copy_to(&directory.path().join(name))?;
        let writer = Writer::new(directory.path(), name).await?;
        ensure!(database_projection(&writer.connection()).await? == projection_before);
        let storage = Storage::builder()
            .height(ANCHOR_HEIGHT)
            .conn(writer.connection())
            .build();
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        let telemetry = (counter_boundary.is_some()
            && std::env::var_os("KONTOR_WORKLOAD_TRIAL_MEMORY").is_some())
        .then(|| Arc::new(WorkloadTelemetry::default()));
        runtime.workload_telemetry = telemetry.clone();
        let cache = runtime.component_cache.clone();
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
        let view_config = match delivery {
            Delivery::Configured(config) => Some(config),
            _ => None,
        };
        let mut model = before.clone();
        let mut pending = Pending::new(ANCHOR_HEIGHT);
        let work = async {
            let boundary_measurement = if counter_boundary.is_some() {
                cache.clear();
                ensure!(cache.workload_metrics().await == (0, 0));
                TrialMemory::start(telemetry.clone())?
            } else {
                None
            };
            let mut projections = Vec::new();
            for (ordinal, input) in inputs.iter().enumerate() {
                let mixed = &workloads[ordinal];
                let reveals = &input.reveals;
                let block = &input.block;
                let height = block.height;
                let execution_height = if delivery == Delivery::BatchAfterInterveningBlock {
                    ANCHOR_HEIGHT
                } else if delivery.batched() {
                    height - 1
                } else {
                    height
                };
                let txids: Vec<_> = reveals
                    .iter()
                    .map(|tx| tx.compute_txid().to_string())
                    .collect();
                let pruning =
                    PruningProof::capture(&trial.db_conn(), 89, history::prune_height_at(height))
                        .await?;
                if let Some(requests) = &simulation_requests[ordinal] {
                    let Delivery::Configured(config) = delivery else {
                        unreachable!("simulation requests require configured delivery")
                    };
                    requests
                        .execute(&mut trial, config.warm_simulation_cache)
                        .await?;
                }
                let simulations = if delivery == Delivery::SimulationsThenBatch {
                    Some(SimulationProof::execute(&mut trial, &reveals[0]).await?)
                } else {
                    None
                };
                let batches = match delivery {
                    Delivery::Configured(config) if config.batch_operations > 0 => {
                        Progress::new(
                            mixed.as_ref().context("missing mixed batch recipe")?,
                            layout,
                            &txids,
                        )?
                        .execute_chunks(
                            &mut trial,
                            reveals,
                            config.batch_operations,
                            checkpoint_directory.path(),
                            &mut model,
                        )
                        .await?
                    }
                    _ if delivery.batched() => {
                        vec![
                            BatchProof::execute(
                                &mut trial,
                                &reveals[0],
                                checkpoint_directory.path(),
                            )
                            .await?,
                        ]
                    }
                    _ => Vec::new(),
                };
                for batch in &batches {
                    Checkpoint::record(
                        &mut projections,
                        batch.checkpoint().clone(),
                        expected_projection.as_deref(),
                    )?;
                }
                for batch in batches {
                    let plan = batch.confirmation_plan(block)?;
                    pending.record(batch, plan)?;
                }
                pending.check_unconfirmed(&trial).await?;
                if delivery.batched()
                    && !matches!(delivery,
                    Delivery::Configured(config) if config.batch_operations > 0)
                {
                    let effects = mixed
                        .as_ref()
                        .map(|mixed| mixed.effects(layout))
                        .transpose()?
                        .unwrap_or_default();
                    let anchor_rows =
                        receipts(&trial.db_conn(), trial.execution.last_height).await?;
                    let before_checks = database_projection(&trial.db_conn()).await?;
                    model = model
                        .check_batch(&mut trial, &anchor_rows, &txids, &effects)
                        .await?;
                    let duplicate = model
                        .check_batch(&mut trial, &anchor_rows, &txids, &effects)
                        .await
                        .err()
                        .context("batch accounting accepted a duplicate charge")?;
                    ensure!(duplicate.to_string() == "paid execution payer balance mismatch");
                    ensure!(database_projection(&trial.db_conn()).await? == before_checks);
                }
                if let Some(intervening) = &intervening {
                    let outstanding = pending.len();
                    ensure!(outstanding == txids.len());
                    apply(&mut trial, intervening.clone()).await?;
                    trial.advance().await?;
                    let gap_projection = database_projection(&trial.db_conn()).await?;
                    ensure!(pending.check_block(&trial, intervening).await?.is_empty());
                    ensure!(pending.len() == outstanding);
                    let gap_rows = receipts(&trial.db_conn(), intervening.height).await?;
                    model = model.check_lifecycle(&mut trial, &gap_rows).await?;
                    ensure!(database_projection(&trial.db_conn()).await? == gap_projection);
                    Checkpoint::record(
                        &mut projections,
                        Checkpoint::capture(checkpoint_directory.path(), &gap_projection)?,
                        expected_projection.as_deref(),
                    )?;
                    eprintln!(
                        "workload_pending_intervening_block={}",
                        serde_json::json!({"trial":name,"height":intervening.height,"pending":pending.len()})
                    );
                }
                let service_started = Instant::now();
                apply(&mut trial, block.clone()).await?;
                if counter_boundary.is_some() {
                    eprintln!(
                        "workload_boundary_service={}",
                        serde_json::json!({
                            "restore": name, "delivery": format!("{delivery:?}"),
                            "height": height, "elapsed_ns": service_started.elapsed().as_nanos(),
                            "scope": "canonical block execution and lifecycle; fixture setup and semantic oracle excluded"
                        })
                    );
                }
                if intervening.is_some() {
                    trial.advance().await?;
                }
                let projection = database_projection(&trial.db_conn()).await?;
                if intervening.is_some() {
                    let mut unknown = Pending::new(block.height - 1);
                    let error = unknown
                        .check_block(&trial, block)
                        .await
                        .err()
                        .context("untracked batch confirmation was accepted")?;
                    ensure!(error.to_string() == "untracked batch confirmation");
                    let mut omitted = block.clone();
                    omitted.transactions.clear();
                    let mut duplicate = block.clone();
                    duplicate.transactions.push(block.transactions[0].clone());
                    let mut wrong_position = block.clone();
                    wrong_position.transactions[0].index += 1;
                    for (changed, expected_error) in [
                        (omitted, "pending confirmation missing or at wrong position"),
                        (duplicate, "duplicate confirmation in block"),
                        (
                            wrong_position,
                            "pending confirmation missing or at wrong position",
                        ),
                    ] {
                        let mut control = pending.clone();
                        let error = control
                            .check_block(&trial, &changed)
                            .await
                            .err()
                            .context("invalid pending confirmation was accepted")?;
                        ensure!(error.to_string() == expected_error);
                        ensure!(control.len() == pending.len());
                    }
                }
                let confirmed_rows = pending.check_block(&trial, block).await?;
                ensure!(pending.len() == 0);
                for (index, txid) in txids.iter().enumerate() {
                    let transaction = get_transaction_by_txid(&trial.db_conn(), txid)
                        .await?
                        .context("missing workload transaction")?;
                    ensure!(
                        transaction.confirmed_height == Some(height)
                            && transaction.tx_index == Some(u32::try_from(index)?)
                            && get_confirmation_position(&trial.db_conn(), txid).await?
                                == Some(raw_position(index)?),
                        "wrong persisted confirmation position for workload transaction {index}"
                    );
                    ensure!(transaction.height == execution_height);
                    if !delivery.batched() {
                        ensure!(transaction.batch_height.is_none());
                    }
                }
                pruning.check(&trial.db_conn()).await?;
                if let Some(population) = &retained_history {
                    population
                        .check_at(&trial.db_conn(), Some(history::prune_height_at(height)))
                        .await?;
                }
                let mut rows = receipts(&trial.db_conn(), height).await?;
                rows.extend(confirmed_rows);
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
                let effects = if let Some(boundary) = &counter_boundary {
                    ensure!(all_paid.len() == paid.len());
                    boundary
                        .check(
                            &mut *trial.execution.test_runtime().await,
                            &paid,
                            layout,
                            execution_height,
                            if delivery.full_block() {
                                txids.len()
                            } else {
                                10_000
                            },
                        )
                        .await?;
                    if let Some(signers) = &shape_signers {
                        signers
                            .check_counter(&mut *trial.execution.test_runtime().await)
                            .await?;
                    }
                    PaidEffects::default()
                } else if let Some(mixed) = &mixed {
                    mixed
                        .check(
                            &mut *trial.execution.test_runtime().await,
                            &all_paid,
                            &paid,
                            layout,
                            execution_height,
                        )
                        .await?;
                    mixed
                        .check_file_lifecycle(&mut *trial.execution.test_runtime().await, &rows)
                        .await?;
                    if let Some(shape_signers) = &shape_signers {
                        shape_signers
                            .check(&mut *trial.execution.test_runtime().await, mixed)
                            .await?;
                    }
                    mixed.effects(layout)?
                } else {
                    ensure!(paid.len() == 3 && all_paid.len() == 3);
                    if let Some(simulations) = simulations {
                        simulations.check(&paid)?;
                    }
                    for (index, row) in paid.iter().enumerate() {
                        ensure!(row.height == execution_height);
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
                    ensure!(
                        state(&mut *trial.execution.test_runtime().await, &addresses[0]).await?
                            == [1, 0, 0, 1]
                    );
                    ensure!(
                        state(&mut *trial.execution.test_runtime().await, &addresses[1]).await?
                            == [0, 0, 0, 0]
                    );
                    PaidEffects::default()
                };
                model = if delivery.batched() {
                    model.check_lifecycle(&mut trial, &rows).await?
                } else {
                    model.check(&mut trial, &rows, &txids, &effects).await?
                };
                ensure!(
                    database_projection(&trial.db_conn()).await? == projection,
                    "observations mutated state"
                );
                Checkpoint::record(
                    &mut projections,
                    Checkpoint::capture(checkpoint_directory.path(), &projection)?,
                    expected_projection.as_deref(),
                )?;
                eprintln!(
                    "workload_sequence_step_passed={}",
                    serde_json::json!({"trial":name,"ordinal":ordinal,"height":height,"hash":block.hash,"transactions":txids.len()})
                );
            }
            if counter_boundary.is_some() {
                eprintln!(
                    "workload_replay_cache={}",
                    serde_json::json!({
                        "restore": name, "before": [0, 0], "after": cache.workload_metrics().await,
                        "metric": "entry count and encoded-byte weight; not compiled code bytes",
                        "warm_simulation_cache": false
                    })
                );
            }
            if let Some(measurement) = boundary_measurement {
                measurement.finish(name, false)?;
            }
            Ok(projections)
        };
        let projections = if let Some(boundary) = &counter_boundary {
            let operations = if delivery.full_block() {
                inputs[0].reveals.len()
            } else {
                10_000
            };
            boundary
                .run_with_views(
                    directory.path(),
                    name,
                    &projection_before,
                    operations,
                    telemetry.clone(),
                    work,
                )
                .await?
        } else {
            views::run_steps(
                directory.path(),
                name,
                view_config,
                &projection_before,
                steps,
                work,
            )
            .await?
        };
        if let Some(expected) = &expected_projection {
            ensure!(
                projections.len() == expected.len(),
                "populated replay checkpoint counts differ"
            );
        }
        expected_projection = Some(projections);
        if let Some(telemetry) = telemetry {
            let drained = telemetry.snapshot();
            ensure!(
                drained.live_roots == 0 && drained.live_stores == 0,
                "boundary workload left invocation Stores alive after draining views"
            );
            eprintln!(
                "workload_drained_stores={}",
                serde_json::json!({"restore":name,"snapshot":drained})
            );
        }
        stop_engine(&mut trial).await?;
    }
    ensure!(database_projection(&history.db_conn()).await? == projection_before);
    if let Some(saved) = saved {
        saved
            .write(
                &snapshot,
                &client,
                &deserialize(&inputs[0].raw)?,
                &projection_before,
                &expected_projection
                    .as_ref()
                    .and_then(|checkpoints| checkpoints.last())
                    .context("missing final projection")?
                    .load()?,
                simulation_requests[0].as_ref(),
            )
            .await?;
    }
    if let Some(saved) = saved_sequence {
        saved
            .write(
                &snapshot,
                &client,
                &inputs,
                &projection_before,
                expected_projection
                    .as_deref()
                    .context("missing sequence checkpoints")?,
                &simulation_requests,
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
