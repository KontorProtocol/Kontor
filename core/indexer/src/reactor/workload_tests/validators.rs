use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use indexer_types::BlockRow;
use sha2::{Digest, Sha256, Sha512};
use tempfile::TempDir;

use super::Snapshot;
use crate::bls::taproot_derivation_path;
use crate::consensus::signing::PrivateKey;
use crate::database::Writer;
use crate::database::queries::{get_contract_signer_id, insert_block};
use crate::reg_tester::derive_taproot_keypair_from_seed;
use crate::runtime::fuel::ExecutionUsage;
use crate::runtime::numerics::{add_decimal, mul_decimal, sub_decimal};
use crate::runtime::staking::api::ValidatorStatus;
use crate::runtime::staking::{address, api};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ComponentCache, Decimal, GenesisParameters, GenesisValidator, Runtime, Storage,
};
use crate::test_utils::{new_mock_block_hash, test_runtime_with_genesis_config};

pub(super) struct Population {
    pub(super) genesis: GenesisParameters,
    incoming: Vec<GenesisValidator>,
}

pub(super) struct Scheduled {
    pub(super) due: u64,
    liquid: BTreeMap<String, Decimal>,
    supply: Decimal,
    burner: Decimal,
}

fn core() -> Signer {
    Signer::Core(Box::new(Signer::Nobody))
}

pub(super) fn execution_fee(runtime: &Runtime, usage: ExecutionUsage) -> Result<Decimal> {
    ensure!(runtime.gas_to_fuel_multiplier == 1000 && usage.deposit_fuel % 1000 == 0);
    let reserved = usage.deposit_fuel / 1000;
    let gas = usage
        .user_fuel
        .checked_add(usage.deposit_fuel)
        .context("fuel overflow")?
        .div_ceil(1000)
        .max(1);
    let charged = gas
        .checked_sub(reserved)
        .context("reservation exceeds gas")?;
    let fee = mul_decimal(Decimal::try_from(charged)?, Decimal::from("0.000000001"))?;
    ensure!(runtime.pricing.execution_fee(charged)? == fee);
    Ok(fee)
}

impl Population {
    pub(super) fn members(&self) -> impl Iterator<Item = &GenesisValidator> {
        self.genesis.validators.iter().chain(&self.incoming)
    }

    pub(super) fn new(active: usize, replacements: usize, seed: [u8; 32]) -> Result<Self> {
        ensure!(
            active > 0 && replacements <= active,
            "invalid fixture population"
        );
        let count = active
            .checked_add(replacements)
            .context("fixture count overflow")?;
        let mut members = Vec::with_capacity(count);
        for index in 0..count {
            let index = u64::try_from(index)?.to_be_bytes();
            let mut bitcoin_seed = Sha512::new();
            bitcoin_seed.update(b"kontor-workload-bitcoin-validator-v1");
            bitcoin_seed.update(seed);
            bitcoin_seed.update(index);
            let bitcoin_seed: [u8; 64] = bitcoin_seed.finalize().into();
            let public_key = derive_taproot_keypair_from_seed(
                &bitcoin_seed,
                &taproot_derivation_path(Network::Regtest),
            )?
            .x_only_public_key()
            .0;
            let mut consensus_seed = Sha256::new();
            consensus_seed.update(b"kontor-workload-consensus-validator-v1");
            consensus_seed.update(seed);
            consensus_seed.update(index);
            let consensus_seed: [u8; 32] = consensus_seed.finalize().into();
            members.push(GenesisValidator {
                x_only_pubkey: public_key.to_string(),
                ed25519_pubkey: PrivateKey::from(consensus_seed)
                    .public_key()
                    .as_bytes()
                    .to_vec(),
                stake: Decimal::from("100"),
            });
        }
        ensure!(
            members
                .iter()
                .map(|member| &member.x_only_pubkey)
                .collect::<BTreeSet<_>>()
                .len()
                == count
        );
        ensure!(
            members
                .iter()
                .map(|member| &member.ed25519_pubkey)
                .collect::<BTreeSet<_>>()
                .len()
                == count
        );
        let incoming = members.split_off(active);
        Ok(Self {
            genesis: GenesisParameters {
                sigma_min: Decimal::from("1"),
                validators: members,
            },
            incoming,
        })
    }

    async fn signer(runtime: &mut Runtime, member: &GenesisValidator) -> Result<Signer> {
        Ok(Signer::Id(
            runtime
                .get_or_create_identity(&member.x_only_pubkey)
                .await?,
        ))
    }

    pub(super) async fn schedule(&self, runtime: &mut Runtime) -> Result<Scheduled> {
        ensure!(
            !self.incoming.is_empty(),
            "transition fixture requires replacements"
        );
        let mut due = None;
        let mut liquid = BTreeMap::new();
        let mut supply = token::total_supply(runtime).await?;
        let mut burner = token::balance(runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        let headroom = Decimal::from("1");
        for (outgoing, incoming) in self.genesis.validators.iter().zip(&self.incoming) {
            let outgoing = Self::signer(runtime, outgoing).await?;
            let holder = HolderRef::from(&outgoing);
            let before = token::balance(runtime, holder.clone())
                .await?
                .unwrap_or_default();
            token::issue_to(runtime, &core(), holder.clone(), headroom).await??;
            supply = add_decimal(supply, headroom)?;
            let previous = runtime.start_usage();
            let result = api::leave_validation(runtime, &outgoing).await;
            let usage = runtime.finish_usage(previous)?;
            let exit = result??;
            let fee = execution_fee(runtime, usage)?;
            supply = sub_decimal(supply, fee)?;
            burner = add_decimal(burner, fee)?;
            liquid.insert(
                holder.to_string(),
                sub_decimal(add_decimal(before, headroom)?, fee)?,
            );
            ensure!(exit.status == ValidatorStatus::PendingExit);
            let signer = Self::signer(runtime, incoming).await?;
            let holder = HolderRef::from(&signer);
            let before = token::balance(runtime, holder.clone())
                .await?
                .unwrap_or_default();
            let funding = add_decimal(incoming.stake, headroom)?;
            token::issue_to(runtime, &core(), holder.clone(), funding).await??;
            supply = add_decimal(supply, funding)?;
            let previous = runtime.start_usage();
            let result = api::register_validator(
                runtime,
                &signer,
                incoming.ed25519_pubkey.clone(),
                incoming.stake,
            )
            .await;
            let usage = runtime.finish_usage(previous)?;
            let join = result??;
            let fee = execution_fee(runtime, usage)?;
            supply = sub_decimal(supply, fee)?;
            burner = add_decimal(burner, fee)?;
            liquid.insert(
                holder.to_string(),
                sub_decimal(add_decimal(before, headroom)?, fee)?,
            );
            ensure!(
                join.status == ValidatorStatus::PendingJoin
                    && join.activation_height == exit.deactivation_height
            );
            ensure!(join.activation_height > runtime.storage.height);
            if let Some(expected) = due {
                ensure!(
                    expected == join.activation_height,
                    "transition heights differ"
                );
            }
            due = Some(join.activation_height);
        }
        Ok(Scheduled {
            due: due.context("no scheduled transition")?,
            liquid,
            supply,
            burner,
        })
    }

    async fn check(
        &self,
        runtime: &mut Runtime,
        scheduled: &Scheduled,
        transitioned: bool,
    ) -> Result<()> {
        let mut expected_active = Vec::new();
        let mut liquid_total = Decimal::default();
        for (index, member) in self
            .genesis
            .validators
            .iter()
            .chain(&self.incoming)
            .enumerate()
        {
            let signer = Self::signer(runtime, member).await?;
            let validator = api::get_validator(runtime, &signer)
                .await?
                .context("missing fixture validator")?;
            let incoming = index >= self.genesis.validators.len();
            let outgoing = index < self.incoming.len();
            let expected = match (transitioned, incoming, outgoing) {
                (false, true, _) => ValidatorStatus::PendingJoin,
                (false, false, true) => ValidatorStatus::PendingExit,
                (true, false, true) => ValidatorStatus::Inactive,
                _ => ValidatorStatus::Active,
            };
            ensure!(
                validator.status == expected
                    && validator.stake == member.stake
                    && validator.ed25519_pubkey == member.ed25519_pubkey,
                "fixture validator state differs"
            );
            if matches!(
                expected,
                ValidatorStatus::Active | ValidatorStatus::PendingExit
            ) {
                expected_active.push((
                    HolderRef::from(&signer).to_string(),
                    member.stake,
                    member.ed25519_pubkey.clone(),
                ));
            }
            let holder = HolderRef::from(&signer);
            let liquid = token::balance(runtime, holder.clone())
                .await?
                .unwrap_or_default();
            ensure!(
                liquid
                    == scheduled
                        .liquid
                        .get(&holder.to_string())
                        .copied()
                        .unwrap_or_default(),
                "transition liquid balance differs from independent fee calculation"
            );
            ensure!(liquid >= token::floor(runtime, holder).await?);
            liquid_total = add_decimal(liquid_total, liquid)?;
        }
        let active = api::get_active_set(runtime).await?;
        ensure!(active.len() == self.genesis.validators.len());
        expected_active.sort_by(|left, right| left.0.cmp(&right.0));
        ensure!(
            active
                .iter()
                .map(|member| (
                    member.x_only_pubkey.clone(),
                    member.stake,
                    member.ed25519_pubkey.clone()
                ))
                .collect::<Vec<_>>()
                == expected_active,
            "active covering index or canonical order differs"
        );
        let info = api::get_staking_info(runtime).await?;
        let expected_stake = mul_decimal(
            Decimal::try_from(u64::try_from(active.len())?)?,
            Decimal::from("100"),
        )?;
        ensure!(info.active_count == active.len() as u64 && info.total_stake == expected_stake);
        // Exiting validation leaves the bond in escrow. Replacements add bonds
        // without inflating the active population, so escrow exceeds active stake.
        let bonds = u64::try_from(self.genesis.validators.len() + self.incoming.len())?;
        let bonded = mul_decimal(Decimal::try_from(bonds)?, Decimal::from("100"))?;
        let contract = runtime
            .storage
            .contract_id(&address())
            .await?
            .context("missing staking contract")?;
        let escrow = get_contract_signer_id(&runtime.get_storage_conn(), contract)
            .await?
            .context("missing staking signer")?;
        ensure!(token::balance(runtime, HolderRef::SignerId(escrow)).await? == Some(bonded));
        ensure!(token::total_supply(runtime).await? == scheduled.supply);
        ensure!(
            token::balance(runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default()
                == scheduled.burner
        );
        // The burner ledger records retired tokens, excluded from total supply.
        ensure!(add_decimal(bonded, liquid_total)? == scheduled.supply);
        Ok(())
    }
}

async fn at_height(runtime: &mut Runtime, height: u64) -> Result<()> {
    insert_block(
        &runtime.get_storage_conn(),
        BlockRow::builder()
            .height(height)
            .hash(new_mock_block_hash(u32::try_from(height)?))
            .relevant(true)
            .build(),
    )
    .await?;
    runtime.set_context(height, None, None, None).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workload_validator_population_restores_due_transitions() -> Result<()> {
    let population = Population::new(4, 2, [73; 32])?;
    let (mut runtime, _source_dir, _source_name) =
        test_runtime_with_genesis_config(&population.genesis, Network::Regtest).await?;
    runtime.set_context(1, None, None, None).await;
    let scheduled = population.schedule(&mut runtime).await?;
    let due = scheduled.due;
    population.check(&mut runtime, &scheduled, false).await?;
    let directory = TempDir::new()?;
    let snapshot = Snapshot::export(
        &runtime.get_storage_conn(),
        &directory.path().join("pending.db"),
    )
    .await?;
    for name in ["first.db", "second.db"] {
        snapshot.copy_to(&directory.path().join(name))?;
        let writer = Writer::new(directory.path(), name).await?;
        let storage = Storage::builder()
            .height(1)
            .conn(writer.connection())
            .build();
        let mut restored = Runtime::new(ComponentCache::new(), storage).await?;
        restored.network = Network::Regtest;
        population.check(&mut restored, &scheduled, false).await?;
        at_height(&mut restored, due - 1).await?;
        let early = api::process_pending_validators(&mut restored, &core(), due - 1).await??;
        ensure!((early.activated, early.deactivated) == (0, 0));
        population.check(&mut restored, &scheduled, false).await?;
        at_height(&mut restored, due).await?;
        let change = api::process_pending_validators(&mut restored, &core(), due).await??;
        ensure!((change.activated, change.deactivated) == (2, 2));
        population.check(&mut restored, &scheduled, true).await?;
        let repeated = api::process_pending_validators(&mut restored, &core(), due).await??;
        ensure!((repeated.activated, repeated.deactivated) == (0, 0));
        population.check(&mut restored, &scheduled, true).await?;
    }
    population.check(&mut runtime, &scheduled, false).await?;
    Ok(())
}
