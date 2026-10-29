use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use indexer_types::ResultRow;
use libsql::params;
use num::BigInt;

use super::super::accounting::{balance, escrow, lifecycle_value};
use super::PopulationConfig;
use crate::database::queries::get_identity;
use crate::reactor::Reactor;
use crate::reactor::executor::RuntimeExecutor;
use crate::reactor::workload_tests::validators::Population;
use crate::runtime::filestorage::{address as storage_address, api as files};
use crate::runtime::numerics::{add_decimal, div_decimal, mul_decimal, sub_decimal};
use crate::runtime::staking::api::{ValidatorInfo, ValidatorStatus};
use crate::runtime::staking::{address as staking_address, api as staking};
use crate::runtime::token::{address as token_address, api as token};
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Runtime};

struct Host {
    weight: BigInt,
    liquid: Decimal,
    bond: Decimal,
    reservation: Decimal,
}

#[derive(Default)]
pub(super) struct PaidEffects {
    pub(super) transferred: Decimal,
    pub(super) staked: Decimal,
}

pub(super) fn root_receipts<'a>(rows: &'a [ResultRow], txid: &str) -> Result<Vec<&'a ResultRow>> {
    let mut roots: BTreeMap<(u32, u32), &ResultRow> = BTreeMap::new();
    let mut positions = BTreeSet::new();
    for row in rows.iter().filter(|row| row.txid.as_deref() == Some(txid)) {
        let position = (
            row.input_index.context("paid receipt missing input")?,
            row.op_index.context("paid receipt missing operation")?,
        );
        ensure!(
            positions.insert((position, row.result_index)),
            "duplicate paid receipt position"
        );
        // Nested calls finish first. The largest result index owns the paid
        // operation's total gas; adding child gas would charge it twice.
        let root = roots.entry(position).or_insert(row);
        if row.result_index > root.result_index {
            *root = row;
        }
    }
    Ok(roots.into_values().collect())
}

pub(super) struct Before {
    config: PopulationConfig,
    payer: String,
    payer_balance: Decimal,
    supply: Decimal,
    burner: Decimal,
    staking_escrow: Decimal,
    storage_escrow: Decimal,
    validators: Vec<(Signer, ValidatorInfo, Decimal)>,
    hosts: BTreeMap<u64, Host>,
    files: BTreeSet<String>,
    omega: BigInt,
}

fn atoms(value: Decimal) -> BigInt {
    assert!(
        value >= Decimal::default(),
        "negative populated oracle amount"
    );
    let mut result = BigInt::from(value.r3);
    for limb in [value.r2, value.r1, value.r0] {
        result = (result << 64) + limb;
    }
    result
}

impl Before {
    pub(super) async fn capture(
        runtime: &mut Runtime,
        population: &Population,
        payer: &str,
        config: PopulationConfig,
    ) -> Result<Self> {
        let mut validators = Vec::new();
        for member in population.members() {
            let identity = get_identity(&runtime.get_storage_conn(), &member.x_only_pubkey)
                .await?
                .context("missing validator identity")?;
            let signer = Signer::Id(identity);
            let info = staking::get_validator(runtime, &signer)
                .await?
                .context("missing validator")?;
            let liquid = balance(runtime, HolderRef::from(&signer)).await?;
            validators.push((signer, info, liquid));
        }
        validators.sort_by(|left, right| left.1.x_only_pubkey.cmp(&right.1.x_only_pubkey));
        ensure!(
            validators
                .iter()
                .filter(|(_, info, _)| info.status == ValidatorStatus::Active)
                .count()
                == config.active_validators - config.replacements
        );
        ensure!(
            validators
                .iter()
                .filter(|(_, info, _)| info.status == ValidatorStatus::PendingExit
                    && info.deactivation_height == 102)
                .count()
                == config.replacements
        );
        ensure!(
            validators
                .iter()
                .filter(|(_, info, _)| info.status == ValidatorStatus::PendingJoin
                    && info.activation_height == 102)
                .count()
                == config.replacements
        );
        let mut hosts: BTreeMap<u64, Host> = BTreeMap::new();
        let mut omega = atoms(Decimal::from("1000"));
        let weight_scale = BigInt::from(10u64).pow(18);
        let agreements = files::get_all_active_agreements(runtime).await?;
        ensure!(agreements.len() == config.agreements);
        let mut ids = BTreeSet::new();
        for agreement in agreements {
            ensure!(agreement.active_challenge.is_none());
            ensure!(ids.insert(agreement.agreement_id.clone()));
            omega += atoms(agreement.storage_weight);
            let nodes = files::get_agreement_nodes(runtime, &agreement.agreement_id).await?;
            ensure!(
                nodes.len() == config.members_per_agreement && nodes.iter().all(|node| node.active)
            );
            let share = atoms(agreement.storage_weight) * &weight_scale / nodes.len();
            for node in nodes {
                if let Entry::Vacant(entry) = hosts.entry(node.node_id) {
                    let holder = HolderRef::SignerId(node.node_id);
                    let stake = staking::get_stake(runtime, &holder.to_string())
                        .await?
                        .context("missing storage bond")?;
                    ensure!(
                        files::reward_balance(runtime, node.node_id).await?? == Decimal::default()
                    );
                    entry.insert(Host {
                        weight: BigInt::from(0),
                        liquid: balance(runtime, holder).await?,
                        bond: stake.stake,
                        reservation: files::get_node_reservation(runtime, node.node_id).await?,
                    });
                }
                hosts.get_mut(&node.node_id).context("missing host")?.weight += &share;
            }
        }
        ensure!(
            hosts.len() == config.members_per_agreement
                && files::get_active_challenges(runtime).await?.is_empty()
        );
        for holder in [
            HolderRef::Core,
            HolderRef::OrderingPool,
            HolderRef::StoragePool,
        ] {
            ensure!(balance(runtime, holder).await? == Decimal::default());
        }
        let storage_escrow = escrow(runtime, &storage_address()).await?;
        ensure!(storage_escrow == Decimal::default());
        Ok(Self {
            config,
            payer: payer.into(),
            payer_balance: balance(runtime, HolderRef::XOnlyPubkey(payer.into())).await?,
            supply: token::total_supply(runtime).await?,
            burner: balance(runtime, HolderRef::Burner).await?,
            staking_escrow: escrow(runtime, &staking_address()).await?,
            storage_escrow,
            validators,
            hosts,
            files: ids,
            omega,
        })
    }

    pub(super) async fn check(
        &self,
        reactor: &mut Reactor<RuntimeExecutor>,
        rows: &[ResultRow],
        txids: &[String],
        effects: &PaidEffects,
    ) -> Result<()> {
        let runtime = &mut reactor.runtime;
        let mut roots = Vec::new();
        let mut transaction_ids = BTreeSet::new();
        for txid in txids {
            ensure!(
                transaction_ids.insert(txid),
                "duplicate workload transaction"
            );
            let transaction_roots = root_receipts(rows, txid)?;
            ensure!(
                !transaction_roots.is_empty(),
                "missing transaction receipts"
            );
            roots.extend(transaction_roots);
        }
        ensure!(!roots.is_empty());
        let gas = roots.iter().try_fold(0u64, |sum, row| {
            sum.checked_add(row.gas).context("gas overflow")
        })?;
        let mut deposit = 0u64;
        let mut user = 0u64;
        for txid in txids {
            let mut usage = runtime.get_storage_conn().query(
            "SELECT u.deposit_fuel, u.user_fuel FROM transaction_execution_usage u JOIN transactions t ON t.id = u.tx_id WHERE t.txid = ?", params![txid],
        ).await?;
            let usage_row = usage.next().await?.context("missing paid usage")?;
            deposit = deposit
                .checked_add(usage_row.get::<u64>(0)?)
                .context("deposit overflow")?;
            user = user
                .checked_add(usage_row.get::<u64>(1)?)
                .context("user fuel overflow")?;
            ensure!(usage.next().await?.is_none(), "duplicate transaction usage");
        }
        ensure!(runtime.gas_to_fuel_multiplier == 1000 && deposit.is_multiple_of(1000));
        let rounded = user
            .checked_add(deposit)
            .context("fuel overflow")?
            .div_ceil(1000);
        ensure!(
            gas >= rounded
                && gas
                    <= rounded
                        .checked_add(u64::try_from(roots.len() - 1)?)
                        .context("rounding bound overflow")?
        );
        let execution = gas
            .checked_sub(deposit / 1000)
            .context("deposit exceeds gas")?;
        let fee = mul_decimal(Decimal::try_from(execution)?, Decimal::from("0.000000001"))?;
        ensure!(runtime.pricing.execution_fee(execution)? == fee);
        ensure!(
            balance(runtime, HolderRef::XOnlyPubkey(self.payer.clone())).await?
                == sub_decimal(
                    sub_decimal(sub_decimal(self.payer_balance, fee)?, effects.transferred)?,
                    effects.staked
                )?
        );
        ensure!(balance(runtime, HolderRef::Burner).await? == add_decimal(self.burner, fee)?);
        let supply = sub_decimal(self.supply, fee)?;
        let scheduled = div_decimal(
            div_decimal(
                mul_decimal(supply, Decimal::from("5"))?,
                Decimal::from("100"),
            )?,
            Decimal::from("52560"),
        )?;
        let ordering = div_decimal(scheduled, Decimal::from("10"))?;
        let budget = sub_decimal(scheduled, ordering)?;
        let emission = token::wave::mint_emission_parse_return_expr(lifecycle_value(
            rows,
            &token_address(),
            "mint-emission",
        )?)?;
        ensure!(
            emission.scheduled_total == scheduled
                && emission.ordering_minted == ordering
                && emission.storage_unminted == budget
        );
        ensure!(
            staking::wave::distribute_ordering_reward_parse_return_expr(lifecycle_value(
                rows,
                &staking_address(),
                "distribute-ordering-reward"
            )?)? == ordering
        );
        let recipients: Vec<_> = self
            .validators
            .iter()
            .filter(|(_, info, _)| info.status == ValidatorStatus::Active)
            .collect();
        let total = recipients
            .iter()
            .try_fold(Decimal::default(), |sum, (_, info, _)| {
                add_decimal(sum, info.stake)
            })?;
        let mut credits = BTreeMap::new();
        let mut credited = Decimal::default();
        for (index, (_, info, _)) in recipients.iter().enumerate() {
            let remaining = sub_decimal(ordering, credited)?;
            let share = if index + 1 == recipients.len() {
                remaining
            } else {
                div_decimal(mul_decimal(ordering, info.stake)?, total)?.min(remaining)
            };
            credited = add_decimal(credited, share)?;
            credits.insert(info.x_only_pubkey.clone(), share);
        }
        ensure!(credited == ordering);
        let mut active = Vec::new();
        let mut total_active = Decimal::default();
        for (signer, old, liquid) in &self.validators {
            let actual = staking::get_validator(runtime, signer)
                .await?
                .context("missing validator after transition")?;
            let stake = add_decimal(
                old.stake,
                credits.get(&old.x_only_pubkey).copied().unwrap_or_default(),
            )?;
            let status = if old.status == ValidatorStatus::PendingExit {
                ValidatorStatus::Inactive
            } else {
                ValidatorStatus::Active
            };
            ensure!(
                actual.x_only_pubkey == old.x_only_pubkey
                    && actual.ed25519_pubkey == old.ed25519_pubkey
                    && actual.stake == stake
                    && actual.status == status
            );
            ensure!(balance(runtime, HolderRef::from(signer)).await? == *liquid);
            if status == ValidatorStatus::Active {
                active.push((old.x_only_pubkey.clone(), stake, old.ed25519_pubkey.clone()));
                total_active = add_decimal(total_active, stake)?;
            }
        }
        let set = staking::get_active_set(runtime).await?;
        ensure!(
            set.iter()
                .map(|member| (
                    member.x_only_pubkey.clone(),
                    member.stake,
                    member.ed25519_pubkey.clone()
                ))
                .collect::<Vec<_>>()
                == active
        );
        let info = staking::get_staking_info(runtime).await?;
        ensure!(
            info.active_count == u64::try_from(self.config.active_validators)?
                && info.total_stake == total_active
        );
        let expected_voting: Vec<(Vec<u8>, u64)> = active
            .iter()
            .map(|(_, stake, key)| {
                let power: u64 = (atoms(*stake) / BigInt::from(10u64).pow(18)).try_into()?;
                ensure!(power > 0);
                Ok((key.clone(), power))
            })
            .collect::<Result<_>>()?;
        ensure!(
            reactor
                .consensus
                .current_validator_set
                .validators
                .iter()
                .map(|member| (member.public_key.as_bytes().to_vec(), member.voting_power))
                .collect::<Vec<_>>()
                == expected_voting
        );
        let changed = staking::wave::process_pending_validators_parse_return_expr(
            lifecycle_value(rows, &staking_address(), "process-pending-validators")?,
        )?;
        ensure!(
            changed.activated == u64::try_from(self.config.replacements)?
                && changed.deactivated == u64::try_from(self.config.replacements)?
        );
        ensure!(
            escrow(runtime, &staking_address()).await?
                == add_decimal(add_decimal(self.staking_escrow, ordering)?, effects.staked)?
        );

        let index_scale = BigInt::from(10u64).pow(36);
        let weight_scale = BigInt::from(10u64).pow(18);
        let step = atoms(budget) * &index_scale / (&self.omega * &weight_scale);
        let mut liability = BigInt::from(0);
        for (node, host) in &self.hosts {
            let earned = &step * &host.weight;
            liability += &earned;
            ensure!(atoms(files::reward_balance(runtime, *node).await??) == &earned / &index_scale);
            let holder = HolderRef::SignerId(*node);
            ensure!(balance(runtime, holder.clone()).await? == host.liquid);
            ensure!(
                staking::get_stake(runtime, &holder.to_string())
                    .await?
                    .context("lost host bond")?
                    .stake
                    == host.bond
            );
            ensure!(files::get_node_reservation(runtime, *node).await? == host.reservation);
        }
        let funded = (liability + &index_scale - 1) / &index_scale;
        ensure!(funded > BigInt::from(0));
        let actual_funded = files::wave::accrue_storage_rewards_parse_return_expr(
            lifecycle_value(rows, &storage_address(), "accrue-storage-rewards")?,
        )?;
        ensure!(atoms(actual_funded) == funded);
        ensure!(
            atoms(escrow(runtime, &storage_address()).await?)
                == atoms(self.storage_escrow) + &funded
        );
        ensure!(
            atoms(token::total_supply(runtime).await?) == atoms(supply) + atoms(ordering) + funded
        );
        for holder in [
            HolderRef::Core,
            HolderRef::OrderingPool,
            HolderRef::StoragePool,
        ] {
            ensure!(balance(runtime, holder).await? == Decimal::default());
        }
        let challenges = files::get_active_challenges(runtime).await?;
        let mut challenged = BTreeMap::new();
        for challenge in challenges {
            ensure!(
                self.files.contains(&challenge.agreement_id)
                    && self.hosts.contains_key(&challenge.prover_id)
            );
            ensure!(
                challenge.block_height == 102
                    && challenge.deadline_height == 2118
                    && challenge.num_challenges == 8
                    && challenge.seed.len() == 64
                    && challenge.status == files::ChallengeStatus::Active
            );
            ensure!(
                challenged
                    .insert(challenge.agreement_id, challenge.challenge_id)
                    .is_none()
            );
        }
        for id in &self.files {
            let file = files::get_agreement(runtime, id)
                .await?
                .context("lost storage agreement")?;
            ensure!(file.active && file.active_challenge.as_ref() == challenged.get(id));
        }
        Ok(())
    }
}

#[test]
#[should_panic(expected = "negative populated oracle amount")]
fn workload_populated_oracle_rejects_negative_amounts() {
    atoms(Decimal::from("-1"));
}
