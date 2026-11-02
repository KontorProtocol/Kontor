use std::collections::BTreeMap;

use anyhow::Result;
use num::BigInt;

use super::settlement_tests::{StorageFixture, at_height};
use super::{address, api};
use crate::database::queries::{get_contract_id_from_address, get_contract_signer_id};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::numerics::{add_decimal, sub_decimal};
use crate::runtime::staking::api as staking;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Error, Runtime, Storage};
use crate::test_utils::{make_descriptor, test_runtime, valid_seed_field};

fn core() -> Signer {
    Signer::Core(Box::new(Signer::Nobody))
}

fn atoms(value: Decimal) -> BigInt {
    let mut result = BigInt::from(value.r3);
    for limb in [value.r2, value.r1, value.r0] {
        result = (result << 64) + limb;
    }
    result
}

fn scale() -> BigInt {
    BigInt::from(10u64).pow(36)
}

#[derive(Clone, Default)]
struct Oracle {
    earned: BTreeMap<u64, BigInt>,
    paid: BTreeMap<u64, BigInt>,
    funded: BigInt,
}

impl Oracle {
    async fn accrue(&mut self, runtime: &mut Runtime) -> Result<Decimal> {
        let emission = token::mint_emission(runtime, &core(), false).await??;
        let files = api::get_all_active_agreements(runtime).await?;
        let weight_scale = BigInt::from(10u64).pow(18);
        let mut omega = BigInt::from(1000) * &weight_scale;
        for file in &files {
            omega += atoms(file.storage_weight);
        }
        let step = atoms(emission.storage_unminted) * scale() / (omega * &weight_scale);
        for file in files {
            let members: Vec<_> = api::get_agreement_nodes(runtime, &file.agreement_id)
                .await?
                .into_iter()
                .filter(|node| node.active)
                .collect();
            if members.is_empty() {
                continue;
            }
            let share = atoms(file.storage_weight) * &weight_scale / members.len();
            for member in members {
                if !api::is_bond_cleanup_pending(runtime, member.node_id).await? {
                    *self.earned.entry(member.node_id).or_default() += &step * &share;
                }
            }
        }
        let liability: BigInt = self.earned.values().sum();
        let funded = (liability + scale() - 1) / scale();
        let expected = &funded - &self.funded;
        let supply = token::total_supply(runtime).await?;
        let actual = api::accrue_storage_rewards(runtime, &core()).await??;
        assert_eq!(
            atoms(actual),
            expected,
            "funding must follow eligible liabilities"
        );
        assert_eq!(
            token::total_supply(runtime).await?,
            add_decimal(supply, actual)?
        );
        assert!(actual <= emission.storage_unminted);
        self.funded = funded;
        self.check(runtime).await?;
        Ok(actual)
    }

    async fn check(&self, runtime: &mut Runtime) -> Result<()> {
        for (node, earned) in &self.earned {
            let paid = self.paid.get(node).cloned().unwrap_or_default();
            assert_eq!(
                atoms(api::reward_balance(runtime, *node).await??),
                earned / scale() - paid,
                "host {node}"
            );
        }
        let conn = runtime.get_storage_conn();
        let id = get_contract_id_from_address(&conn, &address())
            .await?
            .unwrap();
        let holder = get_contract_signer_id(&conn, id).await?.unwrap();
        let escrow = token::balance(runtime, HolderRef::SignerId(holder))
            .await?
            .unwrap_or_default();
        let paid: BigInt = self.paid.values().sum();
        assert_eq!(atoms(escrow), &self.funded - paid);
        assert_eq!(
            token::balance(runtime, HolderRef::StoragePool)
                .await?
                .unwrap_or_default(),
            Decimal::default()
        );
        Ok(())
    }

    async fn claim(&mut self, runtime: &mut Runtime, node: u64, signer: &Signer) -> Result<()> {
        let before = token::balance(runtime, HolderRef::from(signer))
            .await?
            .unwrap_or_default();
        let supply = token::total_supply(runtime).await?;
        let burner = token::balance(runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        let bond = staking::get_stake(runtime, &node.to_string()).await?;
        let expected = self.earned.get(&node).cloned().unwrap_or_default() / scale()
            - self.paid.get(&node).cloned().unwrap_or_default();
        let amount = api::claim_rewards(runtime, signer).await??;
        assert_eq!(atoms(amount), expected);
        *self.paid.entry(node).or_default() += atoms(amount);
        let fees = sub_decimal(
            token::balance(runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default(),
            burner,
        )?;
        assert_eq!(
            token::total_supply(runtime).await?,
            sub_decimal(supply, fees)?
        );
        assert_eq!(
            token::balance(runtime, HolderRef::from(signer))
                .await?
                .unwrap(),
            sub_decimal(add_decimal(before, amount)?, fees)?
        );
        assert_eq!(staking::get_stake(runtime, &node.to_string()).await?, bond);
        assert_eq!(
            api::claim_rewards(runtime, signer).await??,
            Decimal::default()
        );
        self.check(runtime).await
    }
}

#[tokio::test]
async fn storage_rewards_match_eager_accounting_through_membership_changes_and_replay() -> Result<()>
{
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let keys: Vec<_> = (0..5).map(|_| random_x_only_pubkey()).collect();
    let fixture = StorageFixture::new(&mut runtime, 2, &keys).await?;
    for (_, signer) in &fixture.hosts {
        staking::add_stake(&mut runtime, signer, Decimal::from("1000")).await??;
    }
    let mut expected_end = None;
    for _ in 0..2 {
        runtime.storage.savepoint().await?;
        let mut oracle = Oracle::default();
        at_height(&mut runtime, 2).await?;
        for (_, signer) in &fixture.hosts[..2] {
            api::join_agreement(&mut runtime, signer, &fixture.agreements[0]).await??;
        }
        assert_eq!(oracle.accrue(&mut runtime).await?, Decimal::default());
        api::join_agreement(&mut runtime, &fixture.hosts[2].1, &fixture.agreements[0]).await??;
        for height in 3..=10 {
            at_height(&mut runtime, height).await?;
            match height {
                4 => {
                    api::join_agreement(&mut runtime, &fixture.hosts[3].1, &fixture.agreements[0])
                        .await??;
                    for (_, signer) in &fixture.hosts[1..4] {
                        api::join_agreement(&mut runtime, signer, &fixture.agreements[1]).await??;
                    }
                }
                5 => {
                    api::leave_agreement(&mut runtime, &fixture.hosts[0].1, &fixture.agreements[0])
                        .await??;
                }
                6 => {
                    api::join_agreement(&mut runtime, &fixture.hosts[0].1, &fixture.agreements[0])
                        .await??;
                }
                7 => {
                    for (_, signer) in &fixture.hosts[..4] {
                        api::leave_agreement(&mut runtime, signer, &fixture.agreements[0])
                            .await??;
                    }
                    for (_, signer) in &fixture.hosts[1..4] {
                        api::leave_agreement(&mut runtime, signer, &fixture.agreements[1])
                            .await??;
                    }
                }
                9 => {
                    api::join_agreement(&mut runtime, &fixture.hosts[4].1, &fixture.agreements[0])
                        .await??;
                }
                _ => {}
            }
            let amount = oracle.accrue(&mut runtime).await?;
            if height == 7 || height == 8 {
                assert_eq!(amount, Decimal::default());
            }
            let (node, signer) = &fixture.hosts[(height % 5) as usize];
            oracle.claim(&mut runtime, *node, signer).await?;
        }
        for (node, signer) in &fixture.hosts {
            oracle.claim(&mut runtime, *node, signer).await?;
        }
        let supply = token::total_supply(&mut runtime).await?;
        if let Some(previous) = expected_end {
            assert_eq!(supply, previous);
        }
        expected_end = Some(supply);
        assert!(
            api::accrue_storage_rewards(&mut runtime, &core())
                .await?
                .is_err()
        );
        runtime.storage.rollback().await?;
        runtime.set_context(1, None, None, None).await;
        for (node, _) in &fixture.hosts {
            assert_eq!(
                api::reward_balance(&mut runtime, *node).await??,
                Decimal::default()
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn storage_funding_is_height_bound_capped_and_core_only() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let identity = runtime
        .get_or_create_identity(&random_x_only_pubkey())
        .await?;
    let signer = Signer::Id(identity);
    let holder = HolderRef::from(&signer);
    token::issue_to(&mut runtime, &core(), holder.clone(), Decimal::from("1000")).await??;
    assert!(
        token::allocate_storage_emission(&mut runtime, &core(), holder.clone(), Decimal::default())
            .await?
            .is_err()
    );
    let emission = token::mint_emission(&mut runtime, &core(), false).await??;
    assert!(
        token::allocate_storage_emission(
            &mut runtime,
            &signer,
            holder.clone(),
            emission.storage_unminted
        )
        .await
        .is_err()
    );
    assert!(
        api::accrue_storage_rewards(&mut runtime, &signer)
            .await
            .is_err()
    );
    for amount in [
        Decimal::from("-1"),
        add_decimal(
            emission.storage_unminted,
            Decimal::from("0.000000000000000001"),
        )?,
    ] {
        assert!(
            token::allocate_storage_emission(&mut runtime, &core(), holder.clone(), amount)
                .await?
                .is_err()
        );
    }
    let supply = token::total_supply(&mut runtime).await?;
    token::allocate_storage_emission(&mut runtime, &core(), holder.clone(), Decimal::default())
        .await??;
    assert_eq!(token::total_supply(&mut runtime).await?, supply);
    assert!(
        token::allocate_storage_emission(&mut runtime, &core(), holder.clone(), Decimal::default())
            .await?
            .is_err()
    );
    at_height(&mut runtime, 2).await?;
    token::mint_emission(&mut runtime, &core(), false).await??;
    at_height(&mut runtime, 3).await?;
    assert!(
        token::allocate_storage_emission(&mut runtime, &core(), holder, Decimal::default())
            .await?
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn exhaustion_during_preparation_and_folding_preserves_earned_rewards() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let keys: Vec<_> = (0..34).map(|_| random_x_only_pubkey()).collect();
    let fixture = StorageFixture::new(&mut runtime, 1, &keys).await?;
    fixture.join(&mut runtime, Decimal::from("1000")).await?;
    let mut extra_files = Vec::new();
    for (offset, victim) in [(1, 1usize), (2, 32usize)] {
        let file = api::create_agreement(
            &mut runtime,
            &fixture.hosts[victim].1,
            make_descriptor(
                format!("extra-{offset}"),
                vec![1; 32],
                16,
                100,
                "file.txt".into(),
            ),
        )
        .await??
        .agreement_id;
        for member in [victim, 2, 3] {
            api::join_agreement(&mut runtime, &fixture.hosts[member].1, &file).await??;
        }
        api::create_challenge_for_agreement(
            &mut runtime,
            &fixture.hosts[victim].1,
            &file,
            fixture.hosts[victim].0,
            offset,
            valid_seed_field(offset).bytes.to_vec(),
        )
        .await??;
        extra_files.push(file);
    }
    fixture.challenge(&mut runtime, 0, 0).await?;
    for index in [0, 1, 32] {
        staking::slash(
            &mut runtime,
            &core(),
            fixture.hosts[index].0,
            sub_decimal(Decimal::from("1000"), Decimal::from("0.000000000000000001"))?,
        )
        .await??;
    }
    let mut oracle = Oracle::default();
    let mut cutoffs = BTreeMap::new();
    let mut saw_pending_removal = false;
    let mut saw_applied = false;
    for height in 2016..=2030 {
        at_height(&mut runtime, height).await?;
        oracle.accrue(&mut runtime).await?;
        if height == 2017 {
            runtime.storage.savepoint().await?;
            api::expire_challenges(&mut runtime, &core(), height).await?;
            api::settle_expired_challenges(&mut runtime, &core()).await??;
            assert!(
                !api::is_node_in_agreement(
                    &mut runtime,
                    &fixture.agreements[0],
                    fixture.hosts[0].0
                )
                .await?
            );
            api::claim_rewards(&mut runtime, &fixture.hosts[33].1).await??;
            runtime.storage.rollback().await?;
            assert!(
                api::is_node_in_agreement(&mut runtime, &fixture.agreements[0], fixture.hosts[0].0)
                    .await?
            );
            runtime = Runtime::new_with(
                runtime.engine.clone(),
                Runtime::new_linkers(&runtime.engine)?,
                runtime.component_cache.clone(),
                Storage::builder()
                    .height(height)
                    .conn(runtime.get_storage_conn())
                    .build(),
            )
            .await?;
            oracle.check(&mut runtime).await?;
        }
        api::expire_challenges(&mut runtime, &core(), height).await?;
        assert!(api::settle_expired_challenges(&mut runtime, &core()).await?? <= 64);
        for index in [0, 1, 32] {
            let (node, signer) = &fixture.hosts[index];
            if api::is_bond_cleanup_pending(&mut runtime, *node).await? {
                let earned = oracle.earned.get(node).cloned().unwrap_or_default();
                assert_eq!(cutoffs.entry(*node).or_insert(earned.clone()), &earned);
                assert!(
                    staking::add_stake(&mut runtime, signer, Decimal::from("1"))
                        .await?
                        .is_err()
                );
                oracle.claim(&mut runtime, *node, signer).await?;
            }
        }
        if api::is_node_in_agreement(&mut runtime, &fixture.agreements[0], fixture.hosts[0].0)
            .await?
        {
            saw_pending_removal = true;
            assert_eq!(
                api::leave_agreement(&mut runtime, &fixture.hosts[5].1, &fixture.agreements[0])
                    .await?,
                Err(Error::Message(
                    "agreement reward cleanup in progress".into()
                ))
            );
        } else {
            saw_applied = true;
        }
        // A change in another file can settle a host whose prepared delta has
        // already taken effect but has not yet been folded by the cleanup budget.
        if height == 2017 {
            api::join_agreement(&mut runtime, &fixture.hosts[33].1, &extra_files[0]).await??;
        }
        oracle.check(&mut runtime).await?;
    }
    assert!(saw_pending_removal && saw_applied);
    for index in [0, 1, 32] {
        let (node, signer) = &fixture.hosts[index];
        assert!(!api::is_bond_cleanup_pending(&mut runtime, *node).await?);
        assert!(!api::is_node_in_agreement(&mut runtime, &fixture.agreements[0], *node).await?);
        staking::add_stake(&mut runtime, signer, Decimal::from("1000")).await??;
        api::join_agreement(&mut runtime, signer, &fixture.agreements[0]).await??;
    }
    at_height(&mut runtime, 2031).await?;
    oracle.accrue(&mut runtime).await?;
    for (node, signer) in &fixture.hosts {
        oracle.claim(&mut runtime, *node, signer).await?;
    }
    Ok(())
}

#[tokio::test]
async fn storage_reward_atoms_can_exceed_the_whole_integer_conversion_ceiling() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let keys: Vec<_> = (0..3).map(|_| random_x_only_pubkey()).collect();
    let fixture = StorageFixture::new(&mut runtime, 1, &keys).await?;
    fixture.join(&mut runtime, Decimal::from("1000")).await?;
    token::issue_to(
        &mut runtime,
        &core(),
        HolderRef::from(&fixture.hosts[0].1),
        Decimal::from("1e54"),
    )
    .await??;
    let mut oracle = Oracle::default();
    for height in 2..=4 {
        at_height(&mut runtime, height).await?;
        let amount = oracle.accrue(&mut runtime).await?;
        assert!(atoms(amount) > (BigInt::from(1) << 256) / BigInt::from(10u64).pow(18));
    }
    for (node, signer) in &fixture.hosts {
        oracle.claim(&mut runtime, *node, signer).await?;
    }
    Ok(())
}

#[tokio::test]
async fn failed_payout_restores_credit_and_a_different_signer_cannot_claim_it() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let keys: Vec<_> = (0..4).map(|_| random_x_only_pubkey()).collect();
    let fixture = StorageFixture::new(&mut runtime, 1, &keys).await?;
    for (_, signer) in &fixture.hosts[..3] {
        staking::add_stake(&mut runtime, signer, Decimal::from("1000")).await??;
        api::join_agreement(&mut runtime, signer, &fixture.agreements[0]).await??;
    }
    let mut oracle = Oracle::default();
    at_height(&mut runtime, 2).await?;
    oracle.accrue(&mut runtime).await?;
    let (node, signer) = &fixture.hosts[0];
    let claimable = api::reward_balance(&mut runtime, *node).await??;
    assert!(claimable > Decimal::default());
    assert_eq!(
        api::claim_rewards(&mut runtime, &fixture.hosts[3].1).await??,
        Decimal::default()
    );
    assert_eq!(api::reward_balance(&mut runtime, *node).await??, claimable);

    runtime.storage.savepoint().await?;
    let conn = runtime.get_storage_conn();
    let contract_id = get_contract_id_from_address(&conn, &address())
        .await?
        .unwrap();
    let signer_id = get_contract_signer_id(&conn, contract_id).await?.unwrap();
    let escrow = token::balance(&mut runtime, HolderRef::SignerId(signer_id))
        .await?
        .unwrap();
    // Use the trusted host's gas-hold capability to force an underfunded escrow;
    // ordinary transaction signers cannot debit a contract's balance this way.
    token::hold(
        &mut runtime,
        &Signer::Core(Box::new(Signer::new_contract(contract_id, signer_id))),
        escrow,
    )
    .await??;
    assert!(api::claim_rewards(&mut runtime, signer).await?.is_err());
    assert_eq!(api::reward_balance(&mut runtime, *node).await??, claimable);
    runtime.storage.rollback().await?;
    oracle.claim(&mut runtime, *node, signer).await?;
    Ok(())
}
