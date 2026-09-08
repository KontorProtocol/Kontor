use anyhow::Result;
use indexer_types::BlockRow;

use super::api::{self, ChallengeStatus};
use crate::database::queries::insert_block;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::numerics::{add_decimal, div_decimal, mul_decimal, sub_decimal};
use crate::runtime::staking::api as staking;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Error, Runtime};
use crate::test_utils::{make_descriptor, new_mock_block_hash, test_runtime, valid_seed_field};

pub(crate) async fn at_height(runtime: &mut Runtime, height: u64) -> Result<()> {
    insert_block(
        &runtime.get_storage_conn(),
        BlockRow::builder()
            .height(height)
            .hash(new_mock_block_hash(height as u32))
            .relevant(true)
            .build(),
    )
    .await?;
    runtime.set_context(height, None, None, None).await;
    Ok(())
}

pub(crate) struct StorageFixture {
    pub hosts: Vec<(u64, Signer)>,
    pub agreements: Vec<String>,
    pub requirements: Vec<Decimal>,
}

impl StorageFixture {
    pub(crate) async fn new(
        runtime: &mut Runtime,
        files: usize,
        pubkeys: &[String],
    ) -> Result<Self> {
        let core = Signer::Core(Box::new(Signer::Nobody));
        let mut hosts = Vec::new();
        for pubkey in pubkeys {
            let identity = runtime.get_or_create_identity(pubkey).await?;
            let id = identity.signer_id();
            let signer = Signer::Id(identity);
            token::issue_to(
                runtime,
                &core,
                HolderRef::from(&signer),
                Decimal::from("10000"),
            )
            .await??;
            hosts.push((id, signer));
        }
        let mut agreements = Vec::new();
        let mut requirements = Vec::new();
        for i in 0..files {
            let id = api::create_agreement(
                runtime,
                &hosts[0].1,
                make_descriptor(
                    format!("penalty-{i}"),
                    vec![1; 32],
                    16,
                    100,
                    "file.txt".into(),
                ),
            )
            .await??
            .agreement_id;
            requirements.push(
                api::get_agreement(runtime, &id)
                    .await?
                    .unwrap()
                    .required_collateral,
            );
            agreements.push(id);
        }
        Ok(Self {
            hosts,
            agreements,
            requirements,
        })
    }

    pub(crate) async fn join(&self, runtime: &mut Runtime, first_bond: Decimal) -> Result<()> {
        for (index, (_, signer)) in self.hosts.iter().enumerate() {
            staking::add_stake(
                runtime,
                signer,
                if index == 0 {
                    first_bond
                } else {
                    Decimal::from("1000")
                },
            )
            .await??;
            for id in &self.agreements {
                api::join_agreement(runtime, signer, id).await??;
            }
        }
        Ok(())
    }

    pub(crate) async fn challenge(
        &self,
        runtime: &mut Runtime,
        file: usize,
        height: u64,
    ) -> Result<String> {
        Ok(api::create_challenge_for_agreement(
            runtime,
            &self.hosts[0].1,
            &self.agreements[file],
            self.hosts[0].0,
            height,
            valid_seed_field(1).bytes.to_vec(),
        )
        .await??
        .challenge_id)
    }
}

#[tokio::test]
async fn partial_shortfall_retains_service_and_settlement_preserves_a_new_challenge() -> Result<()>
{
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let pubkeys: Vec<_> = (0..3).map(|_| random_x_only_pubkey()).collect();
    let fixture = StorageFixture::new(&mut runtime, 2, &pubkeys).await?;
    let penalty = mul_decimal(fixture.requirements[0], Decimal::from("30"))?;
    let remainder = div_decimal(fixture.requirements[0], Decimal::from("2"))?;
    fixture
        .join(&mut runtime, add_decimal(penalty, remainder)?)
        .await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    let (id, signer) = &fixture.hosts[0];
    let old = fixture.challenge(&mut runtime, 0, 0).await?;
    api::expire_challenges(&mut runtime, &core, 2016).await?;
    let new = fixture.challenge(&mut runtime, 0, 2016).await?;
    let reserved = api::get_node_reservation(&mut runtime, *id).await?;
    let supply = token::total_supply(&mut runtime).await?;
    assert!(
        api::settle_expired_challenges(&mut runtime, signer)
            .await
            .is_err()
    );
    at_height(&mut runtime, 2016).await?;
    runtime.storage.savepoint().await?;
    assert_eq!(
        api::settle_expired_challenges(&mut runtime, &core).await??,
        1
    );
    assert_eq!(
        api::get_challenge(&mut runtime, &old)
            .await?
            .unwrap()
            .status,
        ChallengeStatus::Settled
    );
    assert_eq!(
        api::get_agreement(&mut runtime, &fixture.agreements[0])
            .await?
            .unwrap()
            .active_challenge,
        Some(new.clone())
    );
    assert_eq!(
        staking::get_stake(&mut runtime, &id.to_string())
            .await?
            .unwrap()
            .stake,
        remainder
    );
    assert_eq!(
        sub_decimal(supply, token::total_supply(&mut runtime).await?)?,
        penalty
    );
    assert_eq!(
        api::get_node_reservation(&mut runtime, *id).await?,
        reserved
    );
    assert!(reserved > remainder);
    assert!(api::is_node_in_agreement(&mut runtime, &fixture.agreements[1], *id).await?);
    assert_eq!(
        api::settle_expired_challenges(&mut runtime, &core).await??,
        0
    );
    api::leave_agreement(&mut runtime, signer, &fixture.agreements[0]).await??;
    assert_eq!(
        api::get_node_reservation(&mut runtime, *id).await?,
        reserved
    );
    assert_eq!(
        api::join_agreement(&mut runtime, signer, &fixture.agreements[0]).await?,
        Err(Error::Message("insufficient unreserved collateral".into()))
    );
    staking::add_stake(&mut runtime, signer, sub_decimal(reserved, remainder)?).await??;
    api::join_agreement(&mut runtime, signer, &fixture.agreements[0]).await??;
    assert_eq!(
        api::get_node_reservation(&mut runtime, *id).await?,
        reserved
    );
    runtime.storage.rollback().await?;
    assert_eq!(
        api::get_challenge(&mut runtime, &old)
            .await?
            .unwrap()
            .status,
        ChallengeStatus::Expired
    );
    assert_eq!(token::total_supply(&mut runtime).await?, supply);
    Ok(())
}

#[tokio::test]
async fn exhaustion_cleanup_is_bounded_blocks_reentry_and_writes_off_old_obligations() -> Result<()>
{
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let pubkeys: Vec<_> = (0..3).map(|_| random_x_only_pubkey()).collect();
    let fixture = StorageFixture::new(&mut runtime, 40, &pubkeys).await?;
    let mut bond = Decimal::default();
    for requirement in &fixture.requirements {
        bond = add_decimal(bond, *requirement)?;
    }
    fixture.join(&mut runtime, bond).await?;
    let mut challenges = Vec::new();
    for file in 0..3 {
        challenges.push(fixture.challenge(&mut runtime, file, 0).await?);
    }
    let future = fixture.challenge(&mut runtime, 3, 2000).await?;
    let (id, signer) = &fixture.hosts[0];
    let core = Signer::Core(Box::new(Signer::Nobody));
    at_height(&mut runtime, 2016).await?;
    runtime.storage.savepoint().await?;
    api::expire_challenges(&mut runtime, &core, 2016).await?;
    let processed = api::settle_expired_challenges(&mut runtime, &core).await??;
    assert!(processed > 0 && processed <= 64);
    assert!(api::is_bond_cleanup_pending(&mut runtime, *id).await?);
    assert_eq!(
        staking::get_stake(&mut runtime, &id.to_string())
            .await?
            .unwrap()
            .stake,
        Decimal::default()
    );
    assert_eq!(
        staking::add_stake(&mut runtime, signer, Decimal::from("100")).await?,
        Err(Error::Message("bond cleanup pending".into()))
    );
    assert_eq!(
        staking::register_validator(&mut runtime, signer, vec![9; 32], Decimal::from("100"))
            .await?,
        Err(Error::Message("bond cleanup pending".into()))
    );
    let other = api::create_challenge_for_agreement(
        &mut runtime,
        &fixture.hosts[1].1,
        &fixture.agreements[39],
        fixture.hosts[1].0,
        0,
        valid_seed_field(2).bytes.to_vec(),
    )
    .await??;
    api::leave_agreement(&mut runtime, &fixture.hosts[1].1, &fixture.agreements[39]).await??;
    assert_eq!(
        api::get_node_reservation(&mut runtime, fixture.hosts[1].0).await?,
        bond
    );
    api::expire_challenges(&mut runtime, &core, 2016).await?;
    assert!(api::settle_expired_challenges(&mut runtime, &core).await?? > 0);
    assert_eq!(
        api::get_challenge(&mut runtime, &other.challenge_id)
            .await?
            .unwrap()
            .status,
        ChallengeStatus::Settled
    );
    assert_eq!(
        api::get_node_reservation(&mut runtime, fixture.hosts[1].0).await?,
        sub_decimal(bond, fixture.requirements[39])?
    );
    assert_eq!(
        staking::get_stake(&mut runtime, &fixture.hosts[1].0.to_string())
            .await?
            .unwrap()
            .stake,
        sub_decimal(
            Decimal::from("1000"),
            mul_decimal(fixture.requirements[39], Decimal::from("30"))?
        )?
    );
    assert!(!api::is_bond_cleanup_pending(&mut runtime, *id).await?);
    assert!(!api::has_storage_obligations(&mut runtime, *id).await?);
    assert_eq!(
        api::get_node_reservation(&mut runtime, *id).await?,
        Decimal::default()
    );
    for challenge in challenges.iter().chain([&future]) {
        assert_eq!(
            api::get_challenge(&mut runtime, challenge)
                .await?
                .unwrap()
                .status,
            ChallengeStatus::Settled
        );
    }
    for (index, agreement) in fixture.agreements.iter().enumerate() {
        assert!(!api::is_node_in_agreement(&mut runtime, agreement, *id).await?);
        assert_eq!(
            api::is_node_in_agreement(&mut runtime, agreement, fixture.hosts[1].0).await?,
            index != 39
        );
    }
    staking::add_stake(&mut runtime, signer, Decimal::from("100")).await??;
    assert_eq!(
        api::settle_expired_challenges(&mut runtime, &core).await??,
        0
    );
    assert_eq!(
        staking::get_stake(&mut runtime, &id.to_string())
            .await?
            .unwrap()
            .stake,
        Decimal::from("100")
    );
    api::join_agreement(&mut runtime, signer, &fixture.agreements[0]).await??;
    assert_eq!(
        api::get_node_reservation(&mut runtime, *id).await?,
        fixture.requirements[0]
    );
    runtime.storage.rollback().await?;
    assert!(!api::is_bond_cleanup_pending(&mut runtime, *id).await?);
    assert_eq!(api::get_node_reservation(&mut runtime, *id).await?, bond);
    assert_eq!(
        api::get_challenge(&mut runtime, &future)
            .await?
            .unwrap()
            .status,
        ChallengeStatus::Active
    );
    Ok(())
}
