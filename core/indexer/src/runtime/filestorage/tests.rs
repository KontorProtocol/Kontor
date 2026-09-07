use anyhow::Result;
use indexer_types::BlockRow;

use super::api::{self, ChallengeStatus};
use crate::database::queries::insert_block;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::staking::api as staking;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Error};
use crate::test_utils::{make_descriptor, new_mock_block_hash, test_runtime, valid_seed_field};

#[tokio::test]
async fn obligations_survive_departure_and_expiry_and_follow_block_rollback() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let core = Signer::Core(Box::new(Signer::Nobody));
    let mut signers = Vec::new();
    for _ in 0..3 {
        let identity = runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?;
        let id = identity.signer_id();
        let signer = Signer::Id(identity);
        token::issue_to(
            &mut runtime,
            &core,
            HolderRef::from(&signer),
            Decimal::from("1000"),
        )
        .await??;
        staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
        assert!(!api::has_storage_obligations(&mut runtime, id).await?);
        signers.push((id, signer));
    }
    let agreement = api::create_agreement(
        &mut runtime,
        &signers[0].1,
        make_descriptor(
            "obligations".into(),
            vec![1; 32],
            16,
            100,
            "file.txt".into(),
        ),
    )
    .await??
    .agreement_id;
    for (id, signer) in &signers {
        api::join_agreement(&mut runtime, signer, &agreement).await??;
        assert!(api::has_storage_obligations(&mut runtime, *id).await?);
    }

    // Replaying block 2 must rebuild both indexes from the surviving block 1 rows.
    for _ in 0..2 {
        insert_block(
            &runtime.get_storage_conn(),
            BlockRow::builder()
                .height(2)
                .hash(new_mock_block_hash(2))
                .relevant(true)
                .build(),
        )
        .await?;
        runtime.set_context(2, None, None, None).await;
        let challenge = api::create_challenge_for_agreement(
            &mut runtime,
            &signers[0].1,
            &agreement,
            signers[0].0,
            2,
            valid_seed_field(1).bytes.to_vec(),
        )
        .await??;
        for (_, signer) in &signers {
            api::leave_agreement(&mut runtime, signer, &agreement).await??;
        }
        assert!(api::has_storage_obligations(&mut runtime, signers[0].0).await?);
        for (id, _) in &signers[1..] {
            assert!(!api::has_storage_obligations(&mut runtime, *id).await?);
        }
        assert_eq!(
            api::expire_challenges(&mut runtime, &core, challenge.deadline_height).await?,
            1
        );
        assert_eq!(
            api::get_challenge(&mut runtime, &challenge.challenge_id)
                .await?
                .unwrap()
                .status,
            ChallengeStatus::Expired
        );
        assert!(api::has_storage_obligations(&mut runtime, signers[0].0).await?);
        api::join_agreement(&mut runtime, &signers[0].1, &agreement).await??;
        api::leave_agreement(&mut runtime, &signers[0].1, &agreement).await??;
        assert!(api::has_storage_obligations(&mut runtime, signers[0].0).await?);

        runtime.storage.rollback_with_footprint(1).await?;
        runtime.set_context(1, None, None, None).await;
        assert!(
            api::get_challenge(&mut runtime, &challenge.challenge_id)
                .await?
                .is_none()
        );
        for (id, _) in &signers {
            assert!(api::has_storage_obligations(&mut runtime, *id).await?);
        }
    }
    for (id, signer) in &signers {
        api::leave_agreement(&mut runtime, signer, &agreement).await??;
        assert!(!api::has_storage_obligations(&mut runtime, *id).await?);
    }
    Ok(())
}

#[tokio::test]
async fn admission_tracks_bond_withdrawal_and_rollback() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let core = Signer::Core(Box::new(Signer::Nobody));
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    token::issue_to(
        &mut runtime,
        &core,
        HolderRef::from(&signer),
        Decimal::from("1000"),
    )
    .await??;
    let agreement = api::create_agreement(
        &mut runtime,
        &signer,
        make_descriptor("admission".into(), vec![1; 32], 16, 100, "file.txt".into()),
    )
    .await??
    .agreement_id;
    assert_eq!(
        api::join_agreement(&mut runtime, &signer, &agreement).await?,
        Err(Error::Message("no bonded stake".into()))
    );
    staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;

    for _ in 0..2 {
        insert_block(
            &runtime.get_storage_conn(),
            BlockRow::builder()
                .height(2)
                .hash(new_mock_block_hash(2))
                .relevant(true)
                .build(),
        )
        .await?;
        runtime.set_context(2, None, None, None).await;
        let withdrawal = staking::begin_unstake(&mut runtime, &signer).await??;
        assert_eq!(
            api::join_agreement(&mut runtime, &signer, &agreement).await?,
            Err(Error::Message("withdrawal already requested".into()))
        );
        let height = withdrawal.withdrawal_height.unwrap();
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
        staking::withdraw_stake(&mut runtime, &signer).await??;
        assert_eq!(
            api::join_agreement(&mut runtime, &signer, &agreement).await?,
            Err(Error::Message("no bonded stake".into()))
        );
        assert!(
            api::get_agreement_nodes(&mut runtime, &agreement)
                .await?
                .is_empty()
        );
        assert!(
            !api::get_agreement(&mut runtime, &agreement)
                .await?
                .unwrap()
                .active
        );

        runtime.storage.rollback_with_footprint(1).await?;
        runtime.set_context(1, None, None, None).await;
        let restored = staking::get_stake(&mut runtime, &signer).await?.unwrap();
        assert_eq!(restored.stake, Decimal::from("1"));
        assert_eq!(restored.withdrawal_height, None);
    }
    api::join_agreement(&mut runtime, &signer, &agreement).await??;
    assert!(
        staking::get_validator(&mut runtime, &signer)
            .await?
            .is_none()
    );
    Ok(())
}
