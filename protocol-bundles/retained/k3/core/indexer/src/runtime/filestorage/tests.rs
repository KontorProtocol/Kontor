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
    let required = api::get_agreement(&mut runtime, &agreement)
        .await?
        .unwrap()
        .required_collateral;
    for (id, signer) in &signers {
        api::join_agreement(&mut runtime, signer, &agreement).await??;
        assert!(api::has_storage_obligations(&mut runtime, *id).await?);
        assert_eq!(
            api::get_node_reservation(&mut runtime, *id).await?,
            required
        );
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
        assert_eq!(
            api::get_node_reservation(&mut runtime, signers[0].0).await?,
            required
        );
        for (id, _) in &signers[1..] {
            assert!(!api::has_storage_obligations(&mut runtime, *id).await?);
            assert_eq!(
                api::get_node_reservation(&mut runtime, *id).await?,
                Decimal::default()
            );
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
        assert_eq!(
            api::get_node_reservation(&mut runtime, signers[0].0).await?,
            required
        );
        api::join_agreement(&mut runtime, &signers[0].1, &agreement).await??;
        api::leave_agreement(&mut runtime, &signers[0].1, &agreement).await??;
        assert!(api::has_storage_obligations(&mut runtime, signers[0].0).await?);
        assert_eq!(
            api::get_node_reservation(&mut runtime, signers[0].0).await?,
            required
        );

        runtime.storage.rollback_with_footprint(1).await?;
        runtime.set_context(1, None, None, None).await;
        assert!(
            api::get_challenge(&mut runtime, &challenge.challenge_id)
                .await?
                .is_none()
        );
        for (id, _) in &signers {
            assert!(api::has_storage_obligations(&mut runtime, *id).await?);
            assert_eq!(
                api::get_node_reservation(&mut runtime, *id).await?,
                required
            );
        }
    }
    for (id, signer) in &signers {
        api::leave_agreement(&mut runtime, signer, &agreement).await??;
        assert!(!api::has_storage_obligations(&mut runtime, *id).await?);
        assert_eq!(
            api::get_node_reservation(&mut runtime, *id).await?,
            Decimal::default()
        );
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

#[tokio::test]
async fn collateral_capacity_uses_frozen_quotes_and_atomic_reservations() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let core = Signer::Core(Box::new(Signer::Nobody));
    let mut hosts = Vec::new();
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
        hosts.push((id, signer));
    }
    let mut agreements = Vec::new();
    // Even zero/one-byte labels must pay for the committed padded field elements.
    for (name, padded, original) in [("tiny", 1, 0), ("larger", 1024, 1)] {
        let id = api::create_agreement(
            &mut runtime,
            &hosts[0].1,
            make_descriptor(
                name.into(),
                vec![1; 32],
                padded,
                original,
                "file.txt".into(),
            ),
        )
        .await??
        .agreement_id;
        agreements.push(api::get_agreement(&mut runtime, &id).await?.unwrap());
    }
    let a = &agreements[0];
    let b = &agreements[1];
    assert!(a.required_collateral > Decimal::default());
    assert!(b.required_collateral > a.required_collateral);
    let unit = Decimal::from("0.000000000000000001");
    staking::add_stake(&mut runtime, &hosts[0].1, a.required_collateral - unit).await??;
    assert_eq!(
        api::join_agreement(&mut runtime, &hosts[0].1, &a.agreement_id).await?,
        Err(Error::Message("insufficient unreserved collateral".into()))
    );
    assert!(
        api::get_agreement_nodes(&mut runtime, &a.agreement_id)
            .await?
            .is_empty()
    );
    assert_eq!(
        api::get_node_reservation(&mut runtime, hosts[0].0).await?,
        Decimal::default()
    );
    staking::add_stake(&mut runtime, &hosts[0].1, unit).await??;
    api::join_agreement(&mut runtime, &hosts[0].1, &a.agreement_id).await??;
    assert_eq!(
        api::get_node_reservation(&mut runtime, hosts[0].0).await?,
        a.required_collateral
    );
    assert_eq!(
        api::join_agreement(&mut runtime, &hosts[0].1, &b.agreement_id).await?,
        Err(Error::Message("insufficient unreserved collateral".into()))
    );
    assert!(
        api::get_agreement_nodes(&mut runtime, &b.agreement_id)
            .await?
            .is_empty()
    );
    assert!(
        !api::get_agreement(&mut runtime, &b.agreement_id)
            .await?
            .unwrap()
            .active
    );
    assert!(
        api::join_agreement(&mut runtime, &hosts[0].1, &a.agreement_id)
            .await?
            .is_err()
    );
    assert_eq!(
        api::get_node_reservation(&mut runtime, hosts[0].0).await?,
        a.required_collateral
    );

    for (_, signer) in &hosts[1..] {
        staking::add_stake(&mut runtime, signer, a.required_collateral).await??;
        api::join_agreement(&mut runtime, signer, &a.agreement_id).await??;
    }
    // Creating/activating other agreements must never reprice an existing hold.
    let later = api::create_agreement(
        &mut runtime,
        &hosts[0].1,
        make_descriptor("later".into(), vec![1; 32], 1, 1, "file.txt".into()),
    )
    .await??
    .agreement_id;
    assert!(
        api::get_agreement(&mut runtime, &later)
            .await?
            .unwrap()
            .required_collateral
            > a.required_collateral
    );
    assert_eq!(
        api::get_agreement(&mut runtime, &a.agreement_id)
            .await?
            .unwrap()
            .required_collateral,
        a.required_collateral
    );
    assert_eq!(
        api::get_agreement(&mut runtime, &b.agreement_id)
            .await?
            .unwrap()
            .required_collateral,
        b.required_collateral
    );
    staking::add_stake(&mut runtime, &hosts[0].1, b.required_collateral).await??;
    api::join_agreement(&mut runtime, &hosts[0].1, &b.agreement_id).await??;
    let total = a.required_collateral + b.required_collateral;
    assert_eq!(
        api::get_node_reservation(&mut runtime, hosts[0].0).await?,
        total
    );

    let mut replayed_quote = None;
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
        api::leave_agreement(&mut runtime, &hosts[0].1, &b.agreement_id).await??;
        assert_eq!(
            api::get_node_reservation(&mut runtime, hosts[0].0).await?,
            a.required_collateral
        );
        assert!(
            api::leave_agreement(&mut runtime, &hosts[0].1, &b.agreement_id)
                .await?
                .is_err()
        );
        api::join_agreement(&mut runtime, &hosts[0].1, &b.agreement_id).await??;
        assert_eq!(
            api::get_node_reservation(&mut runtime, hosts[0].0).await?,
            total
        );
        api::leave_agreement(&mut runtime, &hosts[0].1, &b.agreement_id).await??;
        api::join_agreement(&mut runtime, &hosts[0].1, &b.agreement_id).await??;
        for (_, signer) in &hosts[1..] {
            staking::add_stake(&mut runtime, signer, b.required_collateral).await??;
            api::join_agreement(&mut runtime, signer, &b.agreement_id).await??;
        }
        assert!(
            api::get_agreement(&mut runtime, &b.agreement_id)
                .await?
                .unwrap()
                .active
        );
        let transient = api::create_agreement(
            &mut runtime,
            &hosts[0].1,
            make_descriptor(
                "rolled_back_quote".into(),
                vec![1; 32],
                1,
                0,
                "file.txt".into(),
            ),
        )
        .await??
        .agreement_id;
        let quote = api::get_agreement(&mut runtime, &transient)
            .await?
            .unwrap()
            .required_collateral;
        if let Some(previous) = replayed_quote {
            assert_eq!(quote, previous);
        }
        replayed_quote = Some(quote);
        api::leave_agreement(&mut runtime, &hosts[0].1, &b.agreement_id).await??;
        runtime.storage.rollback_with_footprint(1).await?;
        runtime.set_context(1, None, None, None).await;
        assert!(
            api::get_agreement(&mut runtime, &transient)
                .await?
                .is_none()
        );
        assert!(
            !api::get_agreement(&mut runtime, &b.agreement_id)
                .await?
                .unwrap()
                .active
        );
        for (id, _) in &hosts[1..] {
            assert_eq!(
                api::get_node_reservation(&mut runtime, *id).await?,
                a.required_collateral
            );
        }
        assert_eq!(
            api::get_node_reservation(&mut runtime, hosts[0].0).await?,
            total
        );
        assert!(api::is_node_in_agreement(&mut runtime, &b.agreement_id, hosts[0].0).await?);
    }
    assert_eq!(
        staking::get_stake(&mut runtime, &hosts[0].1)
            .await?
            .unwrap()
            .stake,
        total
    );
    assert!(
        staking::get_validator(&mut runtime, &hosts[0].1)
            .await?
            .is_none()
    );
    Ok(())
}
