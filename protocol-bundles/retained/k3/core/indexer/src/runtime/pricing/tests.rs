use anyhow::Result;
use indexer_types::BlockRow;
use proptest::prelude::*;

use super::Pricing;
use crate::database::queries::{
    find_footprint_by_depositor, get_checkpoint_by_height, insert_block,
};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::staking::api as staking;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{CheckedArithmetics, Decimal, ExecutionError, Runtime};
use crate::test_utils::{new_mock_block_hash, test_runtime};

async fn funded(runtime: &mut Runtime, amount: &str) -> Result<Signer> {
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    token::issue_to(
        runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&signer),
        Decimal::from(amount),
    )
    .await??;
    Ok(signer)
}

async fn floor(runtime: &mut Runtime, signer: &Signer) -> Result<Decimal> {
    token::floor(runtime, HolderRef::from(signer)).await
}

#[tokio::test]
async fn rates_are_independent_and_reservations_survive_rollback() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let alice = funded(&mut runtime, "10").await?;
    staking::add_stake(&mut runtime, &alice, Decimal::from("1")).await??;
    let alice_floor = floor(&mut runtime, &alice).await?;
    assert!(alice_floor > Decimal::default());

    runtime.pricing = Pricing::new(Decimal::default(), 3)?;
    assert_eq!(floor(&mut runtime, &alice).await?, alice_floor);
    let bob = funded(&mut runtime, "10").await?;
    staking::add_stake(&mut runtime, &bob, Decimal::from("1")).await??;
    assert_eq!(
        token::balance(&mut runtime, HolderRef::from(&bob)).await?,
        Some(Decimal::from("9"))
    );
    let rows =
        find_footprint_by_depositor(&runtime.get_storage_conn(), bob.signer_id().unwrap()).await?;
    assert!(!rows.is_empty());
    for row in rows {
        assert_eq!(row.deposited_gas, row.footprint_bytes * 3);
    }
    let bob_floor = floor(&mut runtime, &bob).await?;

    // An execution-price increase cannot change already recorded collateral.
    runtime.pricing = Pricing::new(Decimal::from("0.00000025"), 5)?;
    assert_eq!(floor(&mut runtime, &alice).await?, alice_floor);
    assert_eq!(floor(&mut runtime, &bob).await?, bob_floor);
    let mut checkpoint = None;
    for replay in [false, true] {
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
        let before = token::balance(&mut runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        staking::add_stake(&mut runtime, &bob, Decimal::from("1")).await??;
        let after = token::balance(&mut runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        assert!(after > before);
        assert!(floor(&mut runtime, &bob).await? > bob_floor);
        assert_eq!(floor(&mut runtime, &alice).await?, alice_floor);
        let actual = get_checkpoint_by_height(&runtime.get_storage_conn(), 2)
            .await?
            .unwrap();
        if replay {
            assert_eq!(Some(actual), checkpoint);
        } else {
            checkpoint = Some(actual);
            runtime.storage.rollback_with_footprint(1).await?;
            runtime.set_context(1, None, None, None).await;
            assert_eq!(floor(&mut runtime, &bob).await?, bob_floor);
            assert_eq!(
                staking::get_stake(&mut runtime, &bob).await?.unwrap().stake,
                Decimal::from("1")
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn free_execution_still_funds_storage_and_rejects_overflow() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    runtime.pricing = Pricing::new(Decimal::default(), 1)?;
    let signer = funded(&mut runtime, "0.000099").await?;
    assert!(
        staking::add_stake(&mut runtime, &signer, Decimal::from("0.000001"))
            .await
            .is_err()
    );
    assert!(staking::get_stake(&mut runtime, &signer).await?.is_none());
    token::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&signer),
        Decimal::from("1"),
    )
    .await??;
    let before = token::balance(&mut runtime, HolderRef::from(&signer))
        .await?
        .unwrap();
    let supply = token::total_supply(&mut runtime).await?;
    staking::add_stake(&mut runtime, &signer, Decimal::from("0.01")).await??;
    let after = token::balance(&mut runtime, HolderRef::from(&signer))
        .await?
        .unwrap();
    assert_eq!(sub_decimal(before, after)?, Decimal::from("0.01"));
    assert_eq!(token::total_supply(&mut runtime).await?, supply);
    assert_eq!(
        token::balance(&mut runtime, HolderRef::Core)
            .await?
            .unwrap_or_default(),
        Decimal::default()
    );
    assert!(
        token::burn(&mut runtime, &signer, Decimal::default())
            .await?
            .is_err()
    );
    let reserved = floor(&mut runtime, &signer).await?;
    assert!(reserved > Decimal::default() && after >= reserved);

    runtime.pricing = Pricing::new(Decimal::default(), u64::MAX)?;
    let err = staking::add_stake(&mut runtime, &signer, Decimal::from("0.01"))
        .await
        .unwrap_err();
    assert!(matches!(
        err.downcast_ref::<ExecutionError>(),
        Some(ExecutionError::Deterministic(_))
    ));
    assert!(format!("{err:#}").contains("storage reservation overflow"));
    assert_eq!(floor(&mut runtime, &signer).await?, reserved);
    assert_eq!(
        token::balance(&mut runtime, HolderRef::from(&signer)).await?,
        Some(after)
    );
    assert_eq!(
        staking::get_stake(&mut runtime, &signer)
            .await?
            .unwrap()
            .stake,
        Decimal::from("0.01")
    );
    Ok(())
}

#[test]
fn pricing_bounds_and_legacy_amounts() -> Result<()> {
    assert!(Pricing::new(Decimal::from("-1"), 1).is_err());
    assert!(Pricing::new(Decimal::default(), 0).is_err());
    let prices = Pricing::default();
    for gas in [0, 1, 100_000, u64::MAX] {
        assert_eq!(
            prices.execution_fee(gas)?,
            Pricing::storage_collateral(gas)?
        );
        assert_eq!(prices.gas_hold(gas)?, prices.execution_fee(gas)?);
    }
    Ok(())
}

proptest! {
    #[test]
    fn hold_covers_execution_and_collateral(e in 0u64..1_000_000, d in 0u64..1_000_000, spare in 0u64..1_000_000) {
        for rate in ["0", "1e-10", "1e-9", "0.00000025"] {
            let prices = Pricing::new(Decimal::from(rate), 1).unwrap();
            let released = prices.gas_hold(e + d + spare).unwrap()
                .sub(prices.execution_fee(e).unwrap()).unwrap();
            prop_assert!(released >= Pricing::storage_collateral(d).unwrap());
        }
    }
}
