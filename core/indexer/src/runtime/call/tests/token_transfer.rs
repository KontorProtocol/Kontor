use anyhow::Result;
use stdlib::{KeyElement, KeyPath};

use super::funded_with_pubkey;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::numerics::{add_decimal, sub_decimal};
use crate::runtime::token::{address as token_address, api as token};
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, NumericSign, TransactionContext};
use crate::test_utils::test_runtime;

#[tokio::test]
async fn token_self_transfer_conserves_balance_and_supply_after_fees() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let pubkey = random_x_only_pubkey();
    let signer = funded_with_pubkey(&mut runtime, &pubkey).await?;
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(8).build()),
            None,
            None,
        )
        .await;

    for destination in [
        HolderRef::from(&signer),
        HolderRef::XOnlyPubkey(pubkey.clone()),
    ] {
        let before = token::balance(&mut runtime, HolderRef::from(&signer))
            .await?
            .expect("funded signer balance");
        let burner_before = token::balance(&mut runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        let supply_before = token::total_supply(&mut runtime).await?;
        token::transfer(&mut runtime, &signer, destination, Decimal::from("5")).await??;
        let after = token::balance(&mut runtime, HolderRef::from(&signer))
            .await?
            .expect("signer balance after self-transfer");
        let burner_after = token::balance(&mut runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        let supply_after = token::total_supply(&mut runtime).await?;
        let fee = sub_decimal(burner_after, burner_before)?;
        assert_eq!(sub_decimal(before, after)?, fee);
        assert_eq!(sub_decimal(supply_before, supply_after)?, fee);
    }

    let core = Signer::Core(Box::new(Signer::Nobody));
    token::issue_to(&mut runtime, &core, HolderRef::Core, Decimal::from("25")).await??;
    let core_before = token::balance(&mut runtime, HolderRef::Core)
        .await?
        .expect("issued core balance");
    token::transfer(&mut runtime, &core, HolderRef::Core, core_before).await??;
    assert_eq!(
        token::balance(&mut runtime, HolderRef::Core).await?,
        Some(core_before)
    );
    assert!(
        token::transfer(&mut runtime, &core, HolderRef::Core, Decimal::default())
            .await?
            .is_err()
    );
    assert!(
        token::transfer(
            &mut runtime,
            &core,
            HolderRef::Core,
            Decimal::from("1000000000"),
        )
        .await?
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn token_distinct_transfer_preserves_credit_and_storage_floor() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let source = funded_with_pubkey(&mut runtime, &random_x_only_pubkey()).await?;
    let destination = funded_with_pubkey(&mut runtime, &random_x_only_pubkey()).await?;
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(9).build()),
            None,
            None,
        )
        .await;

    let src_before = token::balance(&mut runtime, HolderRef::from(&source))
        .await?
        .expect("source balance");
    let dst_before = token::balance(&mut runtime, HolderRef::from(&destination))
        .await?
        .expect("destination balance");
    let burner_before = token::balance(&mut runtime, HolderRef::Burner)
        .await?
        .unwrap_or_default();
    token::transfer(
        &mut runtime,
        &source,
        HolderRef::from(&destination),
        Decimal::from("5"),
    )
    .await??;
    let src_after = token::balance(&mut runtime, HolderRef::from(&source))
        .await?
        .expect("source after transfer");
    let dst_after = token::balance(&mut runtime, HolderRef::from(&destination))
        .await?
        .expect("destination after transfer");
    let burner_after = token::balance(&mut runtime, HolderRef::Burner)
        .await?
        .unwrap_or_default();
    let fee = sub_decimal(burner_after, burner_before)?;
    assert_eq!(
        sub_decimal(src_before, src_after)?,
        add_decimal(Decimal::from("5"), fee)?
    );
    assert_eq!(sub_decimal(dst_after, dst_before)?, Decimal::from("5"));

    let floor = token::floor(&mut runtime, HolderRef::from(&source)).await?;
    let source_id = source.signer_id().expect("funded source signer id");
    let contract_id = runtime
        .storage
        .contract_id(&token_address())
        .await?
        .expect("native token contract");
    let floor_path = KeyPath::new().push("floor-test");
    runtime
        .storage
        .footprint()
        .on_set(
            contract_id,
            floor_path.as_bytes(),
            Some(source_id),
            Some(1_000_000),
        )
        .await?;
    runtime
        .storage
        .set(
            contract_id,
            floor_path.as_bytes(),
            &[1],
            Some(source_id),
            Some(1_000_000),
        )
        .await?;
    let exercised_floor = token::floor(&mut runtime, HolderRef::from(&source)).await?;
    assert!(exercised_floor > floor && exercised_floor < src_after);
    let source_before_rejection = src_after;
    let destination_before_rejection = dst_after;
    let too_much = sub_decimal(source_before_rejection, exercised_floor)?;
    let result = token::transfer(
        &mut runtime,
        &source,
        HolderRef::from(&destination),
        too_much,
    )
    .await?;
    let error = result.expect_err("the deposit floor must reject a near-full debit");
    assert!(
        error.to_string().contains("storage deposit floor exceeded"),
        "unexpected rejection: {error}"
    );
    assert_eq!(
        token::balance(&mut runtime, HolderRef::from(&destination)).await?,
        Some(destination_before_rejection)
    );
    assert!(
        token::balance(&mut runtime, HolderRef::from(&source))
            .await?
            .expect("source after rejection")
            <= source_before_rejection
    );
    Ok(())
}

#[tokio::test]
async fn failed_destination_credit_rolls_back_prior_debit() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let source = funded_with_pubkey(&mut runtime, &random_x_only_pubkey()).await?;
    let destination = funded_with_pubkey(&mut runtime, &random_x_only_pubkey()).await?;
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(10).build()),
            None,
            None,
        )
        .await;

    // Seed the destination at the wire maximum to exercise a credit overflow
    // that ordinary supply-conserving issuance cannot reach.
    let maximum = Decimal {
        r0: u64::MAX,
        r1: u64::MAX,
        r2: u64::MAX,
        r3: u64::MAX,
        sign: NumericSign::Plus,
    };
    let contract_id = runtime
        .storage
        .contract_id(&token_address())
        .await?
        .expect("native token contract");
    let destination_key = HolderRef::from(&destination).to_string();
    let path = KeyPath::new().push_interned(0).push(destination_key);
    runtime
        .storage
        .set(
            contract_id,
            path.as_bytes(),
            &postcard::to_allocvec(&maximum.encode())?,
            None,
            None,
        )
        .await?;
    assert_eq!(
        token::balance(&mut runtime, HolderRef::from(&destination)).await?,
        Some(maximum)
    );

    let source_before = token::balance(&mut runtime, HolderRef::from(&source))
        .await?
        .expect("source balance");
    let burner_before = token::balance(&mut runtime, HolderRef::Burner)
        .await?
        .unwrap_or_default();
    let supply_before = token::total_supply(&mut runtime).await?;
    let result = token::transfer(
        &mut runtime,
        &source,
        HolderRef::from(&destination),
        Decimal::from("1"),
    )
    .await?;
    let error = result.expect_err("destination credit must overflow");
    assert!(
        error.to_string().to_lowercase().contains("overflow"),
        "unexpected rejection: {error}"
    );
    let source_after = token::balance(&mut runtime, HolderRef::from(&source))
        .await?
        .expect("source balance after rejection");
    let burner_after = token::balance(&mut runtime, HolderRef::Burner)
        .await?
        .unwrap_or_default();
    let supply_after = token::total_supply(&mut runtime).await?;
    let fee = sub_decimal(burner_after, burner_before)?;
    assert_eq!(sub_decimal(source_before, source_after)?, fee);
    assert_eq!(sub_decimal(supply_before, supply_after)?, fee);
    assert_eq!(
        token::balance(&mut runtime, HolderRef::from(&destination)).await?,
        Some(maximum)
    );
    Ok(())
}
