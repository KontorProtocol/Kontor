use anyhow::Result;

use super::funded_with_pubkey;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, TransactionContext};
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
