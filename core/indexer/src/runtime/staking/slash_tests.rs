use anyhow::Result;

use super::api::{self, ValidatorStatus};
use super::reward_tests::escrow;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Error};
use crate::test_utils::test_runtime;

#[tokio::test]
async fn slash_burns_shared_bond_and_preserves_each_validator_status_aggregate() -> Result<()> {
    for status in [
        ValidatorStatus::Inactive,
        ValidatorStatus::PendingJoin,
        ValidatorStatus::Active,
        ValidatorStatus::PendingExit,
    ] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let core = Signer::Core(Box::new(Signer::Nobody));
        let identity = runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?;
        let id = identity.signer_id();
        let signer = Signer::Id(identity);
        token::issue_to(
            &mut runtime,
            &core,
            HolderRef::from(&signer),
            Decimal::from("100"),
        )
        .await??;
        api::add_stake(&mut runtime, &signer, Decimal::from("10")).await??;
        if status != ValidatorStatus::Inactive {
            api::register_validator(&mut runtime, &signer, vec![7; 32], Decimal::default())
                .await??;
            if status != ValidatorStatus::PendingJoin {
                api::process_pending_validators(&mut runtime, &core, 13).await??;
            }
            if status == ValidatorStatus::PendingExit {
                api::leave_validation(&mut runtime, &signer).await??;
            }
        }
        let counted = matches!(
            status,
            ValidatorStatus::Active | ValidatorStatus::PendingExit
        );
        let supply = token::total_supply(&mut runtime).await?;
        let balance = escrow(&mut runtime).await?;
        assert!(
            api::slash(&mut runtime, &signer, id, Decimal::from("3"))
                .await
                .is_err()
        );
        assert_eq!(
            api::slash(&mut runtime, &core, id, Decimal::from("-1")).await?,
            Err(Error::Message("negative penalty".into()))
        );
        let zero = api::slash(&mut runtime, &core, id, Decimal::default()).await??;
        assert_eq!(zero.burned, Decimal::default());
        assert_eq!(zero.remaining, Decimal::from("10"));
        let partial = api::slash(&mut runtime, &core, id, Decimal::from("3")).await??;
        assert_eq!(partial.burned, Decimal::from("3"));
        assert_eq!(partial.remaining, Decimal::from("7"));
        assert_eq!(
            api::get_validator(&mut runtime, &id.to_string())
                .await?
                .map(|v| v.status)
                .unwrap_or(ValidatorStatus::Inactive),
            status
        );
        assert_eq!(
            api::get_staking_info(&mut runtime).await?.total_stake,
            if counted {
                Decimal::from("7")
            } else {
                Decimal::default()
            }
        );
        assert_eq!(
            sub_decimal(supply, token::total_supply(&mut runtime).await?)?,
            Decimal::from("3")
        );
        assert_eq!(
            sub_decimal(balance, escrow(&mut runtime).await?)?,
            Decimal::from("3")
        );

        runtime.storage.savepoint().await?;
        let exhausted = api::slash(&mut runtime, &core, id, Decimal::from("100")).await??;
        assert_eq!(exhausted.burned, Decimal::from("7"));
        assert_eq!(exhausted.remaining, Decimal::default());
        assert_eq!(
            api::get_validator(&mut runtime, &id.to_string())
                .await?
                .map(|v| v.status)
                .unwrap_or(ValidatorStatus::Inactive),
            ValidatorStatus::Inactive
        );
        assert_eq!(
            api::get_staking_info(&mut runtime).await?.total_stake,
            Decimal::default()
        );
        runtime.storage.rollback().await?;
        assert_eq!(
            api::get_validator(&mut runtime, &id.to_string())
                .await?
                .map(|v| v.status)
                .unwrap_or(ValidatorStatus::Inactive),
            status
        );
        assert_eq!(
            api::get_stake(&mut runtime, &id.to_string())
                .await?
                .unwrap()
                .stake,
            Decimal::from("7")
        );
        assert_eq!(
            escrow(&mut runtime).await?,
            sub_decimal(balance, Decimal::from("3"))?
        );
    }
    Ok(())
}
