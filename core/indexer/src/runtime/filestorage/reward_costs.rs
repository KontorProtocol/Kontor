use std::collections::BTreeMap;
use std::ops::AsyncFnOnce;
use std::time::Instant;

use anyhow::{Result, ensure};
use serde_json::json;

use super::api;
use super::settlement_tests::{StorageFixture, at_height};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::fuel::FuelGauge;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::staking::api as staking;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::{Decimal, Runtime};
use crate::test_utils::test_runtime;

async fn measured<T>(
    runtime: &mut Runtime,
    operation: &str,
    members: usize,
    files: usize,
    call: impl AsyncFnOnce(&mut Runtime) -> Result<T>,
) -> Result<T> {
    let gauge = FuelGauge::new();
    runtime.gauge = Some(gauge.clone());
    let started = Instant::now();
    let result = call(runtime).await?;
    let elapsed = started.elapsed();
    let operations: BTreeMap<_, _> = gauge
        .per_type_stats()
        .await
        .into_iter()
        .map(|(kind, stats)| (format!("{kind:?}"), stats.count))
        .collect();
    println!(
        "REWARD_COST {}",
        json!({
            "operation": operation,
            "members": members,
            "files": files,
            "elapsed_us": elapsed.as_micros(),
            "host_fuel": gauge.total_host_fuel().await,
            "host_operations": operations,
        })
    );
    Ok(result)
}

#[tokio::test]
#[ignore = "manual reward fuel and storage cost measurements"]
async fn reward_costs_across_membership_and_file_counts() -> Result<()> {
    let core = Signer::Core(Box::new(Signer::Nobody));
    for (members, files) in [(3, 1), (9, 1), (32, 1), (128, 1), (3, 16), (3, 64)] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let keys: Vec<_> = (0..members).map(|_| random_x_only_pubkey()).collect();
        let fixture = StorageFixture::new(&mut runtime, files, &keys).await?;
        fixture.join(&mut runtime, Decimal::from("1000")).await?;
        let (node, signer) = &fixture.hosts[0];
        let file = &fixture.agreements[0];
        at_height(&mut runtime, 2).await?;
        token::mint_emission(&mut runtime, &core, false).await??;
        measured(&mut runtime, "accrue", members, files, async |rt| {
            Ok(api::accrue_storage_rewards(rt, &core).await??)
        })
        .await?;
        let expected = api::reward_balance(&mut runtime, *node).await??;
        ensure!(expected > Decimal::default());
        let paid = measured(&mut runtime, "claim", members, files, async |rt| {
            Ok(api::claim_rewards(rt, signer).await??)
        })
        .await?;
        ensure!(paid == expected);
        measured(&mut runtime, "leave", members, files, async |rt| {
            Ok(api::leave_agreement(rt, signer, file).await??)
        })
        .await?;
        measured(&mut runtime, "join", members, files, async |rt| {
            Ok(api::join_agreement(rt, signer, file).await??)
        })
        .await?;

        fixture.challenge(&mut runtime, 0, 2).await?;
        staking::slash(
            &mut runtime,
            &core,
            *node,
            sub_decimal(Decimal::from("1000"), Decimal::from("0.000000000000000001"))?,
        )
        .await??;
        at_height(&mut runtime, 2019).await?;
        api::expire_challenges(&mut runtime, &core, 2019).await?;
        let mut completed = false;
        for _ in 0..100 {
            measured(&mut runtime, "cleanup", members, files, async |rt| {
                Ok(api::settle_expired_challenges(rt, &core).await??)
            })
            .await?;
            if !api::is_bond_cleanup_pending(&mut runtime, *node).await? {
                completed = true;
                break;
            }
            // A claim may fold its pending weight change early. Roll it back so
            // the cleanup measurements still cover the full background job.
            runtime.storage.savepoint().await?;
            measured(
                &mut runtime,
                "claim_during_cleanup",
                members,
                files,
                async |rt| Ok(api::claim_rewards(rt, &fixture.hosts[members - 1].1).await??),
            )
            .await?;
            runtime.storage.rollback().await?;
        }
        ensure!(completed, "cleanup did not finish");
        ensure!(!api::is_node_in_agreement(&mut runtime, file, *node).await?);
    }
    Ok(())
}
