use std::time::Instant;

use anyhow::Result;
use serde_json::json;

use super::FuelGauge;
use crate::database::queries::get_checkpoint_by_height;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::staking::api as staking;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, ExecutionError, Runtime};
use crate::test_utils::test_runtime;

async fn fund(runtime: &mut Runtime, key: &str) -> Result<Signer> {
    let signer = Signer::Id(runtime.get_or_create_identity(key).await?);
    token::issue_to(
        runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&signer),
        Decimal::from("1000"),
    )
    .await??;
    Ok(signer)
}

#[tokio::test]
async fn optional_profiling_preserves_state_gas_and_failures() -> Result<()> {
    let key = random_x_only_pubkey();
    let mut outcomes = Vec::new();
    for profiling in [false, true] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        assert!(runtime.gauge.is_none());
        runtime.set_context(1, None, None, None).await;
        let signer = fund(&mut runtime, &key).await?;
        let gauge = profiling.then(FuelGauge::new);
        runtime.gauge = gauge.clone();

        // Includes nested token transfers, deposited storage, and a contract error.
        staking::add_stake(&mut runtime, &signer, Decimal::from("10")).await??;
        assert!(
            staking::add_stake(&mut runtime, &signer, Decimal::from("-1"))
                .await?
                .is_err()
        );
        let normal_limit = runtime.gas_limit_for_non_procs;
        runtime.gas_limit_for_non_procs = 1;
        let exhausted = staking::add_stake(&mut runtime, &signer, Decimal::from("1"))
            .await
            .unwrap_err();
        assert!(matches!(
            exhausted.downcast_ref::<ExecutionError>(),
            Some(ExecutionError::Deterministic(_))
        ));
        runtime.gas_limit_for_non_procs = normal_limit;
        staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
        assert_eq!(
            staking::get_stake(&mut runtime, &signer)
                .await?
                .unwrap()
                .stake,
            Decimal::from("11")
        );
        let balance = token::balance(&mut runtime, HolderRef::from(&signer)).await?;
        let floor = token::floor(&mut runtime, HolderRef::from(&signer)).await?;
        let burned = token::balance(&mut runtime, HolderRef::Burner).await?;
        let conn = runtime.get_storage_conn();
        let checkpoint = get_checkpoint_by_height(&conn, 1).await?.unwrap();
        let mut rows = conn
            .query(
                "SELECT func, gas, status FROM contract_results ORDER BY id",
                (),
            )
            .await?;
        let mut results = Vec::new();
        while let Some(row) = rows.next().await? {
            results.push((
                row.get::<String>(0)?,
                row.get::<u64>(1)?,
                row.get::<String>(2)?,
            ));
        }
        if let Some(gauge) = gauge {
            assert!(gauge.total_host_fuel().await > 0);
            assert!(!gauge.history().await.is_empty());
        }
        outcomes.push((checkpoint, results, balance, floor, burned));
    }
    assert_eq!(outcomes[0], outcomes[1]);
    Ok(())
}

#[tokio::test]
#[ignore = "manual warm runtime profiling overhead measurement"]
async fn fuel_profiling_costs() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let signer = fund(&mut runtime, &random_x_only_pubkey()).await?;
    staking::add_stake(&mut runtime, &signer, Decimal::from("10")).await??;

    // Roll back between samples so each mode performs the same writes. Alternate
    // order to reduce cache/thermal bias; timings are observations, never assertions.
    for sample in 0..7 {
        for profiling in if sample % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            runtime.storage.savepoint().await?;
            let before = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            let gauge = profiling.then(FuelGauge::new);
            runtime.gauge = gauge.clone();
            let started = Instant::now();
            for _ in 0..100 {
                staking::add_stake(&mut runtime, &signer, Decimal::from("1")).await??;
            }
            let elapsed = started.elapsed();
            runtime.gauge = None;
            let after = token::balance(&mut runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default();
            let events = if let Some(gauge) = gauge {
                gauge.history().await.len()
            } else {
                0
            };
            println!(
                "FUEL_PROFILE {}",
                json!({
                    "sample": sample, "profiling": profiling, "calls": 100,
                    "elapsed_us": elapsed.as_micros(), "retained_events": events,
                    "burned_kor": sub_decimal(after, before)?.to_string(),
                })
            );
            runtime.storage.rollback().await?;
        }
    }
    Ok(())
}
