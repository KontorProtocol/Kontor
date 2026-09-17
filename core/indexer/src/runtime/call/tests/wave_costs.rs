use std::time::Instant;

use anyhow::{Result, ensure};
use indexer_types::Payment;
use serde_json::json;

use super::{call_chain, funded};
use crate::runtime::fuel::ExecutionUsage;
use crate::runtime::wit::Signer;
use crate::runtime::{ContractAddress, Decimal, Runtime, TransactionContext, staking, token};
use crate::test_utils::test_runtime;

struct Case {
    name: String,
    target: ContractAddress,
    expression: String,
    paid: bool,
}

async fn observation(
    runtime: &mut Runtime,
    actor: &Signer,
    case: &Case,
) -> Result<(u128, u64, ExecutionUsage, usize, bool)> {
    runtime.storage.savepoint().await?;
    let payment = case.paid.then(|| Payment {
        signer_id: actor.signer_id().unwrap(),
        gas_limit: runtime.gas_limit_for_non_procs,
    });
    let limit = if case.paid {
        runtime.fuel_limit_for_non_procs()
    } else {
        runtime.fuel_limit_for_view()
    };
    let previous = runtime.start_usage();
    let start = Instant::now();
    let outcome = runtime
        .invoke(
            &case.target,
            case.paid.then_some(actor),
            payment.as_ref(),
            &case.expression,
            None,
        )
        .await?;
    let elapsed = start.elapsed().as_nanos();
    let usage = runtime.finish_usage(previous)?;
    let fuel = limit - outcome.remaining_fuel;
    let (bytes, success) = match outcome.result {
        Ok(value) => (value.len(), !value.starts_with("err(")),
        Err(_) => (0, false),
    };
    runtime.storage.rollback().await?;
    ensure!(runtime.stack.is_empty().await, "call leaked a frame");
    Ok((elapsed, fuel, usage, bytes, success))
}

async fn measure(
    runtime: &mut Runtime,
    actor: &Signer,
    cases: &[Case],
    rounds: usize,
    repetitions: usize,
) -> Result<()> {
    let mut samples = vec![Vec::new(); cases.len()];
    let mut observations = Vec::new();
    for case in cases {
        let (_, fuel, usage, bytes, success) = observation(runtime, actor, case).await?;
        observations.push((fuel, usage, bytes, success));
        for _ in 0..3 {
            observation(runtime, actor, case).await?;
        }
    }
    // Rotate case order and restore state after each invocation. Setup, JIT warmup,
    // outer transaction rollback and reporting are outside the measured interval.
    for round in 0..rounds {
        for offset in 0..cases.len() {
            let index = (round + offset) % cases.len();
            let mut elapsed = 0;
            for _ in 0..repetitions {
                let (time, fuel, usage, bytes, success) =
                    observation(runtime, actor, &cases[index]).await?;
                ensure!(
                    (fuel, usage, bytes, success) == observations[index],
                    "unstable accounting: {}",
                    cases[index].name
                );
                elapsed += time;
            }
            samples[index].push(elapsed as f64 / repetitions as f64 / 1000.0);
        }
    }
    for (index, case) in cases.iter().enumerate() {
        samples[index].sort_by(f64::total_cmp);
        let (fuel, usage, bytes, success) = observations[index];
        println!(
            "WAVE_COST {}",
            json!({
                "name": case.name, "paid": case.paid,
                "median_us": samples[index][rounds / 2], "min_us": samples[index][0], "max_us": samples[index][rounds - 1],
                "fuel": fuel, "execution_gas": fuel.saturating_sub(usage.deposit_fuel).div_ceil(runtime.gas_to_fuel_multiplier),
                "system_fuel": usage.system_fuel, "deposit_fuel": usage.deposit_fuel,
                "gas_limit": if case.paid { runtime.gas_limit_for_non_procs } else { runtime.view_gas_limit },
                "input_bytes": case.expression.len(), "output_bytes": bytes, "success": success,
                "rounds": rounds, "repetitions": repetitions
            })
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "manual whole-call WAVE latency and default-budget comparison against main"]
async fn wave_call_costs() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let recipient = funded(&mut runtime).await?;
    let chain = call_chain(&mut runtime, &actor).await?;
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(3).build()),
            None,
            None,
        )
        .await;
    runtime
        .storage
        .insert_contract(
            "wave-crypto",
            include_bytes!("../../../../../../test-contracts/binaries/crypto.wasm.br"),
        )
        .await?;
    let crypto = ContractAddress {
        name: "wave-crypto".into(),
        height: 1,
        tx_index: 3,
    };
    runtime.execute_api(Some(&actor), &crypto, "init()").await?;
    runtime.set_context(1, None, None, None).await;

    let mut cases = Vec::new();
    for (name, expression, paid) in [
        ("scalar-view", "succeed()", false),
        ("storage-view", "storage-state()", false),
        ("string-output-2k", "result-payload(512)", false),
        ("string-output-16k", "result-payload(4096)", false),
        ("string-output-128k", "result-payload(32768)", false),
        ("storage-write", "write-result-payload(128)", true),
        ("mixed-storage-write", "primitive-entries()", true),
    ] {
        for (depth, target) in [(0, &chain[0]), (2, &chain[2])] {
            cases.push(Case {
                name: format!("{name}-depth-{depth}"),
                target: target.clone(),
                expression: expression.into(),
                paid,
            });
        }
    }
    cases.push(Case {
        name: "token-balance".into(),
        target: token::address(),
        expression: format!("balance(signer-id({}))", actor.signer_id().unwrap()),
        paid: false,
    });
    cases.push(Case {
        name: "token-transfer".into(),
        target: token::address(),
        expression: format!(
            "transfer(signer-id({}), {})",
            recipient.signer_id().unwrap(),
            stdlib::to_wave_expr(Decimal::from("1"))
        ),
        paid: true,
    });
    cases.push(Case {
        name: "staking-add-stake".into(),
        target: staking::address(),
        expression: format!("add-stake({})", stdlib::to_wave_expr(Decimal::from("1"))),
        paid: true,
    });
    for length in [16, 256, 4096, 16384, 65536] {
        cases.push(Case {
            name: format!("sha256-bytes-{length}"),
            target: crypto.clone(),
            expression: format!("sha256([{}])", vec!["255"; length].join(",")),
            paid: false,
        });
    }
    measure(&mut runtime, &actor, &cases, 7, 15).await?;

    // Native list results include database reads, guest execution, ABI lifting,
    // WAVE encoding and records with enum/numeric payloads.
    for holders in [16, 128, 512] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let actor = funded(&mut runtime).await?;
        for _ in 1..holders {
            funded(&mut runtime).await?;
        }
        let cases = [Case {
            name: format!("native-balances-{holders}"),
            target: token::address(),
            expression: "balances()".into(),
            paid: false,
        }];
        measure(&mut runtime, &actor, &cases, 7, 5).await?;
    }
    Ok(())
}
