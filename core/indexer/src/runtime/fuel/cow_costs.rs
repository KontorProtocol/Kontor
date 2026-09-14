use std::env;
use std::time::Instant;

use anyhow::{Result, ensure};
use serde_json::json;
use tempfile::TempDir;
use wasmtime::Engine;

use crate::database::native_contracts::NATIVE_CONTRACTS;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::nft::api as nft;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::staking::api as staking;
use crate::runtime::token::api as token;
use crate::runtime::wit::{Signer, kontor::built_in::context::HolderRef};
use crate::runtime::{ComponentCache, Decimal, Runtime};
use crate::test_utils::{make_descriptor, test_runtime};

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Balance,
    Transfer,
    AddStake,
    MintNft,
    ListNfts,
}

struct Fixture {
    runtime: Runtime,
    signer: Signer,
    recipient: HolderRef,
    _dir: TempDir,
}

impl Fixture {
    async fn new(cow: bool, keys: &[String; 2]) -> Result<Self> {
        let (mut runtime, dir, _) = test_runtime().await?;
        let signer = Signer::Id(runtime.get_or_create_identity(&keys[0]).await?);
        let recipient =
            HolderRef::from(&Signer::Id(runtime.get_or_create_identity(&keys[1]).await?));
        let core = Signer::Core(Box::new(Signer::Nobody));
        for holder in [HolderRef::from(&signer), recipient.clone()] {
            token::issue_to(&mut runtime, &core, holder, Decimal::from("1000000")).await??;
        }
        staking::add_stake(&mut runtime, &signer, Decimal::from("10")).await??;
        for i in 0..32 {
            nft::mint(
                &mut runtime,
                &signer,
                &format!("base-{i:03}"),
                vec![],
                make_descriptor(
                    format!("base-file-{i:03}"),
                    vec![1; 32],
                    16,
                    10,
                    "file.txt".into(),
                ),
            )
            .await??;
        }
        // Seed identical balances/state before switching modes, since different
        // initialization fuel during setup would otherwise change paid fees.
        let mut config = runtime.engine.config().clone();
        config.memory_init_cow(cow);
        runtime.engine = Engine::new(&config)?;
        runtime.linkers = Runtime::new_linkers(&runtime.engine)?;
        runtime.component_cache = ComponentCache::new();
        Ok(Self {
            runtime,
            signer,
            recipient,
            _dir: dir,
        })
    }

    async fn call(&mut self, scenario: Scenario, i: usize) -> Result<()> {
        match scenario {
            Scenario::Balance => {
                ensure!(
                    token::balance(&mut self.runtime, self.recipient.clone())
                        .await?
                        .is_some()
                );
            }
            Scenario::Transfer => {
                token::transfer(
                    &mut self.runtime,
                    &self.signer,
                    self.recipient.clone(),
                    Decimal::from("1"),
                )
                .await??;
            }
            Scenario::AddStake => {
                staking::add_stake(&mut self.runtime, &self.signer, Decimal::from("1")).await??;
            }
            Scenario::MintNft => {
                nft::mint(
                    &mut self.runtime,
                    &self.signer,
                    &format!("mint-{i:03}"),
                    vec![],
                    make_descriptor(
                        format!("mint-file-{i:03}"),
                        vec![2; 32],
                        16,
                        10,
                        "file.txt".into(),
                    ),
                )
                .await??;
            }
            Scenario::ListNfts => {
                ensure!(
                    nft::list_nfts(&mut self.runtime, None, 25)
                        .await?
                        .items
                        .len()
                        == 25
                );
            }
        }
        Ok(())
    }

    async fn batch(&mut self, scenario: Scenario, calls: usize) -> Result<(u128, Decimal)> {
        self.runtime.storage.savepoint().await?;
        let burned_before = token::balance(&mut self.runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        let started = Instant::now();
        for i in 0..calls {
            self.call(scenario, i).await?;
        }
        let elapsed_ns = started.elapsed().as_nanos();
        let burned_after = token::balance(&mut self.runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default();
        match scenario {
            Scenario::Transfer => ensure!(
                token::balance(&mut self.runtime, self.recipient.clone()).await?
                    == Some(Decimal::from("1000000") + Decimal::try_from(calls as u64)?)
            ),
            Scenario::AddStake => ensure!(
                staking::get_stake(&mut self.runtime, &self.signer)
                    .await?
                    .unwrap()
                    .stake
                    == Decimal::from("10") + Decimal::try_from(calls as u64)?
            ),
            Scenario::MintNft => {
                ensure!(nft::total_minted(&mut self.runtime).await? == 32 + calls as u64)
            }
            _ => {}
        }
        self.runtime.storage.rollback().await?;
        Ok((elapsed_ns, sub_decimal(burned_after, burned_before)?))
    }
}

#[tokio::test]
#[ignore = "manual paired CoW runtime latency and gas benchmark"]
async fn contract_memory_init_cow_costs() -> Result<()> {
    let samples: usize = env::var("KONTOR_COW_SAMPLES")
        .unwrap_or_else(|_| "10".into())
        .parse()?;
    let calls: usize = env::var("KONTOR_COW_CALLS")
        .unwrap_or_else(|_| "50".into())
        .parse()?;
    ensure!(samples > 0 && calls > 0);
    let keys = [random_x_only_pubkey(), random_x_only_pubkey()];
    let mut fixtures = [
        Fixture::new(false, &keys).await?,
        Fixture::new(true, &keys).await?,
    ];
    let scenarios = [
        Scenario::Balance,
        Scenario::Transfer,
        Scenario::AddStake,
        Scenario::MintNft,
        Scenario::ListNfts,
    ];

    // Warm every path, then restore database state before measured batches.
    // Profiling is disabled: user-paid execution cost comes from actual burns.
    for fixture in &mut fixtures {
        for scenario in scenarios {
            fixture.batch(scenario, calls).await?;
        }
    }
    for sample in 0..samples {
        for scenario in scenarios {
            for mode in if sample % 2 == 0 { [0, 1] } else { [1, 0] } {
                let (elapsed_ns, burned) = fixtures[mode].batch(scenario, calls).await?;
                println!(
                    "COW_BENCH {}",
                    json!({
                        "kind": "runtime", "scenario": format!("{scenario:?}"),
                        "sample": sample, "cow": mode == 1, "calls": calls,
                        "elapsed_ns": elapsed_ns, "burned_kor": burned.to_string(),
                    })
                );
            }
        }
    }

    // Exclude compilation, linker resolution, and Store construction/destruction
    // from this diagnostic; the runtime batches above include per-call plumbing.
    for (index, (name, _)) in NATIVE_CONTRACTS.iter().enumerate() {
        for sample in 0..samples {
            for mode in if sample % 2 == 0 { [0, 1] } else { [1, 0] } {
                let runtime = &fixtures[mode].runtime;
                let component = runtime.load_component(index as u64 + 1).await?;
                let pre = runtime.linkers.native.instantiate_pre(&component)?;
                let mut elapsed_ns = 0;
                let mut fuels = Vec::new();
                for _ in 0..500 {
                    let mut store = runtime.make_store(1_000_000_000)?;
                    let started = Instant::now();
                    pre.instantiate_async(&mut store).await?;
                    elapsed_ns += started.elapsed().as_nanos();
                    fuels.push(1_000_000_000 - store.get_fuel()?);
                }
                ensure!(fuels.iter().all(|fuel| *fuel == fuels[0]));
                println!(
                    "COW_BENCH {}",
                    json!({
                        "kind": "instantiate", "scenario": name,
                        "sample": sample, "cow": mode == 1, "calls": 500,
                        "elapsed_ns": elapsed_ns, "fuel": fuels[0],
                    })
                );
            }
        }
    }
    Ok(())
}
