//! Lite (in-process, no cluster) tests for the staking contract's slashing
//! surface: `slash` and `distribute_slash`. Uses `test_runtime_with_genesis`
//! to stand up active, funded validators, then drives the core-context methods
//! directly via the auto-generated `staking::api` host wrappers.

use anyhow::{Result, anyhow};
use indexer::keygen::derive_validator;
use indexer::runtime::staking::api as staking;
use indexer::runtime::{Decimal, GenesisValidator};
use indexer::test_utils::test_runtime_with_genesis;
use testlib::Signer;

fn dec(n: u64) -> Decimal {
    Decimal::try_from(n).unwrap()
}

fn core() -> Signer {
    Signer::Core(Box::new(Signer::Nobody))
}

/// `n` genesis validators each staking `stake`, returning their x-only pubkeys.
fn validators(n: u32, stake: u64) -> (Vec<GenesisValidator>, Vec<String>) {
    let seed = [0x11u8; 32];
    let (mut gvs, mut pks) = (Vec::new(), Vec::new());
    for i in 0..n {
        let k = derive_validator(&seed, i);
        let pk = hex::encode(k.x_only_pubkey);
        gvs.push(GenesisValidator {
            x_only_pubkey: pk.clone(),
            stake: dec(stake),
            ed25519_pubkey: k.ed25519_pubkey.to_vec(),
        });
        pks.push(pk);
    }
    (gvs, pks)
}

#[tokio::test]
async fn slash_reduces_stake_burns_tau_and_returns_remainder() -> Result<()> {
    let (gvs, pks) = validators(3, 100);
    let (mut rt, _dir, _name) = test_runtime_with_genesis(&gvs).await?;

    // τ_slash default = 50% (5000 bps): slashing 40 burns 20, leaves 20 to redistribute.
    let res = staking::slash(&mut rt, &core(), &pks[0], dec(40))
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(res.slashed, dec(40), "slashed");
    assert_eq!(res.burned, dec(20), "burned (τ_slash share)");
    assert_eq!(res.redistributable, dec(20), "redistributable remainder");

    let v = staking::get_validator(&mut rt, &pks[0])
        .await?
        .expect("validator 0 exists");
    assert_eq!(v.stake, dec(60), "stake reduced 100 -> 60");
    Ok(())
}

#[tokio::test]
async fn slash_saturates_at_stake() -> Result<()> {
    let (gvs, pks) = validators(1, 100);
    let (mut rt, _dir, _name) = test_runtime_with_genesis(&gvs).await?;

    // Slash more than the stake: deduction saturates at k_n, shortfall not carried.
    let res = staking::slash(&mut rt, &core(), &pks[0], dec(1000))
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(res.slashed, dec(100), "saturates at the node's full stake");

    let v = staking::get_validator(&mut rt, &pks[0])
        .await?
        .expect("validator 0 exists");
    assert_eq!(v.stake, dec(0), "stake driven to zero");
    Ok(())
}

#[tokio::test]
async fn distribute_slash_credits_recipients_evenly() -> Result<()> {
    let (gvs, pks) = validators(3, 100);
    let (mut rt, _dir, _name) = test_runtime_with_genesis(&gvs).await?;

    // Redistribute 30 across nodes 1 and 2 -> 15 each (even split, exact).
    staking::distribute_slash(&mut rt, &core(), vec![pks[1].as_str(), pks[2].as_str()], dec(30))
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;

    for pk in [&pks[1], &pks[2]] {
        let v = staking::get_validator(&mut rt, pk)
            .await?
            .expect("recipient exists");
        assert_eq!(v.stake, dec(115), "recipient credited 100 + 15");
    }
    // Non-recipient untouched.
    let v0 = staking::get_validator(&mut rt, &pks[0])
        .await?
        .expect("validator 0 exists");
    assert_eq!(v0.stake, dec(100), "non-recipient unchanged");
    Ok(())
}
