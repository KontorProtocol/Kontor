//! Lite (in-process) tests for the congestion-pricing contract's β(t)
//! recurrence. Validates the deterministic state machine against the reference
//! values from `Documentation/modeling/kontor_v1/congestion.py`.

use anyhow::{Result, anyhow};
use indexer::runtime::Decimal;
use indexer::runtime::congestion::api as congestion;
use indexer::test_utils::test_runtime_with_genesis;
use testlib::Signer;

fn dec(n: u64) -> Decimal {
    Decimal::try_from(n).unwrap()
}

/// `n/d` as an exact fixed-point Decimal (utilizations and β values are
/// fractional). Base-10 fractions like 9/10 are exact in the fixed-point repr.
fn frac(n: u64, d: u64) -> Decimal {
    dec(n) / dec(d)
}

fn core() -> Signer {
    Signer::Core(Box::new(Signer::Nobody))
}

#[tokio::test]
async fn congestion_beta_recurrence() -> Result<()> {
    let (mut rt, _dir, _name) = test_runtime_with_genesis(&[]).await?;

    // Defaults (economics spec §Congestion Pricing).
    let p = congestion::get_congestion_params(&mut rt).await?;
    assert_eq!(p.u_low_bps, 2_000);
    assert_eq!(p.u_high_bps, 8_000);
    assert_eq!(p.lambda_decay_bps, 9_500);
    assert_eq!(p.kappa_cong_bps, 20_000);

    // β starts at 0 — at genesis utilization is low, fees ≈ 0.
    assert_eq!(congestion::get_beta(&mut rt).await?, dec(0));

    // Region 3 (u = 0.90 ≥ u_high): β = max(0,1)·(1 + 2·(0.9−0.8)) = 1.2.
    let b = congestion::update_beta(&mut rt, &core(), frac(9, 10))
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(b, frac(12, 10), "first high-util step → 1.2");

    // Sustained high util compounds: max(1.2,1)·1.2 = 1.44.
    let b = congestion::update_beta(&mut rt, &core(), frac(9, 10))
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(b, frac(144, 100), "compounding → 1.44");

    // Region 1 (u = 0.10 < u_low, free): β = 1.44·0.95 = 1.368.
    let b = congestion::update_beta(&mut rt, &core(), frac(1, 10))
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(b, frac(1368, 1000), "low-util decay → 1.368");

    // Fee multiplier = φ_base · β.
    let m = congestion::fee_multiplier(&mut rt)
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(
        m,
        p.phi_base * frac(1368, 1000),
        "fee multiplier = φ_base·β"
    );

    Ok(())
}

#[tokio::test]
async fn congestion_smoothstep_band_and_decay_floor() -> Result<()> {
    let (mut rt, _dir, _name) = test_runtime_with_genesis(&[]).await?;

    // Region 2 (u = 0.50, mid-band): x = (0.5−0.2)/(0.8−0.2) = 0.5;
    // S(x) = 3·0.25 − 2·0.125 = 0.5; max(S, 0·0.95) = 0.5.
    let b = congestion::update_beta(&mut rt, &core(), frac(5, 10))
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(b, frac(5, 10), "smoothstep at midpoint → 0.5");

    // Staying low decays toward 0: 0.5·0.95 = 0.475.
    let b = congestion::update_beta(&mut rt, &core(), frac(1, 10))
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(b, frac(475, 1000), "decay → 0.475");

    Ok(())
}

/// β(t) region/bound invariants over a deterministic random walk of
/// utilizations spanning all three regions. Checks the structural properties
/// (robust to fixed-point rounding) rather than re-deriving exact values:
/// region 1 decays (β'≤β), region 3 grows (β'≥max(β,1)), region 2 is bounded by
/// the smoothstep ceiling (β'≤max(β,1)), β never goes negative, and the fee
/// multiplier always equals φ_base·β.
#[tokio::test]
async fn congestion_beta_invariants_over_random_walk() -> Result<()> {
    let (mut rt, _dir, _name) = test_runtime_with_genesis(&[]).await?;
    let p = congestion::get_congestion_params(&mut rt).await?;
    let one = dec(1);
    let zero = dec(0);

    let mut prev = congestion::get_beta(&mut rt).await?;
    for seed in 0u64..60 {
        let u_bps = seed.wrapping_mul(167).wrapping_add(13) % 10_001; // 0..=10000
        let u = frac(u_bps, 10_000);

        let b = congestion::update_beta(&mut rt, &core(), u)
            .await?
            .map_err(|e| anyhow!("{e:?}"))?;

        assert!(b >= zero, "seed {seed}: β never negative");
        if u_bps < p.u_low_bps {
            assert!(b <= prev, "seed {seed}: region 1 decays (β' ≤ β)");
        } else if u_bps > p.u_high_bps {
            assert!(b >= one, "seed {seed}: region 3 β' ≥ 1");
            assert!(b >= prev, "seed {seed}: region 3 grows (β' ≥ β)");
        } else {
            let ceil = if prev > one { prev } else { one };
            assert!(
                b <= ceil,
                "seed {seed}: region 2 β' ≤ max(β,1) (smoothstep ≤ 1)"
            );
        }

        let m = congestion::fee_multiplier(&mut rt)
            .await?
            .map_err(|e| anyhow!("{e:?}"))?;
        assert_eq!(m, p.phi_base * b, "seed {seed}: fee multiplier = φ_base·β");

        prev = b;
    }
    Ok(())
}

/// Smoothstep is continuous with the neighbouring regions at the band edges:
/// at u_high, x=1 ⇒ S(1)=1 (joins region 3's floor); at u_low, x=0 ⇒ S(0)=0,
/// so β' is the region-1 decay floor.
#[tokio::test]
async fn congestion_smoothstep_continuous_at_band_edges() -> Result<()> {
    let (mut rt, _dir, _name) = test_runtime_with_genesis(&[]).await?;
    let p = congestion::get_congestion_params(&mut rt).await?;
    let u_low = frac(p.u_low_bps, 10_000); // 0.20
    let u_high = frac(p.u_high_bps, 10_000); // 0.80

    // Upper edge: from β=0, S(1)=1 ⇒ max(1, 0·0.95) = 1.
    let b = congestion::update_beta(&mut rt, &core(), u_high)
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(b, dec(1), "smoothstep top S(1)=1 at u_high");

    // Lower edge: now β=1, S(0)=0 ⇒ max(0, 1·0.95) = 0.95 (decay floor).
    let b = congestion::update_beta(&mut rt, &core(), u_low)
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(
        b,
        frac(95, 100),
        "smoothstep bottom S(0)=0, floored by decay 0.95"
    );

    Ok(())
}
