//! Lite tests for the token contract's service-emission primitive:
//! `mint_emission` computes ε = supply·μ₀/B, mints it to the protocol pool, and
//! reports the storage/ordering split; params are admin-tunable via
//! `set_emission_params`.

use anyhow::{Result, anyhow};
use indexer::keygen::derive_validator;
use indexer::runtime::token::api as token;
use indexer::runtime::{Decimal, GenesisValidator};
use indexer::test_utils::test_runtime_with_genesis;
use testlib::Signer;

fn dec(n: u64) -> Decimal {
    Decimal::try_from(n).unwrap()
}

fn core() -> Signer {
    Signer::Core(Box::new(Signer::Nobody))
}

/// One genesis validator staking `stake` KOR — its stake is minted at genesis,
/// so `total_supply == stake`.
fn one_validator(stake: u64) -> Vec<GenesisValidator> {
    let k = derive_validator(&[0x22u8; 32], 0);
    vec![GenesisValidator {
        x_only_pubkey: hex::encode(k.x_only_pubkey),
        stake: dec(stake),
        ed25519_pubkey: k.ed25519_pubkey.to_vec(),
    }]
}

#[tokio::test]
async fn emission_params_default_to_spec_values() -> Result<()> {
    let (mut rt, _dir, _name) = test_runtime_with_genesis(&[]).await?;
    let p = token::emission_params(&mut rt).await?;
    assert_eq!(p.mu0_bps, 500, "μ₀ = 5%");
    assert_eq!(p.chi_bps, 1000, "χ = 10%");
    assert_eq!(p.blocks_per_year, 52_560, "B");
    Ok(())
}

#[tokio::test]
async fn mint_emission_computes_epsilon_and_splits() -> Result<()> {
    let (mut rt, _dir, _name) = test_runtime_with_genesis(&one_validator(1000)).await?;

    // Override params for an exact assertion: μ₀=100%, χ=20%, B=10
    //   ε = 1000 · 1.0 / 10 = 100 ; ordering = ε·0.2 = 20 ; storage = 80.
    token::set_emission_params(&mut rt, &core(), 10_000, 2_000, 10)
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;

    let r = token::mint_emission(&mut rt, &core())
        .await?
        .map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(r.total, dec(100), "ε = supply·μ₀/B");
    assert_eq!(r.ordering, dec(20), "ordering = ε·χ");
    assert_eq!(r.storage, dec(80), "storage = ε − ordering");

    assert_eq!(
        token::total_supply(&mut rt).await?,
        dec(1100),
        "supply grew by the minted emission"
    );
    Ok(())
}
