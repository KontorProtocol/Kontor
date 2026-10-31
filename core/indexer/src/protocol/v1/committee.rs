use anyhow::{Context, Result};
use malachitebft_app_channel::app::types::core::VotingPower;

use crate::consensus::{Validator, ValidatorSet, signing::PublicKey};
use crate::runtime::{
    Decimal, Runtime,
    numerics::decimal_to_string,
    staking::{
        address as staking_address,
        api::wave::{get_active_set_call_expr, get_active_set_parse_return_expr},
    },
};

pub(crate) async fn build_validator_set(runtime: &mut Runtime) -> Result<ValidatorSet> {
    let result = runtime
        .execute_system_view(&staking_address(), &get_active_set_call_expr())
        .await
        .context("Failed to query active validator set from staking contract")?;
    let active_set = get_active_set_parse_return_expr(&result);

    let validators: Vec<Validator> = active_set
        .into_iter()
        .map(|v| {
            anyhow::ensure!(
                v.ed25519_pubkey.len() == 32,
                "Validator {} has invalid ed25519 pubkey length {}",
                v.x_only_pubkey,
                v.ed25519_pubkey.len()
            );
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&v.ed25519_pubkey);
            let public_key = PublicKey::from_bytes(key_bytes).with_context(|| {
                format!("Invalid ed25519 pubkey for validator {}", v.x_only_pubkey)
            })?;
            let voting_power = stake_to_voting_power(v.stake)
                .with_context(|| format!("Invalid stake for validator {}", v.x_only_pubkey))?;
            Ok(Validator::new(public_key, voting_power))
        })
        .collect::<Result<Vec<_>>>()?;

    ValidatorSet::try_new(validators)
}

pub(crate) fn stake_to_voting_power(stake: Decimal) -> Result<VotingPower> {
    let s = decimal_to_string(stake);
    let integer_part = s
        .split('.')
        .next()
        .context("decimal string missing integer part")?;
    let power = integer_part
        .parse::<u64>()
        .context("stake integer part is not a valid u64")?;
    anyhow::ensure!(power > 0, "stake is below one voting power unit");
    Ok(power)
}
