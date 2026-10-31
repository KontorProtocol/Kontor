use anyhow::{Context, Result, anyhow, ensure};
use malachitebft_signing_ed25519::PublicKey;
use sha3::{Digest, Keccak256};

use crate::protocol::committee::Committee;
use crate::runtime::{
    Decimal, Runtime,
    numerics::decimal_to_string,
    staking::{
        address as staking_address,
        api::wave::{get_active_set_call_expr, get_active_set_parse_return_expr},
    },
};

pub(crate) async fn derive_committee(runtime: &mut Runtime) -> Result<Committee> {
    let result = runtime
        .execute_system_view(&staking_address(), &get_active_set_call_expr())
        .await
        .context("Failed to query active validator set from staking contract")?;
    let active_set = get_active_set_parse_return_expr(&result);

    let validators: Committee = active_set
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
            let hash = Keccak256::digest(public_key.as_bytes());
            let mut address = [0; 20];
            address.copy_from_slice(&hash[..20]);
            Ok((address, key_bytes, voting_power))
        })
        .collect::<Result<Vec<_>>>()?;

    validate_committee(&validators)?;
    Ok(validators)
}

fn validate_committee(validators: &Committee) -> Result<()> {
    // These are P1's original set checks. In particular, P1 neither sorts nor
    // deduplicates the staking contract's result at this boundary.
    ensure!(!validators.is_empty(), "validator set is empty");
    let total = validators.iter().try_fold(0u64, |total, (_, _, power)| {
        ensure!(*power > 0, "validator has zero voting power");
        total
            .checked_add(*power)
            .ok_or_else(|| anyhow!("total voting power overflow"))
    })?;
    ensure!(
        total <= u64::MAX / 3,
        "total voting power exceeds quorum arithmetic limit"
    );
    Ok(())
}

pub(crate) fn stake_to_voting_power(stake: Decimal) -> Result<u64> {
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

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::{derive_committee, validate_committee};
    use crate::consensus::{Validator, ValidatorSet, signing::PrivateKey};
    use crate::protocol::committee::Committee;
    use crate::reg_tester::random_x_only_pubkey;
    use crate::runtime::{Decimal, GenesisValidator};
    use crate::test_utils::test_runtime_with_genesis;

    #[tokio::test]
    async fn native_staking_derivation_preserves_p1_key_address_and_stake() -> Result<()> {
        let key = PrivateKey::from([7; 32]).public_key();
        let (mut runtime, _dir, _name) = test_runtime_with_genesis(&[GenesisValidator {
            x_only_pubkey: random_x_only_pubkey(),
            ed25519_pubkey: key.as_bytes().to_vec(),
            stake: Decimal::from("100.9999999"),
        }])
        .await?;
        runtime.view_gas_limit = 0;
        let expected = Validator::new(key, 100);
        assert_eq!(
            derive_committee(&mut runtime).await?,
            vec![(expected.address.into_inner(), *key.as_bytes(), 100)]
        );
        Ok(())
    }

    #[test]
    fn retained_set_rules_match_p1_at_arithmetic_boundaries() {
        let key = PrivateKey::from([1; 32]).public_key();
        for powers in [
            vec![],
            vec![0],
            vec![1, 0],
            vec![1, 1],
            vec![u64::MAX / 3],
            vec![u64::MAX / 3 - 1, 1],
            vec![u64::MAX / 3, 1],
            vec![u64::MAX, 1],
        ] {
            let original = powers
                .iter()
                .map(|power| Validator::new(key, *power))
                .collect::<Vec<_>>();
            let retained: Committee = original
                .iter()
                .map(|v| {
                    (
                        v.address.into_inner(),
                        *v.public_key.as_bytes(),
                        v.voting_power,
                    )
                })
                .collect();
            let expected = ValidatorSet::try_new(original)
                .map(|_| ())
                .map_err(|error| format!("{error:#}"));
            let actual = validate_committee(&retained).map_err(|error| format!("{error:#}"));
            assert_eq!(actual, expected, "powers {powers:?}");
        }
    }
}
