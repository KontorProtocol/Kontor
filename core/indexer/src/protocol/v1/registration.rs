use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Error, Result, ensure};

use super::committee::{derive_committee, stake_to_voting_power};
use crate::protocol::registration::RegistrationObservation;
use crate::runtime::Runtime;
use crate::runtime::staking::{
    address as staking_address,
    api::{
        ValidatorStatus,
        wave::{
            get_active_set_call_expr, get_active_set_parse_return_expr, get_validator_call_expr,
            get_validator_parse_return_expr,
        },
    },
};

pub(crate) async fn observe(
    runtime: &mut Runtime,
    watched: Vec<String>,
) -> Result<RegistrationObservation> {
    let committee = derive_committee(runtime).await?;
    let result = runtime
        .execute_system_view(&staking_address(), &get_active_set_call_expr())
        .await?;
    let active = get_active_set_parse_return_expr(&result);
    ensure!(
        active.len() == committee.len(),
        "registration committee length changed"
    );
    let mut holders = BTreeSet::new();
    let mut active_registrations = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for (validator, (_, key, power)) in active.into_iter().zip(&committee) {
        ensure!(
            validator.ed25519_pubkey.as_slice() == key.as_slice(),
            "registration committee key changed"
        );
        ensure!(keys.insert(*key), "duplicate active registration key");
        active_registrations.insert(validator.x_only_pubkey.clone(), (*key, *power));
        ensure!(
            holders.insert(validator.x_only_pubkey),
            "duplicate active registration holder"
        );
    }
    // Previously observed holders must also be read after rollback. Their
    // disappearance or inactive state can invalidate an earlier approval even
    // when the same key rejoins before the closure's final committee is chosen.
    holders.extend(watched);
    let mut registrations = Vec::new();
    for holder in holders {
        let result = runtime
            .execute_system_view(&staking_address(), &get_validator_call_expr(&holder))
            .await
            .context("failed to observe validator registration")?;
        let registration = get_validator_parse_return_expr(&result)
            .map(|value| {
                ensure!(
                    value.x_only_pubkey == holder,
                    "registration holder mismatch"
                );
                if let Some((key, power)) = active_registrations.get(&holder) {
                    ensure!(
                        value.ed25519_pubkey.as_slice() == key.as_slice()
                            && stake_to_voting_power(value.stake)? == *power
                            && matches!(
                                value.status,
                                ValidatorStatus::Active | ValidatorStatus::PendingExit
                            ),
                        "active registration disagrees with committee"
                    );
                } else {
                    ensure!(
                        !matches!(
                            value.status,
                            ValidatorStatus::Active | ValidatorStatus::PendingExit
                        ),
                        "active registration omitted from committee"
                    );
                }
                let status = match value.status {
                    ValidatorStatus::Inactive => 0,
                    ValidatorStatus::Active => 1,
                    ValidatorStatus::PendingJoin => 2,
                    ValidatorStatus::PendingExit => 3,
                };
                Ok::<_, Error>((
                    value.ed25519_pubkey,
                    status,
                    value.activation_height,
                    value.deactivation_height,
                ))
            })
            .transpose()?;
        ensure!(
            registration.is_some() || !active_registrations.contains_key(&holder),
            "active registration is absent"
        );
        registrations.push((holder, registration));
    }
    Ok((committee, registrations))
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};

    use super::observe;
    use crate::consensus::signing::PrivateKey;
    use crate::reg_tester::random_x_only_pubkey;
    use crate::runtime::{Decimal, GenesisValidator};
    use crate::test_utils::test_runtime_with_genesis;

    #[tokio::test]
    async fn registration_observation_uses_trusted_views_and_tracks_absent_holders() -> Result<()> {
        let key = PrivateKey::from([7; 32]).public_key();
        let holder = random_x_only_pubkey();
        let missing = u64::MAX.to_string();
        let (mut runtime, _directory, _name) = test_runtime_with_genesis(&[GenesisValidator {
            x_only_pubkey: holder.clone(),
            ed25519_pubkey: key.as_bytes().to_vec(),
            stake: Decimal::from("100.9999999"),
        }])
        .await?;
        let holder = runtime
            .storage
            .lookup_identity(&holder)
            .await?
            .context("genesis holder identity is absent")?
            .to_string();
        runtime.view_gas_limit = 0;
        let (committee, registrations) =
            observe(&mut runtime, vec![missing.clone(), missing.clone()]).await?;
        assert_eq!(committee.len(), 1);
        assert_eq!(committee[0].1, *key.as_bytes());
        assert_eq!(committee[0].2, 100);
        let mut expected = vec![
            (holder, Some((key.as_bytes().to_vec(), 1, 0, 0))),
            (missing, None),
        ];
        expected.sort();
        assert_eq!(registrations, expected);
        Ok(())
    }
}
