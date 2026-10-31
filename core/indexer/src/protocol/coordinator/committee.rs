use std::sync::Arc;

use anyhow::{Context, Result};

#[cfg(not(kontor_node))]
use super::selection::{
    ApplicationPosition, ExecutionSelection, ExecutorVersion, select_legacy_p1,
};
use crate::consensus::{Address, Validator, ValidatorSet, signing::PublicKey};
use crate::protocol::committee::Committee;
#[cfg(not(kontor_node))]
use crate::protocol::v1::committee;
#[cfg(not(kontor_node))]
use crate::runtime::Runtime;

#[cfg(not(kontor_node))]
pub(crate) async fn derive_selected(
    runtime: &mut Runtime,
    selection: &ExecutionSelection,
) -> Result<ValidatorSet> {
    selection
        .verify_committee(
            &runtime.get_storage_conn(),
            runtime.network,
            runtime.executor_version(),
        )
        .await?;
    let mut runtime = runtime.bind_selection(&selection.envelope())?;
    let members = match selection.version() {
        ExecutorVersion::LegacyP1 => committee::derive_committee(&mut runtime).await?,
    };
    materialize_committee(members)
}

pub(super) fn materialize_committee(members: Committee) -> Result<ValidatorSet> {
    let validators = members
        .into_iter()
        .map(|(address, key, voting_power)| {
            Ok(Validator {
                address: Address::new(address),
                public_key: PublicKey::from_bytes(key)
                    .context("selected committee key cannot be represented by consensus")?,
                voting_power,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    // Validation and ordering belong to the selected executor. Reapplying the
    // current node's set constructor here would silently substitute its rules.
    Ok(ValidatorSet {
        validators: Arc::new(validators),
    })
}

#[cfg(not(kontor_node))]
pub(crate) async fn build_validator_set(runtime: &mut Runtime) -> Result<ValidatorSet> {
    // Startup has an owned runtime but no application savepoint yet. Refresh may
    // already be inside one. A nested storage savepoint keeps every staking read
    // on the selected snapshot and leaves any enclosing transaction intact.
    runtime.storage.savepoint().await?;
    let result = async {
        let selection = select_legacy_p1(
            &runtime.get_storage_conn(),
            runtime.network,
            ApplicationPosition::Committee,
        )
        .await?;
        derive_selected(runtime, &selection).await
    }
    .await;
    runtime.storage.rollback().await?;
    result
}

#[cfg(test)]
mod tests {
    use super::materialize_committee;
    use crate::consensus::{Validator, ValidatorSet, signing::PrivateKey};

    #[test]
    fn materialization_preserves_addresses_order_duplicates_and_power() {
        let a = Validator::new(PrivateKey::from([1; 32]).public_key(), 3);
        let b = Validator::new(PrivateKey::from([2; 32]).public_key(), 7);
        let original = ValidatorSet::try_new([b.clone(), a, b]).unwrap();
        let encoded = original
            .iter()
            .map(|v| {
                (
                    v.address.into_inner(),
                    *v.public_key.as_bytes(),
                    v.voting_power,
                )
            })
            .collect();
        assert_eq!(materialize_committee(encoded).unwrap(), original);
    }
}
