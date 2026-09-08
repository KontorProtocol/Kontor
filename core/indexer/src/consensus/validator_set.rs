use core::slice;
use std::sync::Arc;

use anyhow::{Result, anyhow, ensure};
use malachitebft_core_types::VotingPower;
use serde::{Deserialize, Serialize};

use crate::consensus::signing::PublicKey;
use crate::consensus::{Address, Ctx};

// Both default Malachite thresholds multiply observed voting power by three.
const MAX_TOTAL_VOTING_POWER: VotingPower = VotingPower::MAX / 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    pub address: Address,
    pub public_key: PublicKey,
    pub voting_power: VotingPower,
}

impl Validator {
    pub fn new(public_key: PublicKey, voting_power: VotingPower) -> Self {
        Self {
            address: Address::from_public_key(&public_key),
            public_key,
            voting_power,
        }
    }
}

impl PartialOrd for Validator {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Validator {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

impl malachitebft_core_types::Validator<Ctx> for Validator {
    fn address(&self) -> &Address {
        &self.address
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn voting_power(&self) -> VotingPower {
        self.voting_power
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Arc<Vec<Validator>>,
}

impl ValidatorSet {
    pub fn new(validators: impl IntoIterator<Item = Validator>) -> Self {
        Self::try_new(validators).expect("invalid validator set")
    }

    pub fn try_new(validators: impl IntoIterator<Item = Validator>) -> Result<Self> {
        let set = Self {
            validators: Arc::new(validators.into_iter().collect()),
        };
        ensure!(!set.is_empty(), "validator set is empty");
        set.checked_total_voting_power()?;
        Ok(set)
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn iter(&self) -> slice::Iter<'_, Validator> {
        self.validators.iter()
    }

    pub fn total_voting_power(&self) -> VotingPower {
        self.checked_total_voting_power()
            .expect("invalid total voting power")
    }

    fn checked_total_voting_power(&self) -> Result<VotingPower> {
        let total = self.validators.iter().try_fold(0u64, |total, validator| {
            ensure!(
                validator.voting_power > 0,
                "validator has zero voting power"
            );
            total
                .checked_add(validator.voting_power)
                .ok_or_else(|| anyhow!("total voting power overflow"))
        })?;
        ensure!(
            total <= MAX_TOTAL_VOTING_POWER,
            "total voting power exceeds quorum arithmetic limit"
        );
        Ok(total)
    }

    pub fn get_by_index(&self, index: usize) -> Option<&Validator> {
        self.validators.get(index)
    }

    pub fn get_by_address(&self, address: &Address) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.address == address)
    }
}

impl malachitebft_core_types::ValidatorSet<Ctx> for ValidatorSet {
    fn count(&self) -> usize {
        self.validators.len()
    }

    fn total_voting_power(&self) -> VotingPower {
        self.total_voting_power()
    }

    fn get_by_address(&self, address: &Address) -> Option<&Validator> {
        self.get_by_address(address)
    }

    fn get_by_index(&self, index: usize) -> Option<&Validator> {
        self.validators.get(index)
    }
}

#[cfg(test)]
mod tests {
    use malachitebft_core_types::ThresholdParams;

    use super::{MAX_TOTAL_VOTING_POWER, Validator, ValidatorSet};
    use crate::consensus::signing::PrivateKey;

    fn validator(seed: u8, power: u64) -> Validator {
        Validator::new(PrivateKey::from([seed; 32]).public_key(), power)
    }

    #[test]
    fn aggregate_limit_is_safe_for_default_thresholds() {
        let set =
            ValidatorSet::try_new([validator(1, MAX_TOTAL_VOTING_POWER - 1), validator(2, 1)])
                .unwrap();
        let total = set.total_voting_power();
        let thresholds = ThresholdParams::default();
        for threshold in [thresholds.honest, thresholds.quorum] {
            assert!(threshold.is_met(total, total));
            let minimum = threshold.min_expected(total);
            assert!(threshold.is_met(minimum, total));
            assert!(!threshold.is_met(minimum - 1, total));
        }
    }

    #[test]
    fn rejects_unsafe_aggregate_and_overflow() {
        for powers in [[MAX_TOTAL_VOTING_POWER, 1], [u64::MAX, 1]] {
            assert!(
                ValidatorSet::try_new([validator(1, powers[0]), validator(2, powers[1]),]).is_err()
            );
        }
    }

    #[test]
    fn rejects_zero_power_even_in_a_nonempty_set() {
        for powers in [vec![0], vec![0, 0], vec![1, 0]] {
            assert!(
                ValidatorSet::try_new(
                    powers
                        .into_iter()
                        .enumerate()
                        .map(|(i, power)| validator(i as u8 + 1, power))
                )
                .is_err()
            );
        }
    }

    #[test]
    #[should_panic(expected = "invalid total voting power")]
    fn deserialized_total_cannot_wrap() {
        let encoded = serde_json::json!({"validators": [validator(1, u64::MAX), validator(2, 1)]});
        let set: ValidatorSet = serde_json::from_value(encoded).unwrap();
        set.total_voting_power();
    }
}
