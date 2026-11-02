use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use bytes::Bytes;
use malachitebft_codec::Codec;
use malachitebft_core_types::{HeightParams, LinearTimeouts, Round, VoteExtensionPolicy};
use malachitebft_proto::Error as ProtoError;

use crate::api::HeightParameters;
use crate::consensus::codec::ProtobufCodec;
use crate::consensus::signing::PublicKey;
use crate::consensus::{Ctx, Height, Validator, ValidatorSet};

pub(crate) fn round(value: Option<u32>) -> Round {
    value.map_or(Round::Nil, Round::new)
}

pub(crate) fn check_length(length: usize) -> Result<()> {
    // Preserve the old adapter's u32 count/byte ceiling without an outer codec.
    u32::try_from(length)?;
    Ok(())
}

pub(crate) fn message<T>(bytes: Vec<u8>) -> Result<T>
where
    ProtobufCodec: Codec<T, Error = ProtoError>,
{
    check_length(bytes.len())?;
    Ok(ProtobufCodec.decode(Bytes::from(bytes))?)
}

pub(crate) fn encode_message<T>(value: &T) -> Result<Vec<u8>>
where
    ProtobufCodec: Codec<T, Error = ProtoError>,
{
    let bytes = ProtobufCodec.encode(value)?;
    check_length(bytes.len())?;
    Ok(bytes.to_vec())
}

pub(crate) fn height_params(value: HeightParameters) -> Result<(Height, HeightParams<Ctx>)> {
    ensure!(value.height > 0, "consensus height must be positive");
    check_length(value.validators.len())?;
    let mut validators = Vec::new();
    validators.try_reserve(value.validators.len())?;
    let mut seen = BTreeSet::new();
    for validator in value.validators {
        let key = PublicKey::from_bytes(validator.public_key)?;
        let validator = Validator::new(key, validator.voting_power);
        ensure!(seen.insert(validator.address), "duplicate validator");
        validators.push(validator);
    }
    // Preserve committee order: proposer selection uses the validator index.
    let validator_set = ValidatorSet::try_new(validators)?;
    let t = value.timeouts;
    let timeouts = LinearTimeouts {
        propose: t.propose,
        propose_delta: t.propose_delta,
        prevote: t.prevote,
        prevote_delta: t.prevote_delta,
        precommit: t.precommit,
        precommit_delta: t.precommit_delta,
        rebroadcast: t.rebroadcast,
        max_timeout: t.max_timeout,
    };
    Ok((
        Height::new(value.height),
        HeightParams::new(validator_set, timeouts, value.target_time)
            .with_vote_extension_policy(VoteExtensionPolicy::Disabled),
    ))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::api::{Timeouts, Validator as PublicValidator};
    use crate::consensus::signing::PrivateKey;

    pub(crate) fn params(height: u64) -> HeightParameters {
        HeightParameters {
            height,
            validators: [9, 2, 7]
                .map(|seed| PublicValidator {
                    public_key: *PrivateKey::from([seed; 32]).public_key().as_bytes(),
                    voting_power: u64::from(seed),
                })
                .to_vec(),
            timeouts: Timeouts {
                propose: Duration::from_secs(1),
                propose_delta: Duration::from_secs(2),
                prevote: Duration::from_secs(3),
                prevote_delta: Duration::from_secs(4),
                precommit: Duration::from_secs(5),
                precommit_delta: Duration::from_secs(6),
                rebroadcast: Duration::from_secs(7),
                max_timeout: Duration::from_secs(8),
            },
            target_time: Some(Duration::new(2, 3)),
        }
    }

    #[test]
    fn typed_parameters_preserve_committee_order_and_all_timeouts() {
        let original = params(17);
        let (height, actual) = height_params(original.clone()).unwrap();
        assert_eq!(height.as_u64(), 17);
        for (a, b) in actual.validator_set.iter().zip(&original.validators) {
            assert_eq!(a.public_key.as_bytes(), &b.public_key);
            assert_eq!(a.voting_power, b.voting_power);
        }
        let t = actual.timeouts;
        assert_eq!(
            [
                t.propose,
                t.propose_delta,
                t.prevote,
                t.prevote_delta,
                t.precommit,
                t.precommit_delta,
                t.rebroadcast,
                t.max_timeout
            ],
            [1, 2, 3, 4, 5, 6, 7, 8].map(Duration::from_secs)
        );
        assert_eq!(actual.target_time, original.target_time);
        assert!(actual.vote_extension_policy.is_disabled());
    }

    #[test]
    fn typed_parameters_reject_invalid_authority_and_zero_height() {
        assert!(height_params(params(0)).is_err());
        let mut value = params(1);
        value.validators.push(value.validators[0].clone());
        assert!(height_params(value).is_err());
        let mut value = params(1);
        value.validators[0].voting_power = 0;
        assert!(height_params(value).is_err());
        let mut value = params(1);
        value.validators[0].voting_power = u64::MAX;
        assert!(height_params(value).is_err());
        let mut value = params(1);
        value.validators.clear();
        assert!(height_params(value).is_err());
    }

    #[test]
    fn adapter_length_ceiling_is_preserved() {
        assert!(check_length(u32::MAX as usize).is_ok());
        if usize::BITS > 32 {
            assert!(check_length(u32::MAX as usize + 1).is_err());
        }
    }
}
#[cfg(test)]
pub(crate) use tests::params as test_params;
