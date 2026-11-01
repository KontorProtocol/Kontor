use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use malachitebft_codec::Codec;
use malachitebft_core_types::{HeightParams, LinearTimeouts, Round, VoteExtensionPolicy};
use malachitebft_proto::Error as ProtoError;

use crate::consensus::codec::ProtobufCodec;
use crate::consensus::signing::PublicKey;
use crate::consensus::{Ctx, Height, Validator, ValidatorSet};
use crate::protocol::canonical_codec::{Decoder, Encoder};

// This is the in-process adapter format, independent of either engine's network
// envelope. Only owned bytes and standard-library values cross the graph boundary.
pub(crate) const READY: u8 = 1;
pub(crate) const ROUND: u8 = 2;
pub(crate) const VALUE: u8 = 3;
pub(crate) const PART: u8 = 4;
pub(crate) const DECIDED: u8 = 5;
pub(crate) const FINALIZED: u8 = 6;
pub(crate) const MIN_HEIGHT: u8 = 7;
pub(crate) const HISTORY: u8 = 8;
pub(crate) const SYNCED: u8 = 9;
pub(crate) const RESTREAM: u8 = 10;

pub(crate) fn put_round(out: &mut Encoder, round: Round) -> Result<()> {
    match round.as_u32() {
        None => out.tag(0)?,
        Some(round) => {
            out.tag(1)?;
            out.fixed(&round.to_be_bytes())?;
        }
    }
    Ok(())
}

pub(crate) fn get_round(input: &mut Decoder<'_>) -> Result<Round> {
    match input.tag()? {
        0 => Ok(Round::Nil),
        1 => Ok(Round::new(u32::from_be_bytes(input.fixed()?))),
        _ => bail!("invalid bridge round"),
    }
}

pub(crate) fn put_duration(out: &mut Encoder, duration: Duration) -> Result<()> {
    out.u64(duration.as_secs())?;
    out.fixed(&duration.subsec_nanos().to_be_bytes())?;
    Ok(())
}

pub(crate) fn get_duration(input: &mut Decoder<'_>) -> Result<Duration> {
    let seconds = input.u64()?;
    let nanos = u32::from_be_bytes(input.fixed()?);
    ensure!(nanos < 1_000_000_000, "invalid bridge duration");
    Ok(Duration::new(seconds, nanos))
}

pub(crate) fn put_message<T>(out: &mut Encoder, value: &T) -> Result<()>
where
    ProtobufCodec: Codec<T, Error = ProtoError>,
{
    out.bytes(&ProtobufCodec.encode(value)?)?;
    Ok(())
}

pub(crate) fn get_message<T>(input: &mut Decoder<'_>) -> Result<T>
where
    ProtobufCodec: Codec<T, Error = ProtoError>,
{
    Ok(ProtobufCodec.decode(Bytes::copy_from_slice(input.bytes()?))?)
}

pub(crate) fn put_height_params(
    out: &mut Encoder,
    height: Height,
    params: &HeightParams<Ctx>,
) -> Result<()> {
    ensure!(
        params.vote_extension_policy.is_disabled(),
        "vote extensions unsupported"
    );
    ensure!(height.as_u64() > 0, "consensus height must be positive");
    out.u64(height.as_u64())?;
    out.count(params.validator_set.len())?;
    let mut seen = BTreeSet::new();
    for validator in params.validator_set.iter() {
        ensure!(seen.insert(validator.address), "duplicate validator");
        ensure!(
            validator.address
                == Validator::new(validator.public_key, validator.voting_power).address,
            "validator address mismatch"
        );
        out.fixed(validator.public_key.as_bytes())?;
        out.u64(validator.voting_power)?;
    }
    let t = params.timeouts;
    for duration in [
        t.propose,
        t.propose_delta,
        t.prevote,
        t.prevote_delta,
        t.precommit,
        t.precommit_delta,
        t.rebroadcast,
        t.max_timeout,
    ] {
        put_duration(out, duration)?;
    }
    match params.target_time {
        None => out.tag(0)?,
        Some(duration) => {
            out.tag(1)?;
            put_duration(out, duration)?;
        }
    }
    Ok(())
}

pub(crate) fn get_height_params(input: &mut Decoder<'_>) -> Result<(Height, HeightParams<Ctx>)> {
    let height = Height::new(input.u64()?);
    ensure!(height.as_u64() > 0, "consensus height must be positive");
    let count = input.count(40)?;
    let mut validators = Vec::new();
    validators.try_reserve(count)?;
    let mut seen = BTreeSet::new();
    for _ in 0..count {
        let key = PublicKey::from_bytes(input.fixed()?)?;
        let validator = Validator::new(key, input.u64()?);
        ensure!(seen.insert(validator.address), "duplicate validator");
        validators.push(validator);
    }
    // Preserve committee order: proposer selection uses the validator index.
    let validator_set = ValidatorSet::try_new(validators)?;
    let timeouts = LinearTimeouts {
        propose: get_duration(input)?,
        propose_delta: get_duration(input)?,
        prevote: get_duration(input)?,
        prevote_delta: get_duration(input)?,
        precommit: get_duration(input)?,
        precommit_delta: get_duration(input)?,
        rebroadcast: get_duration(input)?,
        max_timeout: get_duration(input)?,
    };
    let target_time = match input.tag()? {
        0 => None,
        1 => Some(get_duration(input)?),
        _ => bail!("invalid bridge target time"),
    };
    Ok((
        height,
        HeightParams::new(validator_set, timeouts, target_time)
            .with_vote_extension_policy(VoteExtensionPolicy::Disabled),
    ))
}

pub(crate) fn decode<T>(
    payload: &[u8],
    read: impl FnOnce(&mut Decoder<'_>) -> Result<T>,
) -> Result<T, String> {
    let mut input = Decoder::new(payload);
    let value = read(&mut input).map_err(|error| error.to_string())?;
    input.finish().map_err(|error| error.to_string())?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::signing::PrivateKey;

    fn params() -> HeightParams<Ctx> {
        let validators = [9, 2, 7]
            .map(|seed| Validator::new(PrivateKey::from([seed; 32]).public_key(), u64::from(seed)));
        HeightParams::new(
            ValidatorSet::new(validators),
            LinearTimeouts::default(),
            None,
        )
    }

    #[test]
    fn preserves_committee_order_and_rejects_partial_or_trailing_payloads() {
        let original = params();
        let mut output = Encoder::default();
        put_height_params(&mut output, Height::new(17), &original).unwrap();
        let bytes = output.finish();
        let (height, decoded) = decode(&bytes, get_height_params).unwrap();
        assert_eq!(height, Height::new(17));
        assert_eq!(decoded, original);
        for end in 0..bytes.len() {
            assert!(
                decode(&bytes[..end], get_height_params).is_err(),
                "accepted truncation {end}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing, get_height_params).is_err());
        let mut duplicate = bytes;
        duplicate.copy_within(12..44, 52);
        assert!(decode(&duplicate, get_height_params).is_err());
    }

    #[test]
    fn duration_encoding_does_not_normalize_invalid_nanos_or_wrap_seconds() {
        for duration in [Duration::ZERO, Duration::new(1, 999_999_999), Duration::MAX] {
            let mut out = Encoder::default();
            put_duration(&mut out, duration).unwrap();
            assert_eq!(decode(&out.finish(), get_duration).unwrap(), duration);
        }
        let mut out = Encoder::default();
        out.u64(u64::MAX).unwrap();
        out.fixed(&1_000_000_000u32.to_be_bytes()).unwrap();
        assert!(decode(&out.finish(), get_duration).is_err());
    }

    #[test]
    fn unsupported_extension_policy_cannot_cross_adapter() {
        let mut params = params();
        params.vote_extension_policy = VoteExtensionPolicy::Required;
        assert!(put_height_params(&mut Encoder::default(), Height::new(1), &params).is_err());
        params.vote_extension_policy = VoteExtensionPolicy::Disabled;
        assert!(put_height_params(&mut Encoder::default(), Height::new(0), &params).is_err());
    }
}
