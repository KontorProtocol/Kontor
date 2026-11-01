use numerics::{Sign, string_to_decimal};

use super::canonical_codec::{CodecError, Encoder};
use super::identity::{ChainId, domain_digest};

fn decimal(output: &mut Encoder, text: &str) -> Result<(), CodecError> {
    let value = string_to_decimal(text).map_err(|_| CodecError::InvalidValue)?;
    output.tag(match value.sign {
        Sign::Plus => 0,
        Sign::Minus => 1,
    })?;
    for limb in [value.r0, value.r1, value.r2, value.r3] {
        output.u64(limb)?;
    }
    Ok(())
}

pub(crate) fn chain_identity(
    network_magic: [u8; 4],
    starting_block_height: u64,
    native_genesis: [u8; 32],
    sigma_min: &str,
    validators: &[(String, String, Vec<u8>)],
) -> Result<ChainId, CodecError> {
    if starting_block_height == 0 {
        return Err(CodecError::InvalidValue);
    }
    let mut output = Encoder::default();
    output.tag(1)?;
    output.fixed(&network_magic)?;
    output.u64(starting_block_height)?;
    output.fixed(&native_genesis)?;
    decimal(&mut output, sigma_min)?;
    output.count(validators.len())?;
    // Publication order affects ordered state writes. This is a sequence, not
    // a validator set to sort before deriving genesis identity.
    for (holder, stake, ed25519) in validators {
        let mut key = [0; 32];
        hex::decode_to_slice(holder, &mut key).map_err(|_| CodecError::InvalidValue)?;
        if ed25519.len() != 32 {
            return Err(CodecError::InvalidValue);
        }
        output.fixed(&key)?;
        decimal(&mut output, stake)?;
        output.fixed(ed25519)?;
    }
    Ok(ChainId(domain_digest(
        b"kontor/chain-genesis/v1",
        &output.finish(),
    )))
}

#[cfg(test)]
mod tests {
    use super::chain_identity;

    #[test]
    fn decimal_spelling_and_key_case_normalize_but_order_and_parameters_do_not() {
        let validators = vec![
            ("ab".repeat(32), "100".into(), vec![1; 32]),
            ("cd".repeat(32), "200".into(), vec![2; 32]),
        ];
        let baseline = chain_identity([1; 4], 10, [2; 32], "50", &validators).unwrap();
        let mut equivalent = validators.clone();
        equivalent[0].0 = equivalent[0].0.to_uppercase();
        equivalent[0].1 = "100.000".into();
        assert_eq!(
            baseline,
            chain_identity([1; 4], 10, [2; 32], "50.0", &equivalent).unwrap()
        );
        let mut reversed = validators.clone();
        reversed.reverse();
        for value in [
            chain_identity([3; 4], 10, [2; 32], "50", &validators),
            chain_identity([1; 4], 11, [2; 32], "50", &validators),
            chain_identity([1; 4], 10, [3; 32], "50", &validators),
            chain_identity([1; 4], 10, [2; 32], "51", &validators),
            chain_identity([1; 4], 10, [2; 32], "50", &reversed),
        ] {
            assert_ne!(baseline, value.unwrap());
        }
    }

    #[test]
    fn malformed_genesis_never_acquires_an_identity() {
        assert!(chain_identity([1; 4], 0, [2; 32], "50", &[]).is_err());
        assert!(chain_identity([1; 4], 1, [2; 32], "not a decimal", &[]).is_err());
        for validators in [
            vec![("not hex".into(), "100".into(), vec![1; 32])],
            vec![("ab".repeat(32), "100".into(), vec![1; 31])],
        ] {
            assert!(chain_identity([1; 4], 1, [2; 32], "50", &validators).is_err());
        }
    }
}
