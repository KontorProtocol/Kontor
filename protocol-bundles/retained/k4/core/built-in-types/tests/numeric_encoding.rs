use built_in_types::numbers_types::{Decimal, Integer, Sign};
use stdlib::{IndexKey, KeyElement};

#[test]
fn numeric_keys_and_buckets_share_encoding_and_canonical_zero() {
    for sign in [Sign::Plus, Sign::Minus] {
        for limbs in [[0; 4], [u64::MAX; 4], [1, 2, 3, 4], [0, 0, 0, 1 << 63]] {
            let integer = Integer {
                r0: limbs[0],
                r1: limbs[1],
                r2: limbs[2],
                r3: limbs[3],
                sign,
            };
            let decimal = Decimal::from_raw_units(integer);
            let bytes = integer.encode();
            assert_eq!(bytes, integer.index_key());
            assert_eq!(bytes, decimal.encode());
            assert_eq!(bytes, decimal.index_key());
            let (decoded, rest) = Integer::decode_from(&bytes).unwrap();
            assert!(rest.is_empty());
            let expected_sign = if limbs == [0; 4] { Sign::Plus } else { sign };
            assert_eq!(decoded.sign, expected_sign);
            assert_eq!([decoded.r0, decoded.r1, decoded.r2, decoded.r3], limbs);
            let (decoded_decimal, rest) = Decimal::decode_from(&bytes).unwrap();
            assert!(rest.is_empty());
            assert_eq!(decoded_decimal.to_raw_units().sign, expected_sign);
            assert_eq!(decoded_decimal.to_raw_units(), decoded);
        }
    }
}
