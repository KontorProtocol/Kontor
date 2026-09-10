use alloc::{rc::Rc, vec::Vec};

use stdlib::{Indexed, KeyPath, ReadStorage, Retrieve, Store, WriteStorage};

use crate::numbers_types::{Decimal, Integer, Sign};

// Value storage preserves the WIT representation, including signed zero. Map
// keys separately use the ordered codec, where equivalent zeros must coalesce.
fn encode(sign: Sign, limbs: [u64; 4]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(33);
    bytes.push(u8::from(matches!(sign, Sign::Minus)));
    for limb in limbs {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn decode(bytes: &[u8]) -> (Sign, [u64; 4]) {
    assert_eq!(bytes.len(), 33, "invalid numeric storage length");
    let sign = match bytes[0] {
        0 => Sign::Plus,
        1 => Sign::Minus,
        _ => panic!("invalid numeric storage sign"),
    };
    let limbs = core::array::from_fn(|i| {
        u64::from_le_bytes(bytes[1 + i * 8..1 + (i + 1) * 8].try_into().unwrap())
    });
    (sign, limbs)
}

macro_rules! numeric_storage {
    ($($ty:ty),+ $(,)?) => {$(
        impl Indexed for $ty {}

        impl<S: ReadStorage + ?Sized> Retrieve<S> for $ty {
            fn __get(ctx: &Rc<S>, path: KeyPath) -> Option<Self> {
                ctx.__get_list_u8(&path).map(|bytes| {
                    let (sign, [r0, r1, r2, r3]) = decode(&bytes);
                    Self { r0, r1, r2, r3, sign }
                })
            }
        }

        impl<S: WriteStorage + ?Sized> Store<S> for $ty {
            fn __set(ctx: &Rc<S>, path: KeyPath, value: Self) {
                ctx.__set_list_u8(&path, encode(value.sign, [value.r0, value.r1, value.r2, value.r3]));
            }
        }
    )+};
}

numeric_storage!(Integer, Decimal);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_codec_preserves_all_limbs_and_signed_zero() {
        for sign in [Sign::Plus, Sign::Minus] {
            for limbs in [[0; 4], [u64::MAX; 4], [1, 2, 3, 4], [0, 0, 0, 1 << 63]] {
                let bytes = encode(sign, limbs);
                let (actual_sign, actual_limbs) = decode(&bytes);
                assert_eq!(actual_sign, sign);
                assert_eq!(actual_limbs, limbs);
            }
        }
        assert_eq!(
            &encode(Sign::Minus, [1, 2, 3, 4])[..9],
            &[1, 1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    #[should_panic(expected = "invalid numeric storage length")]
    fn storage_codec_rejects_wrong_length() {
        decode(&[0; 32]);
    }

    #[test]
    #[should_panic(expected = "invalid numeric storage sign")]
    fn storage_codec_rejects_invalid_sign() {
        decode(&[2; 33]);
    }
}
