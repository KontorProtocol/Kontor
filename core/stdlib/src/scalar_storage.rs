use alloc::{string::String, vec::Vec};
use serde::Deserialize;

/// A value stored at exactly one path. Compound records, options and enums
/// cannot implement this merely because they can also be encoded as map keys.
pub trait ScalarStorage: Sized {
    fn decode_storage(bytes: &[u8]) -> Self;
}

/// Decode the same Postcard framing used by host storage getters. Borrowing the
/// payload avoids a second buffer for numeric and covering-index codec bytes.
pub fn decode_storage<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> T {
    let (value, rest) = postcard::take_from_bytes(bytes).expect("invalid storage value");
    assert!(rest.is_empty(), "trailing storage bytes");
    value
}

macro_rules! scalar_storage {
    ($($ty:ty),+ $(,)?) => {$(
        impl ScalarStorage for $ty {
            fn decode_storage(bytes: &[u8]) -> Self {
                decode_storage(bytes)
            }
        }
    )+};
}

scalar_storage!(u64, i64, bool, String, Vec<u8>);

// These use the host's 64-bit slots, including the signed slot's zigzag encoding.
impl ScalarStorage for u32 {
    fn decode_storage(bytes: &[u8]) -> Self {
        decode_storage::<u64>(bytes)
            .try_into()
            .expect("storage value exceeds u32")
    }
}

impl ScalarStorage for i32 {
    fn decode_storage(bytes: &[u8]) -> Self {
        decode_storage::<i64>(bytes)
            .try_into()
            .expect("storage value exceeds i32")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use serde::Serialize;

    fn roundtrip<T: ScalarStorage + Serialize + PartialEq + core::fmt::Debug>(value: T) {
        assert_eq!(
            T::decode_storage(&postcard::to_allocvec(&value).unwrap()),
            value
        );
    }

    #[test]
    fn primitive_slots_match_host_serialization() {
        for value in [0, 127, 128, u64::MAX] {
            roundtrip(value);
        }
        for value in [i64::MIN, -1, 0, 1, i64::MAX] {
            roundtrip(value);
        }
        for value in [false, true] {
            roundtrip(value);
        }
        for value in ["", "a\0b", "雪"] {
            roundtrip(String::from(value));
        }
        roundtrip(vec![0u8, 255, 128]);
        for value in [0, u32::MAX] {
            assert_eq!(
                u32::decode_storage(&postcard::to_allocvec(&u64::from(value)).unwrap()),
                value
            );
        }
        for value in [i32::MIN, -1, 0, i32::MAX] {
            assert_eq!(
                i32::decode_storage(&postcard::to_allocvec(&i64::from(value)).unwrap()),
                value
            );
        }
    }

    #[test]
    #[should_panic(expected = "invalid storage value")]
    fn rejects_truncated_frame() {
        String::decode_storage(&[3, b'a']);
    }

    #[test]
    #[should_panic(expected = "trailing storage bytes")]
    fn rejects_trailing_frame() {
        u64::decode_storage(&[1, 2]);
    }
}
