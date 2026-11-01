use alloc::{string::String, vec::Vec};

use crate::HasNextRow;

/// A value stored at exactly one path. Compound records, options and enums
/// cannot implement this merely because they can also be encoded as map keys.
pub trait ScalarStorage: Sized {
    fn next_row(rows: &impl HasNextRow) -> Option<(Vec<u8>, Self)>;
}

macro_rules! scalar_storage {
    ($($ty:ty => $next:ident),+ $(,)?) => {$(
        impl ScalarStorage for $ty {
            fn next_row(rows: &impl HasNextRow) -> Option<(Vec<u8>, Self)> {
                rows.$next()
            }
        }
    )+};
}

scalar_storage!(u64 => next_u64, i64 => next_s64, bool => next_bool,
    String => next_str, Vec<u8> => next_list_u8);

pub(crate) fn narrow_u32(value: u64) -> u32 {
    value.try_into().expect("storage value exceeds u32")
}

pub(crate) fn narrow_i32(value: i64) -> i32 {
    value.try_into().expect("storage value exceeds i32")
}

impl ScalarStorage for u32 {
    fn next_row(rows: &impl HasNextRow) -> Option<(Vec<u8>, Self)> {
        rows.next_u64().map(|(key, value)| (key, narrow_u32(value)))
    }
}

impl ScalarStorage for i32 {
    fn next_row(rows: &impl HasNextRow) -> Option<(Vec<u8>, Self)> {
        rows.next_s64().map(|(key, value)| (key, narrow_i32(value)))
    }
}
