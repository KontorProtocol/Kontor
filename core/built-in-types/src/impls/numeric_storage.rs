use alloc::{rc::Rc, vec::Vec};

use stdlib::{IndexKey, Indexed, KeyElement, KeyPath, ReadStorage, Retrieve, Store, WriteStorage};

use crate::numbers_types::{Decimal, Integer};

fn decode_value<T: KeyElement>(bytes: &[u8]) -> T {
    let (value, rest) = T::decode_from(bytes).expect("invalid numeric storage value");
    assert!(rest.is_empty(), "trailing numeric storage bytes");
    value
}

macro_rules! numeric_storage {
    ($($ty:ty),+ $(,)?) => {$(
        impl Indexed for $ty {}

        impl IndexKey for $ty {
            fn index_key(&self) -> Vec<u8> {
                self.encode()
            }
        }

        impl<S: ReadStorage + ?Sized> Retrieve<S> for $ty {
            fn __get(ctx: &Rc<S>, path: KeyPath) -> Option<Self> {
                ctx.__get_list_u8(&path).map(|bytes| decode_value(&bytes))
            }
        }

        impl<S: WriteStorage + ?Sized> Store<S> for $ty {
            fn __set(ctx: &Rc<S>, path: KeyPath, value: Self) {
                ctx.__set_list_u8(&path, value.encode());
            }
        }
    )+};
}

numeric_storage!(Integer, Decimal);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "invalid numeric storage value")]
    fn rejects_truncated_value() {
        decode_value::<Integer>(&Integer::from(1).encode()[..32]);
    }

    #[test]
    #[should_panic(expected = "invalid numeric storage value")]
    fn rejects_wrong_type_tag() {
        decode_value::<Decimal>(&[2; 33]);
    }

    #[test]
    #[should_panic(expected = "trailing numeric storage bytes")]
    fn rejects_trailing_value() {
        let mut bytes = Integer::from(1).encode();
        bytes.extend(Integer::from(2).encode());
        decode_value::<Integer>(&bytes);
    }
}
