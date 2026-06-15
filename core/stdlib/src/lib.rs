#![no_std]
extern crate alloc;

/// The inert placeholder behind a declared `Map`/`IndexedMap` field: holds no
/// live data (the generated field model is the real accessor), it exists only so
/// the field has a type and so a wholesale `Store` write can persist entries.
/// `Map` and `IndexedMap` share this shape and differ only in their `Store`
/// impl, so the boilerplate lives here once. Defined before the modules that use
/// it (textual macro scoping).
macro_rules! storage_placeholder {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        pub struct $name<K, V, S: ?Sized> {
            pub entries: alloc::vec::Vec<(K, V)>,
            pub _marker: core::marker::PhantomData<S>,
        }

        impl<K: Clone, V: Clone, S: ?Sized> $name<K, V, S> {
            pub fn new(entries: &[(K, V)]) -> Self {
                Self {
                    entries: entries.to_vec(),
                    _marker: core::marker::PhantomData,
                }
            }
        }

        impl<K: Clone, V: Clone, S: ?Sized> Clone for $name<K, V, S> {
            fn clone(&self) -> Self {
                Self {
                    entries: self.entries.clone(),
                    _marker: core::marker::PhantomData,
                }
            }
        }

        impl<K, V, S: ?Sized> Default for $name<K, V, S> {
            fn default() -> Self {
                Self {
                    entries: alloc::vec::Vec::new(),
                    _marker: core::marker::PhantomData,
                }
            }
        }
    };
}

pub mod deque;
mod indexed_map;
mod key_path;
mod keycodec;
mod storage_interface;
mod wave_interfaces;

pub use deque::StorageDeque;
pub use indexed_map::*;
pub use key_path::*;
pub use keycodec::*;
pub use macros::{
    Indexed, Model, Root, Storage, StorageRoot, Store, Wavey, contract, contract_address,
    holder_ref, impls, import, interface,
};
pub use storage_interface::*;
pub use wasm_wave;
pub use wave_interfaces::*;
pub use wit_bindgen;

pub trait CheckedArithmetics<E, Other = Self> {
    type Output;

    fn add(self, other: Other) -> Result<Self::Output, E>;
    fn sub(self, other: Other) -> Result<Self::Output, E>;
    fn mul(self, other: Other) -> Result<Self::Output, E>;
    fn div(self, other: Other) -> Result<Self::Output, E>;
}
