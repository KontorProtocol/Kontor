#![no_std]
extern crate alloc;

mod dot_path_buf;
mod storage_interface;
mod wave_interfaces;

pub use dot_path_buf::*;
pub use macros::{
    Model, Root, Storage, StorageRoot, Store, Wavey, contract, contract_address, holder_ref, impls,
    import, interface,
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

/// Deterministic base-10 logarithm for the fixed-point `Decimal`. Backed by the
/// host's fastnum implementation (identical across indexers — unlike
/// `f64::log10`, which would fork consensus). Natural log is `log10(x) * ln(10)`.
pub trait Log10<E> {
    type Output;

    fn log10(self) -> Result<Self::Output, E>;
}
