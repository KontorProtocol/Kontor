mod dot_path_buf;
mod storage_interface;
mod wave_interfaces;

pub use dot_path_buf::*;
pub use macros::{
    Model, Root, Storage, StorageRoot, Store, Wavey, contract, contract_address, impls, import,
    interface,
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

impl FromString for String {
    fn from_string(s: String) -> Self {
        s
    }
}

impl FromString for u64 {
    fn from_string(s: String) -> Self {
        s.parse::<u64>().unwrap()
    }
}
