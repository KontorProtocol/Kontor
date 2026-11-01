#[path = "types.rs"]
mod consensus;
mod protocol;
mod wire;

pub const WIRE_CODEC: u32 = if cfg!(feature = "wire-v2") { 2 } else { 1 };
