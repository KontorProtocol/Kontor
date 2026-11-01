mod bridge;
mod bridge_codec;
mod channel_bridge;
#[path = "types.rs"]
mod consensus;
mod owner;
mod protocol;
mod replies;
mod wire;

pub const WIRE_CODEC: u32 = if cfg!(feature = "wire-v2") { 2 } else { 1 };
