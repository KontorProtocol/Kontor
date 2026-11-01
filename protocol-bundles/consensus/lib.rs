pub mod api;
mod bridge;
mod bridge_types;
mod channel_bridge;
mod config;
mod engine;
mod factory;
pub use engine::Engine;
pub use factory::network_peer_id;
#[path = "types.rs"]
mod consensus;
mod owner;
mod protocol;
mod replies;
mod wire;

pub const WIRE_CODEC: u32 = if cfg!(feature = "wire-v2") { 2 } else { 1 };
