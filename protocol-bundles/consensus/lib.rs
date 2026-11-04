pub mod api;
mod authority;
pub mod authority_api;
mod bridge;
mod bridge_types;
mod channel_bridge;
mod config;
mod engine;
mod factory;
pub use engine::Engine;
pub use factory::{network_peer_id, start};
#[path = "types.rs"]
mod consensus;
mod owner;
// These modules borrow node sources, which are formatted in their own workspace.
#[rustfmt::skip]
mod protocol;
mod recovery;
pub use recovery::{WalInspection, WalResumeContext, inspect_protected_wal};
mod replies;
mod wire;

pub const WIRE_CODEC: u32 = 1;
