// Address, Ed25519 key bytes, and voting power in the retained executor's order.
pub(crate) type Committee = Vec<([u8; 20], [u8; 32], u64)>;
