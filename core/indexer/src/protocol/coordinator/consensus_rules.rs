use crate::protocol::identity::domain_digest;

// This names consensus semantics, not a build of Malachite or the node. Runtime
// updates may keep this identity only after historical compatibility checks.
pub(super) const REFERENCE: &[u8] = include_bytes!("consensus-rules-v1.json");

pub(crate) fn definition() -> [u8; 32] {
    domain_digest(b"kontor/consensus-definition/v1", REFERENCE)
}
