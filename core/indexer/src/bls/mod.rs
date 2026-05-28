//! BLS12-381 verification surface used by the reactor.
//!
//! Pure-crypto pieces — [`RegistrationProof`], EIP-2333 derivation,
//! domain-separator constants — live in the shared `bls-crypto` crate
//! so the JS SDK can call into the same code through the `kontor-sdk`
//! wasm component. This module re-exports them, then adds the
//! aggregate-verification flow, which needs `Runtime` for signer
//! lookups and so stays indexer-local.

mod aggregate;

pub use aggregate::*;
pub use bls_crypto::*;

/// Hard cap on number of operations per aggregate bundle.
pub const MAX_BLS_BULK_OPS: usize = 10_000;

/// Hard cap on total signed message bytes per aggregate bundle.
pub const MAX_BLS_BULK_TOTAL_MESSAGE_BYTES: usize = 1_000_000;

#[cfg(test)]
mod tests;
