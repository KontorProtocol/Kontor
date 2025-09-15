// Asset management primitives for Sigil contracts
// 
// This module provides resource-like semantics for handling assets within a single transaction.
// The core idea is that assets can be temporarily "withdrawn" from their persistent ledgers
// into in-flight objects that can be passed between functions and contracts, then "deposited"
// back into ledgers when the transaction completes.
//
// Note: This module only provides the basic InFlightBalance struct. The Asset trait
// must be defined in individual contracts since it depends on built-in types that
// are only available in the contract context.

// For now, just provide a marker trait that contracts can use.
// The actual Asset trait with built-in types will be defined in each contract.

/// Marker trait to indicate that a contract supports asset semantics.
/// The actual implementation details are defined in each contract since
/// they depend on built-in types that aren't available in stdlib.
pub trait AssetMarker {
    // This trait is intentionally empty - it's just a marker
}
