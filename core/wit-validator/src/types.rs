//! Kontor-specific type definitions.
//!
//! These types are unique to Kontor and don't exist in standard WIT.

#![allow(dead_code)] // Public API - may be used by consumers

/// Valid context types that can be used as the first parameter of exported functions.
pub const VALID_CONTEXT_TYPES: &[&str] = &[
    "proc-context",
    "view-context",
    "core-context",
    "fall-context",
];

/// Kontor-specific primitive types.
pub const KONTOR_PRIMITIVES: &[&str] = &[
    "integer",          // Arbitrary precision integer
    "decimal",          // Fixed-point decimal
    "contract-address", // Kontor contract address
];

/// The required error type name for result types.
pub const ERROR_TYPE_NAME: &str = "error";

/// Built-in types that should be skipped during user-defined type validation.
/// These are provided by the Kontor runtime.
pub const BUILTIN_TYPES: &[&str] = &[
    "transaction",
    "contract-address",
    "view-context",
    "view-storage",
    "fall-context",
    "proc-context",
    "proc-storage",
    "core-context",
    "signer",
    "file-descriptor",
    "raw-file-descriptor",
    "error",
    "keys",
    "integer",
    "decimal",
];

/// Check if a type name is a valid Kontor context type.
pub fn is_context_type(name: &str) -> bool {
    VALID_CONTEXT_TYPES.contains(&name)
}

/// Check if a type name is a Kontor built-in type.
pub fn is_builtin_type(name: &str) -> bool {
    BUILTIN_TYPES.contains(&name)
}

/// Check if a type name is a Kontor-specific primitive.
pub fn is_kontor_primitive(name: &str) -> bool {
    KONTOR_PRIMITIVES.contains(&name)
}
