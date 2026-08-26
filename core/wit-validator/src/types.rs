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

/// Every type name the runtime/macros treat as a Kontor built-in — the union of
/// `BUILTIN_TYPES` and the built-in names the macro layer special-cases (the
/// `import!` skip list and `is_primitive_type`'s Kontor entries). A user WIT may
/// not DEFINE a type with any of these names (aliasing the built-in via `use` is
/// fine): the macros match generated types by bare Rust identifier, so a
/// same-named user type would be silently misrouted down the built-in path.
/// Enforced by `validate_reserved_type_names`; the name-based builtin skips in
/// rules.rs are sound only because of that rule.
pub const RESERVED_TYPE_NAMES: &[&str] = &[
    "transaction",
    "contract",
    "contract-address",
    "view-context",
    "view-storage",
    "fall-context",
    "proc-context",
    "proc-storage",
    "core-context",
    "signer",
    "holder",
    "holder-ref",
    "file-descriptor",
    "raw-file-descriptor",
    "proof",
    "challenge-input",
    "verify-result",
    "error",
    "keys",
    "index-rows",
    "integer",
    "decimal",
];

/// Check if a type name is a valid Kontor context type.
pub fn is_context_type(name: &str) -> bool {
    VALID_CONTEXT_TYPES.contains(&name)
}

/// Check if a type name is reserved for a Kontor built-in (may not be defined
/// by user WIT).
pub fn is_reserved_type_name(name: &str) -> bool {
    RESERVED_TYPE_NAMES.contains(&name)
}

/// Check if a type name is a Kontor built-in type.
pub fn is_builtin_type(name: &str) -> bool {
    BUILTIN_TYPES.contains(&name)
}

/// Check if a type name is a Kontor-specific primitive.
pub fn is_kontor_primitive(name: &str) -> bool {
    KONTOR_PRIMITIVES.contains(&name)
}
