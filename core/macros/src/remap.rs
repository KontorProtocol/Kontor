/// The built-in interfaces whose Rust family lives in `built-in-types`.
/// Single source for contract!'s `with:` block and both macros' twin-family
/// guards — a type-owning built-in interface missing from this list would be
/// regenerated per crate as a second family.
pub const REMAPPED_BUILT_INS: &[(&str, &str)] = &[
    ("file-registry-types", "built_in_types::file_registry_types"),
    ("error", "built_in_types::error"),
    ("numbers", "built_in_types::numbers"),
    ("numbers-types", "built_in_types::numbers_types"),
    ("context-types", "built_in_types::context_types"),
    ("context", "built_in_types::context"),
];
