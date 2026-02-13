//! WIT Validator for Kontor
//!
//! Validates WIT (WebAssembly Interface Types) files against Kontor-specific rules
//! that are stricter than standard WIT.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

mod error;
mod rules;
mod types;

pub use error::{ValidationError, ValidationResult};
pub use wit_parser::Resolve;

const BUILT_IN_WIT: &str = include_str!("../../indexer/src/runtime/wit/deps/built-in.wit");

/// Validates WIT files against Kontor-specific rules.
pub struct Validator;

/// Error returned when WIT parsing fails.
#[derive(Debug)]
pub struct ParseError {
    pub message: String,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl core::error::Error for ParseError {}

impl Validator {
    /// Validate a WIT string against Kontor rules.
    ///
    /// This automatically includes the Kontor built-in types (context, foreign, etc.)
    /// so that contracts importing from `kontor:built-in` can be validated.
    pub fn validate_str(wit_content: &str) -> Result<ValidationResult, ParseError> {
        let mut resolve = Resolve::new();

        resolve
            .push_str("built-in.wit", BUILT_IN_WIT)
            .map_err(|e| ParseError {
                message: alloc::format!("Failed to parse built-in.wit: {}", e),
            })?;

        resolve
            .push_str("contract.wit", wit_content)
            .map_err(|e| ParseError {
                message: alloc::format!("Failed to parse contract WIT: {}", e),
            })?;

        Ok(Self::validate_resolve(&resolve))
    }

    /// Validate an already-parsed `Resolve` against Kontor rules.
    pub fn validate_resolve(resolve: &Resolve) -> ValidationResult {
        let mut errors = Vec::new();
        errors.extend(rules::validate_all(resolve));
        ValidationResult { errors }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::format;

    use super::*;

    /// Wraps fixture content in standard WIT boilerplate
    fn wrap(content: &str) -> std::string::String {
        format!(
            r#"package root:component;

world root {{
    include kontor:built-in/built-in;
    use kontor:built-in/context.{{proc-context, view-context, fall-context}};
    use kontor:built-in/error.{{error}};

{content}
}}"#
        )
    }

    fn validate(content: &str) -> ValidationResult {
        let wit = wrap(content);
        Validator::validate_str(&wit).expect("Failed to parse WIT")
    }

    #[test]
    fn test_empty_resolve_is_valid() {
        let resolve = Resolve::new();
        let result = Validator::validate_resolve(&resolve);
        assert!(result.is_valid());
    }

    #[test]
    fn test_valid_basic() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<proc-context>);
    export get-value: async func(ctx: borrow<view-context>) -> string;
    export set-value: async func(ctx: borrow<proc-context>, val: string) -> result<_, error>;
"#,
        );
        assert!(result.is_valid(), "Expected valid, got errors: {}", result);
    }

    #[test]
    fn test_valid_list_u8_in_record() {
        let result = validate(
            r#"
    record my-data {
        bytes: list<u8>,
        name: string,
    }

    export init: async func(ctx: borrow<proc-context>);
    export get-data: async func(ctx: borrow<view-context>) -> my-data;
"#,
        );
        assert!(
            result.is_valid(),
            "list<u8> should be allowed in records, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_no_context_parameter() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<proc-context>);
    export bad-func: async func() -> string;
"#,
        );
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.message.contains("context")));
    }

    #[test]
    fn test_invalid_wrong_context_type() {
        let result = validate(
            r#"
    resource my-context {}

    export init: async func(ctx: borrow<proc-context>);
    export bad-func: async func(ctx: borrow<my-context>) -> string;
"#,
        );
        assert!(result.has_errors());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("context type"))
        );
    }

    #[test]
    fn test_invalid_empty_record() {
        let result = validate(
            r#"
    record empty {}

    export init: async func(ctx: borrow<proc-context>);
    export get: async func(ctx: borrow<view-context>) -> empty;
"#,
        );
        assert!(result.has_errors());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("at least one field"))
        );
    }

    #[test]
    fn test_invalid_wrong_error_type() {
        let result = validate(
            r#"
    record my-error { msg: string }

    export init: async func(ctx: borrow<proc-context>);
    export bad: async func(ctx: borrow<proc-context>) -> result<string, my-error>;
"#,
        );
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.message.contains("'error'")));
    }

    #[test]
    fn test_invalid_nested_list() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<proc-context>);
    export bad: async func(ctx: borrow<view-context>) -> list<list<string>>;
"#,
        );
        assert!(result.has_errors());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("nested list"))
        );
    }

    #[test]
    fn test_invalid_list_in_record() {
        let result = validate(
            r#"
    record bad { names: list<string> }

    export init: async func(ctx: borrow<proc-context>);
    export get: async func(ctx: borrow<view-context>) -> bad;
"#,
        );
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.message.contains("list<T>")));
    }

    #[test]
    fn test_invalid_result_in_param() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<proc-context>);
    export bad: async func(ctx: borrow<proc-context>, r: result<string, error>) -> string;
"#,
        );
        assert!(result.has_errors());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("return type"))
        );
    }

    #[test]
    fn test_invalid_float() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<proc-context>);
    export bad: async func(ctx: borrow<view-context>) -> f64;
"#,
        );
        assert!(result.has_errors());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("floating point"))
        );
    }

    #[test]
    fn test_invalid_flags() {
        let result = validate(
            r#"
    flags perms { read, write, exec }

    export init: async func(ctx: borrow<proc-context>);
    export get: async func(ctx: borrow<view-context>) -> perms;
"#,
        );
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.message.contains("flags")));
    }

    #[test]
    fn test_invalid_cycle() {
        let result = Validator::validate_str(&wrap(
            r#"
    record node { value: string, next: node }

    export init: async func(ctx: borrow<proc-context>);
    export get: async func(ctx: borrow<view-context>) -> node;
"#,
        ));
        assert!(result.is_err(), "Expected parse error for cyclic type");
        assert!(format!("{}", result.unwrap_err()).contains("depends on itself"));
    }

    #[test]
    fn test_invalid_sync_export() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<proc-context>);
    export bad: func(ctx: borrow<view-context>) -> string;
"#,
        );
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.message.contains("async")));
    }

    #[test]
    fn test_valid_init_fallback() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<proc-context>);
    export fallback: async func(ctx: borrow<fall-context>, expr: string) -> string;
    export get-value: async func(ctx: borrow<view-context>) -> string;
"#,
        );
        assert!(result.is_valid(), "Expected valid, got errors: {}", result);
    }

    #[test]
    fn test_invalid_init_wrong_context() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<view-context>);
"#,
        );
        assert!(result.has_errors());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("proc-context"))
        );
    }

    #[test]
    fn test_invalid_init_has_return() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<proc-context>) -> string;
"#,
        );
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.message.contains("return")));
    }

    #[test]
    fn test_invalid_fallback_wrong_context() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<proc-context>);
    export fallback: async func(ctx: borrow<proc-context>, expr: string) -> string;
"#,
        );
        assert!(result.has_errors());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("fall-context"))
        );
    }

    #[test]
    fn test_invalid_fallback_wrong_return() {
        let result = validate(
            r#"
    export init: async func(ctx: borrow<proc-context>);
    export fallback: async func(ctx: borrow<fall-context>, expr: string) -> u64;
"#,
        );
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.message.contains("string")));
    }

    #[test]
    fn test_render_includes_source_location() {
        let wit = wrap(
            r#"
    export init: async func(ctx: borrow<proc-context>);
    export bad: func(ctx: borrow<view-context>) -> string;
"#,
        );
        let mut resolve = Resolve::new();
        resolve
            .push_str("built-in.wit", BUILT_IN_WIT)
            .expect("Failed to parse built-in.wit");
        resolve
            .push_str("contract.wit", &wit)
            .expect("Failed to parse contract WIT");
        let result = Validator::validate_resolve(&resolve);

        assert!(result.has_errors());
        let error = &result.errors[0];
        assert_eq!(
            error.render(&resolve),
            "contract.wit:10:12: error: exported functions must be async"
        );
    }

    #[test]
    fn test_invalid_missing_init() {
        let result = validate(
            r#"
    export get-value: async func(ctx: borrow<view-context>) -> string;
"#,
        );
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.message.contains("init")));
    }

    #[test]
    fn test_cross_type_cycle_record_variant() {
        let result = Validator::validate_str(&wrap(
            r#"
    record wrapper { data: my-variant }
    variant my-variant { some(wrapper), none }

    export init: async func(ctx: borrow<proc-context>);
    export get: async func(ctx: borrow<view-context>) -> wrapper;
"#,
        ));
        assert!(result.is_err() || result.unwrap().has_errors());
    }

    #[test]
    fn test_variant_self_reference() {
        let result = Validator::validate_str(&wrap(
            r#"
    variant tree { leaf(string), branch(tree) }

    export init: async func(ctx: borrow<proc-context>);
    export get: async func(ctx: borrow<view-context>) -> tree;
"#,
        ));
        assert!(result.is_err() || result.unwrap().has_errors());
    }

    #[test]
    fn test_indirect_cycle_three_types() {
        let result = Validator::validate_str(&wrap(
            r#"
    record a { b-field: b }
    record b { c-field: c }
    record c { a-field: a }

    export init: async func(ctx: borrow<proc-context>);
    export get: async func(ctx: borrow<view-context>) -> a;
"#,
        ));
        assert!(result.is_err() || result.unwrap().has_errors());
    }
}
