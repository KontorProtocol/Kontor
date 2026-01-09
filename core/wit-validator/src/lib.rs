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

pub use error::{Location, LocationKind, ValidationError, ValidationResult};
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

    use super::*;

    fn validate_fixture(wit: &str) -> ValidationResult {
        Validator::validate_str(wit).expect("Failed to parse WIT")
    }

    const VALID_BASIC: &str = include_str!("tests/fixtures/valid_basic/contract.wit");
    const VALID_LIST_U8_IN_RECORD: &str =
        include_str!("tests/fixtures/valid_list_u8_in_record/contract.wit");
    const INVALID_NO_CONTEXT: &str = include_str!("tests/fixtures/invalid_no_context/contract.wit");
    const INVALID_WRONG_CONTEXT: &str =
        include_str!("tests/fixtures/invalid_wrong_context/contract.wit");
    const INVALID_EMPTY_RECORD: &str =
        include_str!("tests/fixtures/invalid_empty_record/contract.wit");
    const INVALID_WRONG_ERROR_TYPE: &str =
        include_str!("tests/fixtures/invalid_wrong_error_type/contract.wit");
    const INVALID_NESTED_LIST: &str =
        include_str!("tests/fixtures/invalid_nested_list/contract.wit");
    const INVALID_LIST_IN_RECORD: &str =
        include_str!("tests/fixtures/invalid_list_in_record/contract.wit");
    const INVALID_RESULT_IN_PARAM: &str =
        include_str!("tests/fixtures/invalid_result_in_param/contract.wit");
    const INVALID_FLOAT: &str = include_str!("tests/fixtures/invalid_float/contract.wit");
    const INVALID_FLAGS: &str = include_str!("tests/fixtures/invalid_flags/contract.wit");
    const INVALID_CYCLE: &str = include_str!("tests/fixtures/invalid_cycle/contract.wit");
    const INVALID_SYNC_EXPORT: &str =
        include_str!("tests/fixtures/invalid_sync_export/contract.wit");
    const VALID_INIT_FALLBACK: &str =
        include_str!("tests/fixtures/valid_init_fallback/contract.wit");
    const INVALID_INIT_WRONG_CONTEXT: &str =
        include_str!("tests/fixtures/invalid_init_wrong_context/contract.wit");
    const INVALID_INIT_HAS_RETURN: &str =
        include_str!("tests/fixtures/invalid_init_has_return/contract.wit");
    const INVALID_FALLBACK_WRONG_CONTEXT: &str =
        include_str!("tests/fixtures/invalid_fallback_wrong_context/contract.wit");
    const INVALID_FALLBACK_WRONG_RETURN: &str =
        include_str!("tests/fixtures/invalid_fallback_wrong_return/contract.wit");
    const INVALID_MISSING_INIT: &str =
        include_str!("tests/fixtures/invalid_missing_init/contract.wit");

    #[test]
    fn test_empty_resolve_is_valid() {
        let resolve = Resolve::new();
        let result = Validator::validate_resolve(&resolve);
        assert!(result.is_valid());
    }

    #[test]
    fn test_valid_basic() {
        let result = validate_fixture(VALID_BASIC);
        assert!(result.is_valid(), "Expected valid, got errors: {}", result);
    }

    #[test]
    fn test_valid_list_u8_in_record() {
        let result = validate_fixture(VALID_LIST_U8_IN_RECORD);
        assert!(
            result.is_valid(),
            "Expected valid (list<u8> is allowed in records), got errors: {}",
            result
        );
    }

    #[test]
    fn test_invalid_no_context_parameter() {
        let result = validate_fixture(INVALID_NO_CONTEXT);
        assert!(
            result.has_errors(),
            "Expected error for missing context parameter"
        );
        assert!(
            result.errors.iter().any(|e| e.message.contains("context")),
            "Expected error about context parameter, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_wrong_context_type() {
        let result = validate_fixture(INVALID_WRONG_CONTEXT);
        assert!(result.has_errors(), "Expected error for wrong context type");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("context type")),
            "Expected error about context type, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_empty_record() {
        let result = validate_fixture(INVALID_EMPTY_RECORD);
        assert!(result.has_errors(), "Expected error for empty record");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("at least one field")),
            "Expected error about empty record, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_wrong_error_type() {
        let result = validate_fixture(INVALID_WRONG_ERROR_TYPE);
        assert!(result.has_errors(), "Expected error for wrong error type");
        assert!(
            result.errors.iter().any(|e| e.message.contains("'error'")),
            "Expected error about error type, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_nested_list() {
        let result = validate_fixture(INVALID_NESTED_LIST);
        assert!(result.has_errors(), "Expected error for nested list");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("nested list")),
            "Expected error about nested list, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_list_in_record() {
        let result = validate_fixture(INVALID_LIST_IN_RECORD);
        assert!(result.has_errors(), "Expected error for list<T> in record");
        assert!(
            result.errors.iter().any(|e| e.message.contains("list<T>")),
            "Expected error about list in record, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_result_in_param() {
        let result = validate_fixture(INVALID_RESULT_IN_PARAM);
        assert!(
            result.has_errors(),
            "Expected error for result in parameter"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("return type")),
            "Expected error about result usage, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_float() {
        let result = validate_fixture(INVALID_FLOAT);
        assert!(result.has_errors(), "Expected error for float type");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("floating point")),
            "Expected error about float type, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_flags() {
        let result = validate_fixture(INVALID_FLAGS);
        assert!(result.has_errors(), "Expected error for flags type");
        assert!(
            result.errors.iter().any(|e| e.message.contains("flags")),
            "Expected error about flags, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_cycle() {
        let result = Validator::validate_str(INVALID_CYCLE);
        assert!(
            result.is_err(),
            "Expected parse error for cyclic type, got: {:?}",
            result
        );
        let err = std::format!("{}", result.unwrap_err());
        assert!(
            err.contains("depends on itself"),
            "Expected error about cycle, got: {}",
            err
        );
    }

    #[test]
    fn test_invalid_sync_export() {
        let result = validate_fixture(INVALID_SYNC_EXPORT);
        assert!(result.has_errors(), "Expected error for sync export");
        assert!(
            result.errors.iter().any(|e| e.message.contains("async")),
            "Expected error about async, got: {}",
            result
        );
    }

    #[test]
    fn test_valid_init_fallback() {
        let result = validate_fixture(VALID_INIT_FALLBACK);
        assert!(
            result.is_valid(),
            "Expected valid init/fallback, got errors: {}",
            result
        );
    }

    #[test]
    fn test_invalid_init_wrong_context() {
        let result = validate_fixture(INVALID_INIT_WRONG_CONTEXT);
        assert!(
            result.has_errors(),
            "Expected error for init with wrong context"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("proc-context")),
            "Expected error about proc-context, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_init_has_return() {
        let result = validate_fixture(INVALID_INIT_HAS_RETURN);
        assert!(
            result.has_errors(),
            "Expected error for init with return type"
        );
        assert!(
            result.errors.iter().any(|e| e.message.contains("return")),
            "Expected error about return type, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_fallback_wrong_context() {
        let result = validate_fixture(INVALID_FALLBACK_WRONG_CONTEXT);
        assert!(
            result.has_errors(),
            "Expected error for fallback with wrong context"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("fall-context")),
            "Expected error about fall-context, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_fallback_wrong_return() {
        let result = validate_fixture(INVALID_FALLBACK_WRONG_RETURN);
        assert!(
            result.has_errors(),
            "Expected error for fallback with wrong return"
        );
        assert!(
            result.errors.iter().any(|e| e.message.contains("string")),
            "Expected error about string return, got: {}",
            result
        );
    }

    #[test]
    fn test_invalid_missing_init() {
        let result = validate_fixture(INVALID_MISSING_INIT);
        assert!(result.has_errors(), "Expected error for missing init");
        assert!(
            result.errors.iter().any(|e| e.message.contains("init")),
            "Expected error about missing init, got: {}",
            result
        );
    }
}

#[cfg(test)]
mod cycle_tests {
    extern crate std;

    use super::*;

    #[test]
    fn test_cross_type_cycle_record_variant() {
        let wit = r#"
package test:cross-cycle;
world root {
    include kontor:built-in/built-in;
    use kontor:built-in/context.{view-context};
    record wrapper { data: my-variant }
    variant my-variant { some(wrapper), none }
    export get: func(ctx: borrow<view-context>) -> wrapper;
}
"#;
        let result = Validator::validate_str(wit);
        std::println!("Cross-type cycle result: {:?}", result);
        assert!(result.is_err() || result.unwrap().has_errors());
    }

    #[test]
    fn test_variant_self_reference() {
        let wit = r#"
package test:variant-self;
world root {
    include kontor:built-in/built-in;
    use kontor:built-in/context.{view-context};
    variant tree { leaf(string), branch(tree) }
    export get: func(ctx: borrow<view-context>) -> tree;
}
"#;
        let result = Validator::validate_str(wit);
        std::println!("Variant self-ref result: {:?}", result);
        assert!(result.is_err() || result.unwrap().has_errors());
    }

    #[test]
    fn test_indirect_cycle_three_types() {
        let wit = r#"
package test:indirect;
world root {
    include kontor:built-in/built-in;
    use kontor:built-in/context.{view-context};
    record a { b-field: b }
    record b { c-field: c }
    record c { a-field: a }
    export get: func(ctx: borrow<view-context>) -> a;
}
"#;
        let result = Validator::validate_str(wit);
        std::println!("Indirect 3-type cycle result: {:?}", result);
        assert!(result.is_err() || result.unwrap().has_errors());
    }
}
