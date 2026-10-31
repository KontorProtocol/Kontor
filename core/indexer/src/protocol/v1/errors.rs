use std::char::{CharTryFromError, DecodeUtf16Error};
use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::str::Utf8Error;

use anyhow::{Error as AnyError, Result};
use indexer_types::OpStatus;
use wasmtime::{Error as WasmtimeError, OutOfMemory, Trap};

use crate::runtime::GuestMemoryLimitExceeded;

/// Distinguishes deterministic failures from non-deterministic failures
/// in the contract execution path.
#[derive(Debug)]
pub enum ExecutionError {
    /// Deterministic failure — all nodes see the same result for the same inputs.
    /// WASM traps, contract not found, bad arguments, etc.
    /// Caller should rollback and continue processing.
    Deterministic(AnyError),
    /// Non-deterministic failure — DB/IO error, host panic, tokio task failure.
    /// Different nodes may see different results.
    /// Caller should propagate to reactor and shut down.
    NonDeterministic(AnyError),
}

impl Display for ExecutionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (kind, error) = match self {
            ExecutionError::Deterministic(error) => ("deterministic error", error),
            ExecutionError::NonDeterministic(error) => ("non-deterministic error", error),
        };
        write!(f, "{kind}: ")?;
        // Expand causes only when the outer caller requests it. Chain formatters
        // use ordinary Display for each source, avoiding recursive expansion.
        Display::fmt(error, f)
    }
}

impl StdError for ExecutionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ExecutionError::Deterministic(e) | ExecutionError::NonDeterministic(e) => {
                Some(e.as_ref())
            }
        }
    }
}

/// Convert an anyhow error to ExecutionError, preserving the classification
/// if the error already contains an ExecutionError (e.g. from a cross-contract
/// call through the WIT foreign::call boundary). Falls back to NonDeterministic
/// for errors without an ExecutionError inside.
impl From<AnyError> for ExecutionError {
    fn from(e: AnyError) -> Self {
        match e.downcast::<ExecutionError>() {
            Ok(ee) => ee,
            Err(e) => ExecutionError::NonDeterministic(e),
        }
    }
}

pub(crate) fn is_deterministic(error: &WasmtimeError) -> bool {
    match error.downcast_ref::<ExecutionError>() {
        Some(ExecutionError::Deterministic(_)) => return true,
        Some(ExecutionError::NonDeterministic(_)) => return false,
        None => {}
    }
    if error.is::<OutOfMemory>() {
        return false;
    }
    if error.is::<GuestMemoryLimitExceeded>() {
        return true;
    }
    if error.is::<Trap>() {
        return true;
    }
    // Our generated anyhow host bindings preserve this marker. A host may
    // return the same message or decoder type as a guest conversion failure.
    if error.is::<AnyError>() {
        return false;
    }
    let cause = error.root_cause();
    if cause.is::<Utf8Error>() || cause.is::<DecodeUtf16Error>() || cause.is::<CharTryFromError>() {
        return true;
    }
    // The pinned Wasmtime fork has no public types for these guest canonical
    // errors. Keep the host-origin guard above and repin these tests on upgrade.
    let message = cause.to_string();
    matches!(
        message.as_str(),
        "too much data is being copied between the host and the guest: fuel allocated for hostcalls has been exhausted"
            | "borrow handles still remain at the end of the call"
            | "string pointer/length out of bounds of memory"
            | "string pointer not aligned to 2"
            | "list pointer/length out of bounds of memory"
            | "list pointer is not aligned"
            | "return pointer not aligned"
            | "pointer out of bounds of memory"
            | "realloc return: result not aligned"
            | "realloc return: beyond end of memory"
            | "invalid option discriminant"
            | "invalid expected discriminant"
    ) || is_invalid_discriminant(&message)
        || is_resource_limit(&message)
        || is_unknown_handle_index(&message)
        || is_guest_resource_type_mismatch(&message)
}

fn is_canonical_u32(value: &str) -> bool {
    value
        .parse::<u32>()
        .is_ok_and(|index| value == index.to_string())
}

fn is_unknown_handle_index(message: &str) -> bool {
    let Some(index) = message.strip_prefix("unknown handle index ") else {
        return false;
    };
    is_canonical_u32(index) && message == format!("unknown handle index {index}")
}

fn is_guest_resource_type_mismatch(message: &str) -> bool {
    const SUFFIX: &str = " used with the wrong type, expected guest-defined resource but found a different guest-defined resource";
    let Some(index) = message
        .strip_prefix("handle index ")
        .and_then(|value| value.strip_suffix(SUFFIX))
    else {
        return false;
    };
    is_canonical_u32(index) && message == format!("handle index {index}{SUFFIX}")
}

fn is_resource_limit(message: &str) -> bool {
    if let Some((resource, count)) = message
        .strip_prefix("resource limit exceeded: ")
        .and_then(|s| s.split_once(" count too high at "))
    {
        return matches!(resource, "instance" | "memory" | "table")
            && count
                .parse::<usize>()
                .is_ok_and(|value| count == value.to_string());
    }
    message
        .strip_prefix("table minimum size of ")
        .and_then(|s| s.strip_suffix(" elements exceeds table limits"))
        .is_some_and(|count| {
            count
                .parse::<usize>()
                .is_ok_and(|value| count == value.to_string())
        })
}

fn is_invalid_discriminant(message: &str) -> bool {
    if let Some(discriminant) = message.strip_prefix("unexpected discriminant: ") {
        return discriminant
            .parse::<u32>()
            .is_ok_and(|value| discriminant == value.to_string());
    }
    let Some((discriminant, len)) = message
        .strip_prefix("discriminant ")
        .and_then(|s| s.strip_suffix(')'))
        .and_then(|s| s.split_once(" out of range [0.."))
    else {
        return false;
    };
    let (Ok(discriminant), Ok(len)) = (discriminant.parse::<u32>(), len.parse::<u32>()) else {
        return false;
    };
    // Pin Wasmtime's complete format, including canonical decimal integers.
    discriminant >= len && message == format!("discriminant {discriminant} out of range [0..{len})")
}

/// Categorize the result of a wasm call into a persisted `OpStatus`.
///
/// - `Ok(s)` where `s` starts with `"err("` means the contract function
///   returned a `result<_, error>::Err` value. The call ran cleanly but
///   the semantic outcome was a failure; storage was rolled back. Treated
///   as `OpStatus::ContractErr`.
/// - `Ok(_)` otherwise is a successful call returning either a value or
///   nothing. `OpStatus::Ok`.
/// - `Err(ExecutionError::Deterministic(e))` is mapped by looking at the
///   underlying error for a `wasmtime::Trap` variant. `Trap::OutOfFuel`
///   becomes `OpStatus::OutOfFuel`; other trap variants become
///   `OpStatus::Trap`. Non-trap errors become `OpStatus::Other`.
/// - `Err(NonDeterministic)` shouldn't normally produce a row — those
///   propagate as fatal infrastructure errors and the block won't
///   commit. Mapped to `Other` for completeness.
pub(crate) fn classify_result(result: &Result<String, ExecutionError>) -> OpStatus {
    match result {
        Ok(v) if v.starts_with("err(") => OpStatus::ContractErr,
        Ok(_) => OpStatus::Ok,
        Err(ExecutionError::Deterministic(e)) => {
            if let Some(trap) = e.downcast_ref::<Trap>() {
                match trap {
                    Trap::OutOfFuel => OpStatus::OutOfFuel,
                    _ => OpStatus::Trap,
                }
            } else {
                OpStatus::Other
            }
        }
        Err(ExecutionError::NonDeterministic(_)) => OpStatus::Other,
    }
}
