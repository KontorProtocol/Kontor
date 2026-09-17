use std::char::DecodeUtf16Error;
use std::str::Utf8Error;

use wasmtime::{Error, OutOfMemory, Trap};

use crate::runtime::ExecutionError;

pub(super) fn is_deterministic(error: &Error) -> bool {
    match error.downcast_ref::<ExecutionError>() {
        Some(ExecutionError::Deterministic(_)) => return true,
        Some(ExecutionError::NonDeterministic(_)) => return false,
        None => {}
    }
    if error.is::<OutOfMemory>() {
        return false;
    }
    if error.is::<Trap>() {
        return true;
    }
    // Our generated anyhow host bindings preserve this marker. A host may
    // return the same message or decoder type as a guest conversion failure.
    if error.is::<anyhow::Error>() {
        return false;
    }
    let cause = error.root_cause();
    if cause.is::<Utf8Error>() || cause.is::<DecodeUtf16Error>() {
        return true;
    }
    // Wasmtime 48.0.2 has no public types for these errors. Real conversion
    // regressions pin each message; review them when upgrading Wasmtime.
    matches!(
        cause.to_string().as_str(),
        "too much data is being copied between the host and the guest: fuel allocated for hostcalls has been exhausted"
            | "string pointer/length out of bounds of memory"
            | "string pointer not aligned to 2"
    )
}
