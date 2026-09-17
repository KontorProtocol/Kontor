use std::char::{CharTryFromError, DecodeUtf16Error};
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
    if cause.is::<Utf8Error>() || cause.is::<DecodeUtf16Error>() || cause.is::<CharTryFromError>() {
        return true;
    }
    // Wasmtime 48.0.2 has no public types for these errors. Real conversion
    // regressions pin each message; review them when upgrading Wasmtime.
    let message = cause.to_string();
    matches!(
        message.as_str(),
        "too much data is being copied between the host and the guest: fuel allocated for hostcalls has been exhausted"
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
