//! Error types for WIT validation.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use wit_parser::{Resolve, Span};

/// A validation error found in a WIT file.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Clear, self-explanatory description of the error.
    pub message: String,
    /// Source span from wit-parser (byte offsets into the source text).
    pub span: Span,
}

impl ValidationError {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }

    /// Render this error with source location from the given `Resolve`.
    pub fn render(&self, resolve: &Resolve) -> String {
        if self.span.is_known() {
            format!(
                "{}: error: {}",
                resolve.render_location(self.span),
                self.message,
            )
        } else {
            format!("error: {}", self.message)
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error: {}", self.message)
    }
}

impl core::error::Error for ValidationError {}

/// The result of validating a WIT file.
#[derive(Debug, Default)]
pub struct ValidationResult {
    /// All validation errors found.
    pub errors: Vec<ValidationError>,
}

impl ValidationResult {
    /// Returns true if validation passed with no errors.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns true if there are any errors.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Render all errors with source locations from the given `Resolve`.
    pub fn render(&self, resolve: &Resolve) -> String {
        if self.is_valid() {
            return String::from("Validation passed");
        }
        let mut out = format!("Validation failed with {} error(s):\n", self.errors.len());
        for error in &self.errors {
            out.push_str(&format!("  - {}\n", error.render(resolve)));
        }
        out
    }
}

impl fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_valid() {
            write!(f, "Validation passed")
        } else {
            writeln!(f, "Validation failed with {} error(s):", self.errors.len())?;
            for error in &self.errors {
                writeln!(f, "  - {}", error)?;
            }
            Ok(())
        }
    }
}
