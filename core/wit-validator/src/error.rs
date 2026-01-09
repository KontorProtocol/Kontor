//! Error types for WIT validation.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// A validation error found in a WIT file.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Clear, self-explanatory description of the error.
    pub message: String,
    /// Where in the WIT the error occurred.
    pub location: Location,
}

impl ValidationError {
    pub fn new(message: impl Into<String>, location: Location) -> Self {
        Self {
            message: message.into(),
            location,
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.message, self.location)
    }
}

impl core::error::Error for ValidationError {}

/// Location information for where an error occurred.
#[derive(Debug, Clone)]
pub struct Location {
    /// What kind of WIT element this is.
    pub kind: LocationKind,
    /// The name of the element (e.g., function name, type name).
    pub name: String,
    /// Additional detail (e.g., field name, parameter name).
    pub detail: Option<String>,
}

impl Location {
    pub fn function(name: impl Into<String>) -> Self {
        Self {
            kind: LocationKind::Function,
            name: name.into(),
            detail: None,
        }
    }

    pub fn type_def(name: impl Into<String>) -> Self {
        Self {
            kind: LocationKind::Type,
            name: name.into(),
            detail: None,
        }
    }

    pub fn field(type_name: impl Into<String>, field_name: impl Into<String>) -> Self {
        Self {
            kind: LocationKind::Field,
            name: type_name.into(),
            detail: Some(field_name.into()),
        }
    }

    pub fn parameter(func_name: impl Into<String>, param_name: impl Into<String>) -> Self {
        Self {
            kind: LocationKind::Parameter,
            name: func_name.into(),
            detail: Some(param_name.into()),
        }
    }

    pub fn return_type(func_name: impl Into<String>) -> Self {
        Self {
            kind: LocationKind::ReturnType,
            name: func_name.into(),
            detail: None,
        }
    }

    pub fn variant_case(type_name: impl Into<String>, case_name: impl Into<String>) -> Self {
        Self {
            kind: LocationKind::VariantCase,
            name: type_name.into(),
            detail: Some(case_name.into()),
        }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.kind, &self.detail) {
            (LocationKind::Function, None) => write!(f, "function '{}'", self.name),
            (LocationKind::Type, None) => write!(f, "type '{}'", self.name),
            (LocationKind::Field, Some(field)) => {
                write!(f, "field '{}' in type '{}'", field, self.name)
            }
            (LocationKind::Parameter, Some(param)) => {
                write!(f, "parameter '{}' in function '{}'", param, self.name)
            }
            (LocationKind::ReturnType, None) => {
                write!(f, "return type of function '{}'", self.name)
            }
            (LocationKind::VariantCase, Some(case)) => {
                write!(f, "case '{}' in variant '{}'", case, self.name)
            }
            _ => write!(f, "{:?} '{}'", self.kind, self.name),
        }
    }
}

/// The kind of WIT element where an error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationKind {
    Function,
    Type,
    Field,
    Parameter,
    ReturnType,
    VariantCase,
}

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
