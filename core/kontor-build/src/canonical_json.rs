use std::io::{self, Write};

use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::Value;
use serde_json::ser::{Formatter, Serializer};

struct Spaced;
impl Formatter for Spaced {
    fn begin_array_value<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }
    fn begin_object_key<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }
    fn begin_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        writer.write_all(b": ")
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Style {
    Compact,
    Pretty,
    Spaced,
}

// Existing references use Python's sorted ASCII JSON, including UTF-16 escapes
// for supplementary characters. Changing these bytes would change identities.
pub(crate) fn encode(value: &Value, style: Style) -> Result<String> {
    fn integers(value: &Value) -> bool {
        match value {
            Value::Number(n) => !n.is_f64(),
            Value::Array(a) => a.iter().all(integers),
            Value::Object(o) => o.values().all(integers),
            _ => true,
        }
    }
    ensure!(
        integers(value),
        "canonical evidence requires integer JSON numbers"
    );
    let mut value = value.clone();
    value.sort_all_objects();
    let source = match style {
        Style::Compact => serde_json::to_string(&value)?,
        Style::Pretty => serde_json::to_string_pretty(&value)?,
        Style::Spaced => {
            let mut bytes = Vec::new();
            value.serialize(&mut Serializer::with_formatter(&mut bytes, Spaced))?;
            String::from_utf8(bytes)?
        }
    };
    let mut result = String::new();
    for c in source.chars() {
        if c < '\u{7f}' {
            result.push(c);
        } else {
            for word in c.encode_utf16(&mut [0; 2]) {
                result.push_str(&format!("\\u{word:04x}"));
            }
        }
    }
    Ok(result)
}
