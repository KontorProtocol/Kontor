use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::de::{Error, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::model::FileRef;
use crate::container::sha256;

struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("integer JSON without duplicate keys")
            }
            fn visit_bool<E: Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }
            fn visit_i64<E: Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }
            fn visit_u64<E: Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }
            fn visit_str<E: Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.into())))
            }
            fn visit_unit<E: Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut object: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, StrictValue(value))) =
                    object.next_entry::<String, StrictValue>()?
                {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(A::Error::custom(format!("duplicate JSON key: {key}")));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes)?;
    Ok(serde_json::from_str::<StrictValue>(text)?.0)
}

pub(super) struct Fixture {
    pub root: PathBuf,
    pub manifest: Value,
    pub sha256: String,
}
impl Fixture {
    pub fn open(path: &Path) -> Result<Self> {
        let path = path.canonicalize()?;
        let bytes = fs::read(&path)?;
        Ok(Self {
            root: path.parent().context("manifest parent")?.to_path_buf(),
            manifest: parse(&bytes)?,
            sha256: hex::encode(Sha256::digest(&bytes)),
        })
    }
    fn reference_path(&self, reference: &FileRef) -> Result<PathBuf> {
        let name = &reference.path.0;
        ensure!(
            !name.contains(['\\', '\0'])
                && !Path::new(name).is_absolute()
                && name.split('/').all(|p| !matches!(p, "" | "." | "..")),
            "expected canonical relative POSIX path"
        );
        let path = self.root.join(name).canonicalize()?;
        ensure!(
            path.starts_with(&self.root) && path.is_file(),
            "missing fixture file or directory escape"
        );
        Ok(path)
    }
    pub fn verify_references(&self, value: &Value) -> Result<()> {
        match value {
            Value::Object(fields)
                if fields.len() == 2
                    && fields.contains_key("path")
                    && fields.contains_key("sha256") =>
            {
                let reference: FileRef = serde_json::from_value(value.clone())?;
                ensure!(
                    sha256(&self.reference_path(&reference)?)? == reference.sha256.0,
                    "fixture SHA-256 mismatch"
                );
            }
            Value::Object(fields) => {
                for child in fields.values() {
                    self.verify_references(child)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    self.verify_references(child)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub fn document(&self, reference: &FileRef) -> Result<Value> {
        let bytes = fs::read(self.reference_path(reference)?)?;
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == reference.sha256.0,
            "fixture SHA-256 mismatch"
        );
        parse(&bytes)
    }
}
