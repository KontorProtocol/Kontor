//! Serde deserialization for `turso::Row`.
//!
//! Mirrors `libsql::de::from_row`'s shape so call sites stay one-liners.
//! The Rust binding for Turso doesn't ship serde integration (see discussion
//! tursodatabase/turso#1145 — the maintainers explicitly target rusqlite
//! ergonomics, not libsql), so we own this layer.

use serde::de::{
    value::{Error as DeError, MapDeserializer, SeqDeserializer},
    Deserialize, Deserializer, Error as _, Visitor,
};
use turso::{Row, Rows, Value};

use super::queries::Error;

struct ValueDeserializer(Value);

impl<'de> serde::de::IntoDeserializer<'de, DeError> for ValueDeserializer {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

impl<'de> Deserializer<'de> for ValueDeserializer {
    type Error = DeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Null => visitor.visit_unit(),
            Value::Integer(i) => visitor.visit_i64(i),
            Value::Real(r) => visitor.visit_f64(r),
            Value::Text(s) => visitor.visit_string(s),
            Value::Blob(b) => visitor.visit_byte_buf(b),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    // SQLite stores booleans as integer 0/1; serde won't accept i64 for a bool field.
    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Integer(i) => visitor.visit_bool(i != 0),
            other => Err(DeError::custom(format!("expected bool, got {other:?}"))),
        }
    }

    // `Vec<u8>` (and similar `Vec<T>`) call deserialize_seq, not deserialize_any.
    // Fixed-size arrays like `[u8; 32]` call deserialize_tuple(N, _).
    // Both need Blob bytes fed through a SeqDeserializer so they round-trip.
    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Blob(b) => visitor.visit_seq(SeqDeserializer::new(b.into_iter())),
            other => Err(DeError::custom(format!("expected seq/blob, got {other:?}"))),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Blob(b) => visitor.visit_byte_buf(b),
            other => Err(DeError::custom(format!("expected bytes/blob, got {other:?}"))),
        }
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_bytes(visitor)
    }

    serde::forward_to_deserialize_any! {
        i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        unit unit_struct newtype_struct
        tuple_struct map struct enum identifier ignored_any
    }
}

struct RowDeserializer<'a> {
    row: &'a Row,
    cols: &'a [String],
}

impl<'de, 'a> Deserializer<'de> for RowDeserializer<'a> {
    type Error = DeError;

    fn deserialize_any<V: Visitor<'de>>(self, _v: V) -> Result<V::Value, Self::Error> {
        Err(DeError::custom("rows can only be deserialized into structs"))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        let pairs = self
            .cols
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let value = self
                    .row
                    .get_value(i)
                    .map_err(|e| DeError::custom(format!("row.get_value({i}): {e}")))?;
                Ok((name.as_str(), ValueDeserializer(value)))
            })
            .collect::<Result<Vec<_>, DeError>>()?;
        visitor.visit_map(MapDeserializer::new(pairs.into_iter()))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}

/// Deserialize the next row into `T`, returning `None` if the row stream is
/// exhausted. Direct replacement for `rows.next().await?.map(|r| from_row(&r)).transpose()?`.
pub async fn first_row<T: for<'de> Deserialize<'de>>(rows: &mut Rows) -> Result<Option<T>, Error> {
    let cols = rows.column_names();
    let Some(row) = rows.next().await? else {
        return Ok(None);
    };
    let de = RowDeserializer { row: &row, cols: &cols };
    Ok(Some(T::deserialize(de)?))
}

/// Deserialize all remaining rows into `Vec<T>`.
pub async fn collect_rows<T: for<'de> Deserialize<'de>>(
    rows: &mut Rows,
) -> Result<Vec<T>, Error> {
    let cols = rows.column_names();
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        let de = RowDeserializer { row: &row, cols: &cols };
        out.push(T::deserialize(de)?);
    }
    Ok(out)
}
