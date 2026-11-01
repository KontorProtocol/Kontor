use std::collections::BTreeMap;

use anyhow::Result;
use libsql::{Connection, Value as SqlValue};
use serde_json::{Value, json};

// This snapshot includes every persistent table, preserving value types and
// ignoring only physical row order and SQLite page/WAL layout.
pub(crate) async fn full_state(conn: &Connection) -> Result<Value> {
    let mut names = conn
        .query(
            "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name",
            (),
        )
        .await?;
    let mut result = BTreeMap::new();
    while let Some(table) = names.next().await? {
        let name: String = table.get(0)?;
        let quoted = name.replace('"', "\"\"");
        let mut rows = conn
            .query(&format!("SELECT * FROM \"{quoted}\""), ())
            .await?;
        let count = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            let mut fields = Vec::new();
            for column in 0..count {
                fields.push(match row.get_value(column)? {
                    SqlValue::Null => json!(["null"]),
                    SqlValue::Integer(value) => json!(["integer", value]),
                    SqlValue::Real(value) => json!(["real_bits", value.to_bits()]),
                    SqlValue::Text(value) => json!(["text", value]),
                    SqlValue::Blob(value) => json!(["blob", hex::encode(value)]),
                });
            }
            values.push(serde_json::to_string(&fields)?);
        }
        values.sort();
        result.insert(name, values);
    }
    Ok(serde_json::to_value(result)?)
}
