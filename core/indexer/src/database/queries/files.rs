use turso::{Connection, Value, params};

use super::Error;
use crate::database::de::{collect_rows, first_row};
use crate::database::types::FileMetadataRow;

pub async fn select_all_file_metadata(conn: &Connection) -> Result<Vec<FileMetadataRow>, Error> {
    let mut rows = conn
        .query(
            r#"SELECT
            id,
            file_id,
            object_id,
            nonce,
            root,
            padded_len,
            original_size,
            filename,
            height,
            historical_root
            FROM file_metadata
            ORDER BY id ASC"#,
            params![],
        )
        .await?;

    collect_rows(&mut rows).await
}

pub async fn select_file_metadata_by_file_id(
    conn: &Connection,
    file_id: &str,
) -> Result<Option<FileMetadataRow>, Error> {
    let mut rows = conn
        .query(
            r#"SELECT
            id,
            file_id,
            object_id,
            nonce,
            root,
            padded_len,
            original_size,
            filename,
            height,
            historical_root
            FROM file_metadata
            WHERE file_id = ?
            LIMIT 1"#,
            params![file_id],
        )
        .await?;

    first_row(&mut rows).await
}

pub async fn insert_file_metadata(
    conn: &Connection,
    entry: &FileMetadataRow,
) -> Result<i64, Error> {
    let historical_root_value: Value = match &entry.historical_root {
        Some(root) => Value::Blob(root.to_vec()),
        None => Value::Null,
    };

    conn.execute(
        r#"INSERT INTO
        file_metadata
        (file_id,
        object_id,
        nonce,
        root,
        padded_len,
        original_size,
        filename,
        height,
        historical_root)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        params![
            entry.file_id.clone(),
            entry.object_id.clone(),
            entry.nonce.clone(),
            entry.root,
            entry.padded_len,
            entry.original_size,
            entry.filename.clone(),
            entry.height,
            historical_root_value,
        ],
    )
    .await?;
    Ok(conn.last_insert_rowid())
}
