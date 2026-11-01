use std::sync::Arc;

use libsql::{Connection, Error as DriverError, Rows, params};

use super::{
    Error, create_contract_signer, get_contract_signer_id, get_signer_entry_by_id, latest_one,
};
use crate::protocol::storage_identity::{CoreCallbacks, IdentityCallbacks, NonceCallbacks};
use crate::protocol::storage_rows::CursorOwner;

fn driver_error(error: DriverError) -> String {
    Error::from(error).to_string()
}

pub(crate) fn identity_callbacks(conn: &Connection) -> IdentityCallbacks {
    (
        {
            let conn = conn.clone();
            Arc::new(move |pubkey| {
                let conn = conn.clone();
                Box::pin(async move {
                    let mut rows = conn
                        .query(
                            "SELECT signer_id FROM x_only_pubkeys WHERE x_only_pubkey = ?",
                            params![pubkey],
                        )
                        .await
                        .map_err(driver_error)?;
                    rows.next()
                        .await
                        .map_err(driver_error)?
                        .map(|row| row.get::<i64>(0).map(|id| id as u64))
                        .transpose()
                        .map_err(driver_error)
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |height| {
                let conn = conn.clone();
                Box::pin(async move {
                    create_contract_signer(&conn, height)
                        .await
                        .map_err(|e| e.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |signer_id, pubkey, height| {
                let conn = conn.clone();
                Box::pin(async move {
                    conn.execute("INSERT INTO x_only_pubkeys (signer_id, x_only_pubkey, height) VALUES (?, ?, ?)", params![signer_id, pubkey, height]).await.map(|_| ()).map_err(driver_error)
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |signer_id, height| {
                let conn = conn.clone();
                Box::pin(async move {
                    conn.execute(
                        "INSERT INTO nonces (signer_id, next_nonce, height) VALUES (?, 0, ?)",
                        params![signer_id, height],
                    )
                    .await
                    .map(|_| ())
                    .map_err(driver_error)
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |signer_id| {
                let conn = conn.clone();
                Box::pin(async move {
                    let mut rows = conn
                        .query(
                            &latest_one("x_only_pubkeys", "signer_id", "x_only_pubkey"),
                            params![signer_id],
                        )
                        .await
                        .map_err(driver_error)?;
                    rows.next()
                        .await
                        .map_err(driver_error)?
                        .map(|row| row.get(0))
                        .transpose()
                        .map_err(driver_error)
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |signer_id| {
                let conn = conn.clone();
                Box::pin(async move {
                    let mut rows = conn
                        .query(
                            &latest_one("bls_keys", "signer_id", "bls_pubkey"),
                            params![signer_id],
                        )
                        .await
                        .map_err(driver_error)?;
                    rows.next()
                        .await
                        .map_err(driver_error)?
                        .map(|row| row.get(0))
                        .transpose()
                        .map_err(driver_error)
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |signer_id, pubkey, height| {
                let conn = conn.clone();
                Box::pin(async move {
                    conn.execute("INSERT OR REPLACE INTO bls_keys (signer_id, bls_pubkey, height) VALUES (?, ?, ?)", params![signer_id, pubkey, height]).await.map(|_| ()).map_err(driver_error)
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |contract_id| {
                let conn = conn.clone();
                Box::pin(async move {
                    get_contract_signer_id(&conn, contract_id)
                        .await
                        .map_err(|e| e.to_string())
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |signer_id| {
                let conn = conn.clone();
                Box::pin(async move {
                    get_signer_entry_by_id(&conn, signer_id)
                        .await
                        .map(|entry| {
                            entry.map(|entry| {
                                (
                                    entry.signer_id,
                                    entry.x_only_pubkey,
                                    entry.bls_pubkey,
                                    entry.next_nonce,
                                )
                            })
                        })
                        .map_err(|error| error.to_string())
                })
            })
        },
    )
}

pub(crate) fn core_callbacks(conn: &Connection) -> CoreCallbacks {
    let read_conn = conn.clone();
    let write_conn = conn.clone();
    (
        Arc::new(move || {
            let conn = read_conn.clone();
            Box::pin(async move {
                conn.query("SELECT id FROM signers ORDER BY id ASC LIMIT 1", ())
                    .await
                    .map_err(driver_error)?
                    .next()
                    .await
                    .map_err(driver_error)?
                    .map(|row| row.get::<i64>(0).map(|id| id as u64))
                    .transpose()
                    .map_err(driver_error)
            })
        }),
        Arc::new(move || {
            let conn = write_conn.clone();
            Box::pin(async move {
                conn.execute("INSERT INTO signers (height) VALUES (0)", ())
                    .await
                    .map_err(driver_error)?;
                Ok(conn.last_insert_rowid() as u64)
            })
        }),
    )
}

struct NonceOwner {
    conn: Connection,
    signer_id: u64,
    rows: Rows,
}

pub(crate) fn nonce_callbacks(conn: &Connection) -> NonceCallbacks {
    let conn = conn.clone();
    (
        Arc::new(move |signer_id| {
            let conn = conn.clone();
            Box::pin(async move {
                let mut rows = conn
                    .query(
                        &latest_one("nonces", "signer_id", "next_nonce"),
                        params![signer_id],
                    )
                    .await
                    .map_err(driver_error)?;
                let nonce = rows
                    .next()
                    .await
                    .map_err(driver_error)?
                    .map(|row| row.get(0))
                    .transpose()
                    .map_err(driver_error)?;
                Ok((
                    Box::new(NonceOwner {
                        conn,
                        signer_id,
                        rows,
                    }) as CursorOwner,
                    nonce,
                ))
            })
        }),
        Arc::new(move |owner, next_nonce, height| {
            Box::pin(async move {
                let owner = owner.downcast::<NonceOwner>().map_err(|_| {
                    "StorageV1 received a nonce owned by another adapter".to_owned()
                })?;
                owner.conn.execute("INSERT OR REPLACE INTO nonces (signer_id, next_nonce, height) VALUES (?, ?, ?)", params![owner.signer_id, next_nonce, height]).await.map_err(driver_error)?;
                drop(owner.rows);
                Ok(())
            })
        }),
    )
}
