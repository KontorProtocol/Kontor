use std::sync::Arc;

use libsql::Connection;

use crate::protocol::storage_session::{SavepointAction, SessionCallbacks, TransactionAction};

fn transaction_action(conn: &Connection, sql: &'static str) -> TransactionAction {
    let conn = conn.clone();
    Arc::new(move || {
        let conn = conn.clone();
        Box::pin(async move {
            conn.execute(sql, ())
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
    })
}

fn savepoint_action(conn: &Connection, prefix: &'static str) -> SavepointAction {
    let conn = conn.clone();
    Arc::new(move |index| {
        let conn = conn.clone();
        Box::pin(async move {
            conn.execute(&format!("{prefix} S{index}"), ())
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
    })
}

pub(crate) fn session_callbacks(conn: &Connection) -> SessionCallbacks {
    (
        transaction_action(conn, "BEGIN TRANSACTION"),
        savepoint_action(conn, "SAVEPOINT"),
        transaction_action(conn, "COMMIT"),
        savepoint_action(conn, "RELEASE"),
        transaction_action(conn, "ROLLBACK"),
        savepoint_action(conn, "ROLLBACK TO"),
        transaction_action(conn, "BEGIN IMMEDIATE"),
    )
}
