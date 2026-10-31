use std::error::Error;
use std::sync::Arc;

use bitcoin::hashes::Hash;
use libsql::Connection;

use super::queries::{
    depositors_affected_by_reorg, prune_contract_state, rollback_to_height, select_block_at_height,
};
use crate::protocol::storage_aux::{AuxiliaryCallbacks, StorageFailure};

fn failure(error: impl Error + 'static) -> StorageFailure {
    let mut causes = vec![error.to_string()];
    let mut cause = error.source();
    while let Some(error) = cause {
        causes.push(error.to_string());
        cause = error.source();
    }
    causes
}

pub(crate) fn auxiliary_callbacks(conn: &Connection) -> AuxiliaryCallbacks {
    (
        (
            {
                let conn = conn.clone();
                Arc::new(move |height| {
                    let conn = conn.clone();
                    Box::pin(async move {
                        depositors_affected_by_reorg(&conn, height)
                            .await
                            .map_err(failure)
                    })
                })
            },
            {
                let conn = conn.clone();
                Arc::new(move |height| {
                    let conn = conn.clone();
                    Box::pin(
                        async move { rollback_to_height(&conn, height).await.map_err(failure) },
                    )
                })
            },
            {
                let conn = conn.clone();
                Arc::new(move |height| {
                    let conn = conn.clone();
                    Box::pin(async move {
                        select_block_at_height(&conn, height)
                            .await
                            .map(|block| block.map(|block| block.hash.to_byte_array().to_vec()))
                            .map_err(failure)
                    })
                })
            },
        ),
        (
            {
                let conn = conn.clone();
                Arc::new(move |previous, height| {
                    let conn = conn.clone();
                    Box::pin(async move {
                        prune_contract_state(&conn, previous, height)
                            .await
                            .map_err(failure)
                    })
                })
            },
            {
                let conn = conn.clone();
                Arc::new(move || {
                    let conn = conn.clone();
                    Box::pin(async move {
                        let mut rows = conn
                            .query("PRAGMA freelist_count;", ())
                            .await
                            .map_err(failure)?;
                        match rows.next().await.map_err(failure)? {
                            Some(row) => row.get(0).map_err(failure),
                            None => Ok(0),
                        }
                    })
                })
            },
            {
                let conn = conn.clone();
                Arc::new(move |pages| {
                    let conn = conn.clone();
                    Box::pin(async move {
                        conn.query(&format!("PRAGMA incremental_vacuum({pages});"), ())
                            .await
                            .map_err(failure)?;
                        Ok(())
                    })
                })
            },
        ),
    )
}
