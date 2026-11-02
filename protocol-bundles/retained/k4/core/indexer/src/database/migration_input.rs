use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, ensure};
use bitcoin::BlockHash;
use libsql::{Builder, Connection, Row, params};
use tokio::sync::Mutex;

use super::canonical_history::{self, ApplicationCursor, HistoryState};
use crate::protocol::migration_input::{INPUT_CHUNK_BYTES, InputCallbacks, InputRow};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InputMetadata {
    pub(crate) row: i64,
    pub(crate) key_bytes: u64,
    pub(crate) value_bytes: u64,
    pub(crate) depositor: Option<u64>,
    pub(crate) deposited_gas: Option<u64>,
}

impl InputMetadata {
    fn from_row(row: Row) -> Result<Self> {
        Ok(Self {
            row: row.get(0)?,
            key_bytes: row.get(1)?,
            value_bytes: row.get(2)?,
            depositor: row.get(3)?,
            deposited_gas: row.get(4)?,
        })
    }
}

enum InputState {
    Fresh,
    Pinning,
    Pinned,
    Closed,
}

// This connection belongs to one canonical root, never to an API pool or a
// retained executor. A completed capability cannot be repinned for another root.
pub(crate) struct MigrationInput {
    conn: Connection,
    path: String,
    state: Mutex<InputState>,
    claimed: AtomicBool,
}

struct RowHandle {
    input: Arc<MigrationInput>,
    metadata: InputMetadata,
}

impl MigrationInput {
    pub(crate) async fn open(writer: &Connection) -> Result<Arc<Self>> {
        ensure!(
            writer.is_autocommit(),
            "migration input requires an idle writer"
        );
        let path = Self::database_path(writer).await?;
        let database = Builder::new_local(&path).build().await?;
        let conn = database.connect()?;
        conn.execute_batch("PRAGMA query_only = ON; PRAGMA busy_timeout = 5000;")
            .await?;
        Ok(Arc::new(Self {
            conn,
            path,
            state: Mutex::new(InputState::Fresh),
            claimed: AtomicBool::new(false),
        }))
    }

    async fn database_path(writer: &Connection) -> Result<String> {
        let path: String = writer
            .query(
                "SELECT file FROM pragma_database_list WHERE name = 'main'",
                (),
            )
            .await?
            .next()
            .await?
            .context("writer has no main database")?
            .get(0)?;
        ensure!(
            !path.is_empty(),
            "migration input requires a persistent database"
        );
        Ok(path)
    }

    pub(crate) async fn verify_writer(&self, writer: &Connection) -> Result<()> {
        ensure!(
            self.path == Self::database_path(writer).await?,
            "migration input belongs to another database"
        );
        Ok(())
    }

    fn row(self: &Arc<Self>, metadata: InputMetadata) -> InputRow {
        (
            Arc::new(RowHandle {
                input: self.clone(),
                metadata: metadata.clone(),
            }),
            metadata.key_bytes,
            metadata.value_bytes,
            metadata.depositor,
            metadata.deposited_gas,
        )
    }

    pub(crate) fn callbacks(self: &Arc<Self>) -> InputCallbacks {
        let point = self.clone();
        let next = self.clone();
        let chunk = self.clone();
        (
            Arc::new(move |contract, key| {
                let input = point.clone();
                Box::pin(async move {
                    input
                        .point(contract, &key)
                        .await
                        .map(|row| row.map(|row| input.row(row)))
                        .map_err(|error| error.to_string())
                })
            }),
            Arc::new(move |contract, after| {
                let input = next.clone();
                Box::pin(async move {
                    input
                        .next(contract, after.as_deref())
                        .await
                        .map(|row| row.map(|row| input.row(row)))
                        .map_err(|error| error.to_string())
                })
            }),
            Arc::new(move |owner, key, offset, length| {
                let input = chunk.clone();
                Box::pin(async move {
                    let row = owner
                        .downcast::<RowHandle>()
                        .map_err(|_| "migration input row has another adapter".to_owned())?;
                    if !Arc::ptr_eq(&input, &row.input) {
                        return Err("migration input row belongs to another root".into());
                    }
                    let size = if key {
                        row.metadata.key_bytes
                    } else {
                        row.metadata.value_bytes
                    };
                    if offset
                        .checked_add(u64::from(length))
                        .is_none_or(|end| end > size)
                    {
                        return Err("migration input chunk exceeds the row".into());
                    }
                    input
                        .chunk(row.metadata.row, key, offset, length)
                        .await
                        .map_err(|error| error.to_string())
                })
            }),
        )
    }

    pub(crate) fn claim(&self) -> Result<()> {
        ensure!(
            self.claimed
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok(),
            "migration input already belongs to a root"
        );
        Ok(())
    }

    pub(crate) async fn pin(
        &self,
        expected: ApplicationCursor,
        anchor_height: u64,
        anchor_hash: BlockHash,
    ) -> Result<()> {
        ensure!(
            self.claimed.load(Ordering::SeqCst),
            "migration input has no root"
        );
        let mut state = self.state.lock().await;
        ensure!(
            matches!(*state, InputState::Fresh),
            "migration input cannot be repinned"
        );
        ensure!(
            self.conn.is_autocommit(),
            "migration input already has a transaction"
        );
        *state = InputState::Pinning;
        self.conn.execute("BEGIN", ()).await?;
        // This main-database query establishes the SQLite snapshot. BEGIN and
        // constant SELECTs alone would allow a later read to see newer writes.
        let actual = canonical_history::state(&self.conn).await?;
        ensure!(
            actual == HistoryState::Ready(expected) && expected.authentic,
            "migration input does not match the expected canonical lineage"
        );
        let hash: String = self
            .conn
            .query("SELECT hash FROM blocks WHERE height = ?1", [anchor_height])
            .await?
            .next()
            .await?
            .context("migration anchor is absent")?
            .get(0)?;
        ensure!(
            hash == anchor_hash.to_string(),
            "migration input anchor changed"
        );
        *state = InputState::Pinned;
        Ok(())
    }

    pub(crate) async fn point(&self, contract: u64, key: &[u8]) -> Result<Option<InputMetadata>> {
        let state = self.state.lock().await;
        ensure!(
            matches!(*state, InputState::Pinned),
            "migration input is not pinned"
        );
        let mut rows = self
            .conn
            .query(
                "SELECT s.rowid, length(s.path), length(s.value), s.depositor, s.deposited_gas
             FROM current_contract_state c JOIN contract_state s
             ON s.contract_id = c.contract_id AND s.path = c.path AND s.height = c.height
             WHERE c.contract_id = ?1 AND c.path = ?2",
                params![contract, key],
            )
            .await?;
        rows.next().await?.map(InputMetadata::from_row).transpose()
    }

    pub(crate) async fn next(
        &self,
        contract: u64,
        after: Option<&[u8]>,
    ) -> Result<Option<InputMetadata>> {
        let state = self.state.lock().await;
        ensure!(
            matches!(*state, InputState::Pinned),
            "migration input is not pinned"
        );
        // Separate predicates retain an indexed range seek, including the first
        // empty key. No path/value bytes are allocated by this metadata query.
        let predicate = if after.is_some() {
            "AND c.path > ?2"
        } else {
            "AND ?2 IS NULL"
        };
        let sql = format!(
            "SELECT s.rowid, length(s.path), length(s.value), s.depositor, s.deposited_gas
             FROM current_contract_state c JOIN contract_state s
             ON s.contract_id = c.contract_id AND s.path = c.path AND s.height = c.height
             WHERE c.contract_id = ?1 {predicate} ORDER BY c.path LIMIT 1"
        );
        let mut rows = self.conn.query(&sql, params![contract, after]).await?;
        rows.next().await?.map(InputMetadata::from_row).transpose()
    }

    pub(crate) async fn chunk(
        &self,
        row: i64,
        key: bool,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>> {
        ensure!(
            length <= INPUT_CHUNK_BYTES,
            "migration input chunk is too large"
        );
        let start = i64::try_from(offset)?
            .checked_add(1)
            .context("migration chunk offset overflow")?;
        let state = self.state.lock().await;
        ensure!(
            matches!(*state, InputState::Pinned),
            "migration input is not pinned"
        );
        let field = if key { "path" } else { "value" };
        let sql = format!("SELECT substr({field}, ?2, ?3) FROM contract_state WHERE rowid = ?1");
        let value = self
            .conn
            .query(&sql, params![row, start, length])
            .await?
            .next()
            .await?
            .context("migration input row is absent")?
            .get(0)?;
        Ok(value)
    }

    // Called by the root supervisor after tasks/callbacks drain and before the
    // writer settles. The mutex also prevents cleanup racing an input callback.
    pub(crate) async fn close(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        // Even a failed or cancelled rollback must revoke the read capability;
        // the supervisor retains the connection in quarantine in that case.
        *state = InputState::Closed;
        if !self.conn.is_autocommit() {
            self.conn.execute("ROLLBACK", ()).await?;
        }
        ensure!(
            self.conn.is_autocommit(),
            "migration input cleanup left a transaction"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use bitcoin::{Network, hashes::Hash};
    use futures_util::poll;
    use libsql::{AuthAction, Authorization};
    use tempfile::TempDir;

    use super::*;
    use crate::database::connection::new_connection;
    use crate::protocol::coordinator::linked::{begin_unit, link_runtime};
    use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
    use crate::protocol::identity::ChainId;
    use crate::runtime::ownership::OwnerService;
    use crate::runtime::pool::LinkedSession;
    use crate::runtime::{ComponentCache, Runtime, Storage};

    async fn fixture() -> Result<(TempDir, Connection, ApplicationCursor, BlockHash)> {
        let dir = TempDir::new()?;
        let conn = new_connection(dir.path(), "input.db").await?;
        conn.execute("BEGIN", ()).await?;
        canonical_history::bind_genesis(&conn, ChainId([1; 32])).await?;
        conn.execute("COMMIT", ()).await?;
        let HistoryState::Ready(cursor) = canonical_history::state(&conn).await? else {
            unreachable!()
        };
        let hash = BlockHash::from_byte_array([2; 32]);
        conn.execute(
            "INSERT INTO blocks (height, hash, relevant) VALUES (1, ?1, 1)",
            [hash.to_string()],
        )
        .await?;
        for key in [b"b", b"d"] {
            write(&conn, key, b"original", false).await?;
        }
        Ok((dir, conn, cursor, hash))
    }

    async fn write(conn: &Connection, key: &[u8], value: &[u8], deleted: bool) -> Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO contract_state
            (contract_id, height, path, value, size, deleted) VALUES (1, 1, ?1, ?2, ?3, ?4)",
            params![key, value, (key.len() + value.len()) as u64, deleted],
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn migration_input_cancelled_waiters_and_held_rows_cannot_outlive_cleanup() -> Result<()>
    {
        let (_dir, writer, cursor, hash) = fixture().await?;
        let input = MigrationInput::open(&writer).await?;
        input.claim()?;
        writer.execute("BEGIN IMMEDIATE", ()).await?;
        let held = input.state.lock().await;
        let mut pin = Box::pin(input.pin(cursor, 1, hash));
        assert!(poll!(&mut pin).is_pending());
        drop(pin);
        drop(held);
        assert!(input.conn.is_autocommit());
        input.pin(cursor, 1, hash).await?;
        let (point, _, chunk) = input.callbacks();
        let row = point(1, b"b".to_vec()).await.map_err(Error::msg)?.unwrap();
        let held = input.state.lock().await;
        let mut bytes = chunk(row.0.clone(), false, 0, 8);
        assert!(poll!(&mut bytes).is_pending());
        drop(bytes);
        let mut close = Box::pin(input.close());
        assert!(
            poll!(&mut close).is_pending(),
            "cleanup bypassed an input lock"
        );
        drop(held);
        close.await?;
        assert!(input.conn.is_autocommit());
        assert!(chunk(row.0, false, 0, 8).await.is_err());
        assert!(input.pin(cursor, 1, hash).await.is_err());
        writer.execute("ROLLBACK", ()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn migration_input_cleanup_failure_revokes_capability_and_quarantines_writer()
    -> Result<()> {
        let (dir, writer, cursor, hash) = fixture().await?;
        let input = MigrationInput::open(&writer).await?;
        let mut runtime = Runtime::new(
            ComponentCache::new(),
            Storage::builder().height(1).conn(writer.clone()).build(),
        )
        .await?;
        runtime.network = Network::Regtest;
        let session = LinkedSession::new(writer.clone(), link_runtime(runtime, true));
        let service = OwnerService::new();
        let selection = select_legacy_p1(
            &writer,
            Network::Regtest,
            ApplicationPosition::Migration {
                anchor_height: 1,
                anchor_hash: hash,
            },
        )
        .await?;
        let mut lease = service
            .begin_linked_migration_reserved(
                &session,
                service.reserve_root_capacity().await?,
                selection.clone(),
                input.clone(),
            )
            .await?;
        begin_unit(&session, &selection, Network::Regtest).await?;
        input.pin(cursor, 1, hash).await?;
        write(&writer, b"b", b"uncommitted", false).await?;
        // Deny the actual SQLite ROLLBACK rather than fabricating a supervisor
        // error, exercising the input cleanup failure path end to end.
        input.conn.authorizer(Some(Arc::new(|context| {
            if matches!(context.action, AuthAction::Transaction { .. }) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        })))?;
        assert!(lease.drain().await.is_err());
        assert!(lease.settle(true).await.is_err());
        assert!(service.is_fatal());
        assert_eq!(service.quarantined_roots().await, 1);
        assert!(!writer.is_autocommit());
        assert!(!input.conn.is_autocommit());
        assert!(input.point(1, b"b").await.is_err());
        assert!(service.reserve_root_capacity().await.is_err());
        let reader = Builder::new_local(dir.path().join("input.db"))
            .build()
            .await?
            .connect()?;
        let value: Vec<u8> = reader
            .query(
                "SELECT value FROM contract_state WHERE path = ?1",
                [b"b".as_slice()],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert_eq!(value, b"original");
        service.shutdown();
        Ok(())
    }

    #[tokio::test]
    async fn input_capabilities_reject_other_databases_roots_and_closed_snapshots() -> Result<()> {
        let (_first_dir, first, cursor, hash) = fixture().await?;
        let (_second_dir, second, same_cursor, same_hash) = fixture().await?;
        assert_eq!((cursor, hash), (same_cursor, same_hash));
        let input = MigrationInput::open(&first).await?;
        input.verify_writer(&first).await?;
        assert!(input.verify_writer(&second).await.is_err());
        let other = MigrationInput::open(&first).await?;
        input.claim()?;
        other.claim()?;
        first.execute("BEGIN IMMEDIATE", ()).await?;
        input.pin(cursor, 1, hash).await?;
        other.pin(cursor, 1, hash).await?;
        let callbacks = input.callbacks();
        let row = callbacks.0(1, b"b".to_vec())
            .await
            .map_err(Error::msg)?
            .unwrap();
        assert_eq!(
            callbacks.2(row.0.clone(), false, 0, 8).await.unwrap(),
            b"original"
        );
        assert!(
            other.callbacks().2(row.0.clone(), false, 0, 0)
                .await
                .is_err()
        );
        assert!(callbacks.2(row.0.clone(), false, 8, 1).await.is_err());
        assert!(
            callbacks.2(row.0.clone(), false, u64::MAX, 1)
                .await
                .is_err()
        );
        input.close().await?;
        assert!(callbacks.2(row.0.clone(), false, 0, 0).await.is_err());
        other.close().await?;
        first.execute("ROLLBACK", ()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_survives_same_height_replacement_and_late_first_scan() -> Result<()> {
        let (_dir, writer, cursor, hash) = fixture().await?;
        let input = MigrationInput::open(&writer).await?;
        input.claim()?;
        writer.execute("BEGIN IMMEDIATE", ()).await?;
        input.pin(cursor, 1, hash).await?;
        let visited = input.point(1, b"b").await?.unwrap();
        write(&writer, b"b", b"changed", false).await?;
        write(&writer, b"d", b"", true).await?;
        writer
            .execute(
                "DELETE FROM contract_state WHERE path = ?1",
                [b"d".as_slice()],
            )
            .await?;
        write(&writer, b"d", b"reinserted", false).await?;
        write(&writer, b"a", b"before", false).await?;
        write(&writer, b"z", b"after", false).await?;
        assert_eq!(input.chunk(visited.row, false, 0, 8).await?, b"original");
        assert_eq!(input.next(1, None).await?, Some(visited.clone()));
        let unvisited = input.next(1, Some(b"b")).await?.unwrap();
        assert_eq!(input.chunk(unvisited.row, true, 0, 1).await?, b"d");
        assert_eq!(input.chunk(unvisited.row, false, 0, 8).await?, b"original");
        assert!(input.next(1, Some(b"d")).await?.is_none());
        assert!(input.point(1, b"a").await?.is_none());
        assert!(
            input
                .chunk(visited.row, false, 0, INPUT_CHUNK_BYTES + 1)
                .await
                .is_err()
        );
        assert!(input.chunk(visited.row, false, u64::MAX, 1).await.is_err());
        input.close().await?;
        assert!(!writer.is_autocommit());
        assert!(input.point(1, b"b").await.is_err());
        assert!(input.pin(cursor, 1, hash).await.is_err());
        writer.execute("COMMIT", ()).await?;
        let current: Vec<u8> = writer
            .query(
                "SELECT value FROM contract_state WHERE path = ?1",
                [b"b".as_slice()],
            )
            .await?
            .next()
            .await?
            .unwrap()
            .get(0)?;
        assert_eq!(current, b"changed");
        Ok(())
    }

    #[tokio::test]
    async fn pin_rejects_wrong_lineage_anchor_and_unowned_or_uncommitted_entry() -> Result<()> {
        let (_dir, writer, cursor, hash) = fixture().await?;
        writer.execute("BEGIN", ()).await?;
        assert!(MigrationInput::open(&writer).await.is_err());
        writer.execute("ROLLBACK", ()).await?;
        for wrong_anchor in [false, true] {
            let input = MigrationInput::open(&writer).await?;
            assert!(input.pin(cursor, 1, hash).await.is_err());
            input.claim()?;
            assert!(input.claim().is_err());
            writer.execute("BEGIN IMMEDIATE", ()).await?;
            let mut expected = cursor;
            if !wrong_anchor {
                expected.lineage = [7; 32];
            }
            let anchor = if wrong_anchor {
                BlockHash::from_byte_array([9; 32])
            } else {
                hash
            };
            assert!(input.pin(expected, 1, anchor).await.is_err());
            assert!(input.point(1, b"b").await.is_err());
            input.close().await?;
            assert!(input.conn.is_autocommit());
            writer.execute("ROLLBACK", ()).await?;
        }
        Ok(())
    }
}
