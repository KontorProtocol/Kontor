use super::{Error, StorageRowCursor, live_paths_scan, scan_bounds, traversal_probe};
use crate::database::connection::new_connection;
use crate::test_utils::test_runtime;
use anyhow::{Context, Result as AnyResult, ensure};
use libsql::{Connection, Rows, Value, params};
use std::{hint::black_box, mem::take, time::Instant};
use stdlib::{KeyElement, next_element};

async fn load(conn: &Connection) -> AnyResult<()> {
    conn.load_extension_enable()?;
    conn.load_extension(
        std::env::var("KONTOR_BLOB_EXTENSION")?,
        Some("sqlite3_kontorblob_init"),
    )?;
    conn.load_extension_disable()?;
    Ok(())
}

async fn stat(conn: &Connection, index: i64) -> AnyResult<i64> {
    Ok(conn
        .query("SELECT kontor_blob_stats(?)", [index])
        .await?
        .next()
        .await?
        .context("missing counter")?
        .get(0)?)
}

async fn session(conn: &Connection) -> AnyResult<(Rows, i64)> {
    let mut rows = conn
        .query("SELECT id FROM kontor_blob_sessions", ())
        .await?;
    let id = rows.next().await?.context("missing session")?.get(0)?;
    Ok((rows, id))
}

struct ExtensionCursor {
    scan: StorageRowCursor,
    session: Option<Rows>,
    session_id: i64,
    reuse: bool,
}

impl ExtensionCursor {
    fn new(conn: &Connection, root: Vec<u8>, reverse: bool, reuse: bool) -> Self {
        Self {
            scan: StorageRowCursor::new(conn, 1, root, None, None, reverse),
            session: None,
            session_id: 0,
            reuse,
        }
    }
    async fn next(&mut self, budget: u64) -> AnyResult<Option<(Vec<u8>, Vec<u8>)>> {
        if self.scan.finished {
            return Ok(None);
        }
        let result = self.read_next(budget).await;
        if !matches!(result, Ok(Some(_))) {
            self.scan.finished = true;
            self.scan.rows = None;
            self.scan.values.query = None;
            self.session = None;
        }
        result
    }
    async fn read_next(&mut self, budget: u64) -> AnyResult<Option<(Vec<u8>, Vec<u8>)>> {
        let mut rows = match self.scan.rows.take() {
            Some(rows) => rows,
            None => {
                self.scan
                    .values
                    .conn
                    .query(&self.scan.sql, take(&mut self.scan.params))
                    .await?
            }
        };
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let key_bytes: u64 = row.get(0)?;
        let size: u64 = row.get(1)?;
        if key_bytes > budget || size > budget - key_bytes {
            return Err(Error::ValueTooLarge.into());
        }
        let full: Vec<u8> = row.get(2)?;
        let (elem, tail) = next_element(&full[self.scan.prefix_len..]).map_err(Error::KeyCodec)?;
        if !tail.is_empty() {
            return Err(Error::NonScalarRow.into());
        }
        let rowid: i64 = row.get(3)?;
        if self.reuse && self.session.is_none() {
            let (rows, id) = session(&self.scan.values.conn).await?;
            self.session = Some(rows);
            self.session_id = id;
        }
        let mut statement = match self.scan.values.query.take() {
            Some(statement) => statement,
            None => {
                self.scan
                    .values
                    .conn
                    .prepare("SELECT kontor_blob_read(?, ?, ?, ?)")
                    .await?
            }
        };
        let value: Vec<u8> = statement
            .query_row(params![
                rowid,
                i64::try_from(size)?,
                (budget - key_bytes).min(i64::MAX as u64) as i64,
                self.session_id
            ])
            .await?
            .get(0)?;
        statement.reset();
        self.scan.values.query = Some(statement);
        self.scan.rows = Some(rows);
        Ok(Some((elem.to_vec(), value)))
    }
}

async fn scan(
    conn: &Connection,
    root: Vec<u8>,
    reverse: bool,
    budget: u64,
    mode: usize,
) -> AnyResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut output = Vec::new();
    if mode == 0 {
        let mut cursor = StorageRowCursor::new(conn, 1, root, None, None, reverse);
        while let Some(row) = cursor.next(budget).await? {
            output.push(row);
        }
    } else if mode == 1 {
        let mut cursor = StreamingRowCursor::new(conn, 1, root, None, None, reverse);
        while let Some(row) = cursor.next(budget).await? {
            output.push(row);
        }
    } else {
        let mut cursor = ExtensionCursor::new(conn, root, reverse, mode == 3);
        while let Some(row) = cursor.next(budget).await? {
            output.push(row);
        }
    }
    Ok(output)
}

#[tokio::test]
#[ignore]
async fn compare_extension() -> AnyResult<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    load(&runtime.storage.conn).await?;
    for size in [0usize, 8, 128, 4096, 65536, 1048576] {
        let count = if size >= 1048576 { 32 } else { 256 };
        let root = format!("blob-bench-{size}").encode();
        let mut expected = Vec::new();
        for i in 0..count as u64 {
            let mut path = root.clone();
            path.extend(i.encode());
            let value = vec![i as u8; size];
            runtime.storage.set(1, &path, &value, None, None).await?;
            expected.push((i.encode(), value));
        }
        for reverse in [false, true] {
            let mut times: [Vec<u128>; 4] = Default::default();
            if reverse {
                expected.reverse();
            }
            for trial in 0..29 {
                // Rotate and reverse ordering to distribute cache/frequency effects.
                let order = if trial % 2 == 0 {
                    [0, 1, 2, 3]
                } else {
                    [3, 2, 1, 0]
                };
                for offset in 0..4 {
                    let mode = order[(offset + trial) % 4];
                    let start = Instant::now();
                    let rows =
                        scan(&runtime.storage.conn, root.clone(), reverse, u64::MAX, mode).await?;
                    let elapsed = start.elapsed().as_nanos();
                    ensure!(rows == expected, "mode {mode} returned different data");
                    black_box(rows);
                    if trial >= 5 {
                        times[mode].push(elapsed);
                    }
                }
            }
            times.iter_mut().for_each(|times| times.sort_unstable());
            eprintln!(
                "extension size={size} rows={count} reverse={reverse} sql={}ns copy_guard={}ns open_close={}ns reuse={}ns reuse_vs_sql={:.3} reuse_vs_copy={:.3}",
                times[0][12],
                times[1][12],
                times[2][12],
                times[3][12],
                times[3][12] as f64 / times[0][12] as f64,
                times[3][12] as f64 / times[1][12] as f64
            );
        }
    }
    for size in [4096usize, 4194304] {
        let root = format!("blob-reject-{size}").encode();
        let mut path = root.clone();
        path.extend(0u64.encode());
        runtime
            .storage
            .set(1, &path, &vec![3; size], None, None)
            .await?;
        let mut times: [Vec<u128>; 4] = Default::default();
        for trial in 0..29 {
            for mode in (0..4).map(|offset| (offset + trial) % 4) {
                let start = Instant::now();
                let result = scan(&runtime.storage.conn, root.clone(), false, 16, mode).await;
                let elapsed = start.elapsed().as_nanos();
                ensure!(matches!(
                    result.unwrap_err().downcast_ref::<Error>(),
                    Some(Error::ValueTooLarge)
                ));
                if trial >= 5 {
                    times[mode].push(elapsed);
                }
            }
        }
        times.iter_mut().for_each(|times| times.sort_unstable());
        eprintln!(
            "extension_reject size={size} sql={}ns copy_guard={}ns open_close={}ns reuse={}ns",
            times[0][12], times[1][12], times[2][12], times[3][12]
        );
    }
    Ok(())
}
/// A streaming row cursor whose values are copied only after checking the
/// current byte budget. SQLite may still read the value internally while stepping.
pub struct StreamingRowCursor {
    conn: Connection,
    prefix_len: usize,
    sql: String,
    params: Vec<(String, Value)>,
    rows: Option<Rows>,
    finished: bool,
}

impl StreamingRowCursor {
    pub fn new(
        conn: &Connection,
        contract_id: u64,
        path: Vec<u8>,
        lo: Option<Vec<u8>>,
        hi: Option<Vec<u8>>,
        descending: bool,
    ) -> Self {
        let (lo, lo_cmp, hi) = scan_bounds(&path, lo, hi);
        let (sql, mut params) = live_paths_scan(
            "length(cs.path) - :prefix_len, cs.size, cs.path, cs.value",
            lo_cmp,
            contract_id,
            lo,
            hi,
            Some(if descending {
                "cs.path DESC"
            } else {
                "cs.path"
            }),
            None,
        );
        params.push((":prefix_len".into(), Value::Integer(path.len() as i64)));
        Self {
            conn: conn.clone(),
            prefix_len: path.len(),
            sql,
            params,
            rows: None,
            finished: false,
        }
    }

    pub async fn next(&mut self, max_bytes: u64) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
        if self.finished {
            return Ok(None);
        }
        let result = self.read_next(max_bytes).await;
        if !matches!(result, Ok(Some(_))) {
            self.finished = true;
            self.rows = None;
        }
        result
    }

    async fn read_next(&mut self, max_bytes: u64) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
        let mut rows = match self.rows.take() {
            Some(rows) => rows,
            None => {
                self.conn
                    .query(&self.sql, std::mem::take(&mut self.params))
                    .await?
            }
        };
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let key_bytes: u64 = row.get(0)?;
        let size: u64 = row.get(1)?;
        if key_bytes > max_bytes || size > max_bytes - key_bytes {
            return Err(Error::ValueTooLarge);
        }
        let full: Vec<u8> = row.get(2)?;
        let (elem, tail) = next_element(&full[self.prefix_len..]).map_err(Error::KeyCodec)?;
        if !tail.is_empty() {
            return Err(Error::NonScalarRow);
        }
        let value = row.get::<Vec<u8>>(3)?;
        #[cfg(test)]
        traversal_probe::copied_value(value.len());
        let member = elem.to_vec();
        self.rows = Some(rows);
        Ok(Some((member, value)))
    }
}

async fn rowid(conn: &Connection, path: &[u8]) -> AnyResult<i64> {
    let mut rows = conn.query("SELECT rowid FROM contract_state WHERE contract_id = 1 AND path = ? ORDER BY height DESC LIMIT 1", [path.to_vec()]).await?;
    Ok(rows.next().await?.context("missing row")?.get(0)?)
}

async fn read(
    conn: &Connection,
    id: i64,
    size: i64,
    budget: i64,
    session: i64,
) -> AnyResult<Vec<u8>> {
    Ok(conn
        .query(
            "SELECT kontor_blob_read(?, ?, ?, ?)",
            params![id, size, budget, session],
        )
        .await?
        .next()
        .await?
        .context("missing BLOB")?
        .get(0)?)
}

#[tokio::test]
#[ignore]
async fn extension_lifetimes_and_budgets() -> AnyResult<()> {
    let (runtime, dir, name) = test_runtime().await?;
    let conn = &runtime.storage.conn;
    load(conn).await?;
    let root = "extension-life".to_string().encode();
    let mut a = root.clone();
    a.extend(0u64.encode());
    let mut b = root.clone();
    b.extend(1u64.encode());
    runtime.storage.set(1, &a, &[1; 4], None, None).await?;
    runtime.storage.set(1, &b, &[2; 8], None, None).await?;
    let id_a = rowid(conn, &a).await?;
    let id_b = rowid(conn, &b).await?;

    for reuse in [false, true] {
        let before = stat(conn, 0).await?;
        let mut cursor = ExtensionCursor::new(conn, root.clone(), false, reuse);
        ensure!(cursor.next(1).await.is_err());
        ensure!(
            stat(conn, 0).await? == before,
            "overbudget row must not open BLOB"
        );
        ensure!(stat(conn, 4).await? == 0);
        ensure!(cursor.next(u64::MAX).await?.is_none());

        let mut cursor = ExtensionCursor::new(conn, root.clone(), false, reuse);
        ensure!(
            cursor
                .next(4 + 0u64.encode().len() as u64)
                .await?
                .unwrap()
                .1
                == vec![1; 4]
        );
        let reads = stat(conn, 2).await?;
        ensure!(cursor.next(7 + 1u64.encode().len() as u64).await.is_err());
        ensure!(
            stat(conn, 2).await? == reads,
            "shrinking budget must stop before read"
        );
        ensure!(
            stat(conn, 4).await? == 0,
            "budget failure must close retained BLOB"
        );

        let mut cursor = ExtensionCursor::new(conn, root.clone(), false, reuse);
        cursor.next(u64::MAX).await?;
        drop(cursor);
        ensure!(stat(conn, 4).await? == 0, "abandoning scan must close BLOB");
    }

    let (mut owner, sid) = session(conn).await?;
    let (other_owner, other_sid) = session(conn).await?;
    ensure!(read(conn, id_a, 4, 4, sid).await? == vec![1; 4]);
    ensure!(read(conn, id_b, 8, 8, other_sid).await? == vec![2; 8]);
    ensure!(stat(conn, 4).await? == 2);
    drop(other_owner);
    ensure!(stat(conn, 4).await? == 1);
    ensure!(read(conn, id_a, 4, 4, other_sid).await.is_err());

    let opens = stat(conn, 0).await?;
    let reopens = stat(conn, 1).await?;
    ensure!(read(conn, id_b, 8, 7, sid).await.is_err());
    ensure!(stat(conn, 0).await? == opens && stat(conn, 1).await? == reopens);
    ensure!(stat(conn, 4).await? == 0);
    ensure!(read(conn, id_a, 4, 4, sid).await? == vec![1; 4]);
    ensure!(read(conn, i64::MAX, 4, 4, sid).await.is_err());
    ensure!(stat(conn, 4).await? == 0);
    ensure!(read(conn, id_b, 8, 8, sid).await? == vec![2; 8]);
    let reads = stat(conn, 2).await?;
    ensure!(read(conn, id_b, 7, 7, sid).await.is_err());
    ensure!(
        stat(conn, 2).await? == reads,
        "size mismatch must not copy bytes"
    );
    ensure!(stat(conn, 4).await? == 0);
    read(conn, id_a, 4, 4, sid).await?;
    ensure!(owner.next().await?.is_none());
    ensure!(stat(conn, 4).await? == 0, "session EOF must close BLOB");
    drop(owner);

    let (owner, sid) = session(conn).await?;
    runtime.storage.savepoint().await?;
    runtime.storage.set(1, &a, &[3; 16], None, None).await?;
    ensure!(read(conn, rowid(conn, &a).await?, 16, 16, sid).await? == vec![3; 16]);
    runtime.storage.rollback().await?;
    ensure!(read(conn, rowid(conn, &a).await?, 4, 4, sid).await? == vec![1; 4]);
    runtime.storage.set(1, &a, &[4; 32], None, None).await?;
    ensure!(read(conn, id_b, 8, 8, sid).await? == vec![2; 8]);
    drop(owner);
    ensure!(stat(conn, 4).await? == 0);

    let view = new_connection(dir.path(), &name).await?;
    load(&view).await?;
    let (owner, sid) = session(&view).await?;
    ensure!(read(&view, rowid(&view, &a).await?, 32, 32, sid).await? == vec![4; 32]);
    runtime.storage.set(1, &b, &[5; 64], None, None).await?;
    ensure!(
        read(&view, rowid(&view, &b).await?, 8, 8, sid).await? == vec![2; 8],
        "session must retain its snapshot"
    );
    drop(owner);
    ensure!(stat(&view, 4).await? == 0);
    ensure!(
        read(&view, rowid(&view, &b).await?, 64, 64, 0).await? == vec![5; 64],
        "drop must release old snapshot"
    );

    let mut cursor = ExtensionCursor::new(&view, root.clone(), false, true);
    ensure!(cursor.next(u64::MAX).await?.unwrap().1 == vec![4; 32]);
    runtime.storage.set(1, &b, &[6; 128], None, None).await?;
    ensure!(
        cursor.next(u64::MAX).await?.unwrap().1 == vec![5; 64],
        "BLOB and metadata must share snapshot"
    );
    ensure!(cursor.next(u64::MAX).await?.is_none());
    ensure!(stat(&view, 4).await? == 0);
    let mut cursor = ExtensionCursor::new(&view, root, false, true);
    cursor.next(u64::MAX).await?;
    ensure!(cursor.next(u64::MAX).await?.unwrap().1 == vec![6; 128]);
    drop(cursor);
    ensure!(stat(&view, 4).await? == 0);
    eprintln!(
        "extension budgets, abandonment, EOF, overlapping sessions, error recovery, writes, rollback, and snapshots passed"
    );
    Ok(())
}
