use anyhow::{Context, Result, ensure};
use libsql::{Connection, params};

use super::{fixed, replay_input};
use crate::protocol::coordinator::application_closure::WorkItem;
use crate::protocol::coordinator::closure_work::{
    WorkCursor, WorkOrigin, decode_item, item_bytes, item_digest, plan_id,
};

pub(crate) const PAGE_ITEMS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Draft {
    pub(crate) origin: WorkOrigin,
    pub(crate) count: u64,
    pub(crate) digest: [u8; 32],
    published: Option<[u8; 32]>,
}

impl Draft {
    pub(crate) fn cursor(self) -> Result<WorkCursor> {
        let id = self.published.context("work plan is unpublished")?;
        ensure!(
            id == plan_id(self.origin, self.count, self.digest)?,
            "work plan identity differs"
        );
        Ok(WorkCursor {
            plan: id,
            index: 0,
            count: self.count,
            prefix: self.origin.key()?,
        })
    }
}

async fn load(conn: &Connection, key: [u8; 32]) -> Result<Draft> {
    let row = conn.query("SELECT height, origin, item_count, digest, plan_id FROM closure_work_plans WHERE plan_key = ?1",
        [key.to_vec()]).await?.next().await?.context("work plan unavailable")?;
    let origin = WorkOrigin::decode(&row.get::<Vec<u8>>(1)?)?;
    ensure!(
        origin.key()? == key && origin.height == u64::from_be_bytes(fixed(row.get(0)?)?),
        "work origin binding differs"
    );
    let draft = Draft {
        origin,
        count: u64::from_be_bytes(fixed(row.get(2)?)?),
        digest: fixed(row.get(3)?)?,
        published: row.get::<Option<Vec<u8>>>(4)?.map(fixed).transpose()?,
    };
    if draft.published.is_some() {
        draft.cursor()?;
    }
    Ok(draft)
}

pub(crate) async fn published(conn: &Connection, id: [u8; 32]) -> Result<Draft> {
    let row = conn
        .query(
            "SELECT plan_key FROM closure_work_plans WHERE plan_id = ?1",
            [id.to_vec()],
        )
        .await?
        .next()
        .await?
        .context("published work plan unavailable")?;
    let draft = load(conn, fixed(row.get(0)?)?).await?;
    ensure!(draft.published == Some(id), "published work plan differs");
    Ok(draft)
}

pub(crate) async fn for_origin(conn: &Connection, origin: WorkOrigin) -> Result<Draft> {
    let draft = load(conn, origin.key()?).await?;
    ensure!(draft.origin == origin, "work origin differs");
    Ok(draft)
}

pub(crate) async fn begin(conn: &Connection, origin: WorkOrigin) -> Result<Draft> {
    ensure!(
        !conn.is_autocommit(),
        "work plan creation requires transaction"
    );
    let row = conn
        .query(
            "SELECT plan_id FROM closure_plans WHERE height = ?1",
            [origin.height.to_be_bytes().to_vec()],
        )
        .await?
        .next()
        .await?
        .context("work plan lacks closure")?;
    ensure!(
        fixed::<32>(row.get(0)?)? == origin.closure,
        "work plan belongs to another closure"
    );
    let key = origin.key()?;
    conn.execute("INSERT OR IGNORE INTO closure_work_plans (plan_key, height, origin, item_count, digest) VALUES (?1, ?2, ?3, ?4, ?1)",
        params![key.to_vec(), origin.height.to_be_bytes().to_vec(), origin.encode()?, 0u64.to_be_bytes().to_vec()]).await?;
    for_origin(conn, origin).await
}

async fn validate_item(conn: &Connection, origin: WorkOrigin, item: WorkItem) -> Result<()> {
    if let WorkItem::Execute { decision } | WorkItem::Replay { decision, .. } = item {
        ensure!(
            decision > 0 && decision <= origin.height,
            "work refers to future decision"
        );
        ensure!(
            conn.query(
                "SELECT 1 FROM certified_decisions WHERE height = ?1",
                [decision.to_be_bytes().to_vec()]
            )
            .await?
            .next()
            .await?
            .is_some(),
            "work lacks retained certified decision"
        );
    }
    if let WorkItem::Replay { decision, input } = item {
        replay_input::get(conn, input, origin, decision).await?;
    }
    Ok(())
}

// The caller commits bounded pages. Unpublished rows never authorize execution.
pub(crate) async fn append(
    conn: &Connection,
    expected: Draft,
    items: &[WorkItem],
) -> Result<Draft> {
    ensure!(!conn.is_autocommit(), "work append requires transaction");
    ensure!(items.len() <= PAGE_ITEMS, "work append exceeds page size");
    let key = expected.origin.key()?;
    let mut draft = load(conn, key).await?;
    ensure!(
        draft == expected && draft.published.is_none(),
        "work draft is stale or published"
    );
    for &item in items {
        validate_item(conn, draft.origin, item).await?;
        let digest = item_digest(draft.digest, draft.count, item)?;
        conn.execute("INSERT INTO closure_work_items (plan_key, ordinal, item, previous, digest) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![key.to_vec(), draft.count.to_be_bytes().to_vec(), item_bytes(item)?, draft.digest.to_vec(), digest.to_vec()]).await?;
        draft.count = draft.count.checked_add(1).context("work count exhausted")?;
        draft.digest = digest;
    }
    conn.execute("UPDATE closure_work_plans SET item_count = ?2, digest = ?3 WHERE plan_key = ?1 AND plan_id IS NULL",
        params![key.to_vec(), draft.count.to_be_bytes().to_vec(), draft.digest.to_vec()]).await?;
    Ok(draft)
}

pub(crate) async fn verify(conn: &Connection, draft: Draft) -> Result<()> {
    let mut rows = conn.query("SELECT ordinal, item, previous, digest FROM closure_work_items WHERE plan_key = ?1 ORDER BY ordinal",
        [draft.origin.key()?.to_vec()]).await?;
    let mut count = 0u64;
    let mut digest = draft.origin.key()?;
    while let Some(row) = rows.next().await? {
        ensure!(
            u64::from_be_bytes(fixed(row.get(0)?)?) == count && fixed::<32>(row.get(2)?)? == digest,
            "work plan has a gap or changed prefix"
        );
        let item = decode_item(&row.get::<Vec<u8>>(1)?)?;
        validate_item(conn, draft.origin, item).await?;
        digest = item_digest(digest, count, item)?;
        ensure!(
            fixed::<32>(row.get(3)?)? == digest,
            "work item digest differs"
        );
        count = count.checked_add(1).context("work count exhausted")?;
    }
    ensure!(
        count == draft.count && digest == draft.digest,
        "work plan count or digest differs"
    );
    Ok(())
}

pub(crate) async fn publish(conn: &Connection, expected: Draft) -> Result<WorkCursor> {
    ensure!(
        !conn.is_autocommit(),
        "work publication requires transaction"
    );
    let mut draft = load(conn, expected.origin.key()?).await?;
    ensure!(draft == expected, "work draft changed before publication");
    verify(conn, draft).await?;
    if draft.published.is_none() {
        let id = plan_id(draft.origin, draft.count, draft.digest)?;
        conn.execute(
            "UPDATE closure_work_plans SET plan_id = ?2 WHERE plan_key = ?1 AND plan_id IS NULL",
            params![draft.origin.key()?.to_vec(), id.to_vec()],
        )
        .await?;
        draft.published = Some(id);
    }
    draft.cursor()
}

// Each stage reads one indexed item. The cursor binds the already-consumed prefix;
// recovery verifies the complete plan once before resuming its unfinished suffix.
pub(crate) async fn next(
    conn: &Connection,
    cursor: WorkCursor,
) -> Result<Option<(WorkItem, WorkCursor)>> {
    let plan = published(conn, cursor.plan).await?;
    ensure!(
        cursor.count == plan.count && cursor.index <= cursor.count,
        "work cursor bounds differ"
    );
    if cursor.index == 0 {
        ensure!(
            cursor.prefix == plan.origin.key()?,
            "work cursor initial prefix differs"
        );
    }
    if cursor.is_empty() {
        ensure!(
            cursor.prefix == plan.digest,
            "completed work prefix differs"
        );
        return Ok(None);
    }
    let row = conn.query("SELECT item, previous, digest FROM closure_work_items WHERE plan_key = ?1 AND ordinal = ?2",
        params![plan.origin.key()?.to_vec(), cursor.index.to_be_bytes().to_vec()]).await?.next().await?.context("next work item missing")?;
    ensure!(
        fixed::<32>(row.get(1)?)? == cursor.prefix,
        "next work prefix differs"
    );
    let item = decode_item(&row.get::<Vec<u8>>(0)?)?;
    let digest = item_digest(cursor.prefix, cursor.index, item)?;
    ensure!(
        fixed::<32>(row.get(2)?)? == digest,
        "next work item differs"
    );
    let next = WorkCursor {
        index: cursor.index + 1,
        prefix: digest,
        ..cursor
    };
    if next.is_empty() {
        ensure!(next.prefix == plan.digest, "final work digest differs");
    }
    Ok(Some((item, next)))
}

#[cfg(feature = "protocol-qualification")]
pub(crate) async fn qualify(
    conn: &Connection,
    reopened: &Connection,
    mut origin: WorkOrigin,
) -> Result<WorkCursor> {
    // A distinct origin keeps this deliberately synthetic work out of the live
    // closure. Admission must reject it even though its rows are well formed.
    origin.previous = [91; 32];
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    let mut draft = begin(conn, origin).await?;
    let empty = draft;
    ensure!(draft.cursor().is_err());
    ensure!(
        append(conn, draft, &vec![WorkItem::Observe; PAGE_ITEMS + 1])
            .await
            .is_err()
    );
    draft = append(conn, draft, &vec![WorkItem::Observe; PAGE_ITEMS]).await?;
    ensure!(append(conn, empty, &[WorkItem::Observe]).await.is_err());
    conn.execute_batch("COMMIT").await?;
    ensure!(for_origin(reopened, origin).await? == draft);
    ensure!(draft.cursor().is_err());

    conn.execute_batch("BEGIN IMMEDIATE").await?;
    append(conn, draft, &[WorkItem::Finality]).await?;
    conn.execute_batch("ROLLBACK").await?;
    ensure!(for_origin(reopened, origin).await? == draft);
    for _ in 0..3 {
        conn.execute_batch("BEGIN IMMEDIATE").await?;
        draft = append(conn, draft, &vec![WorkItem::Observe; PAGE_ITEMS]).await?;
        conn.execute_batch("COMMIT").await?;
    }
    let key = origin.key()?;
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    conn.execute(
        "DELETE FROM closure_work_items WHERE plan_key = ?1 AND ordinal = ?2",
        params![key.to_vec(), 200u64.to_be_bytes().to_vec()],
    )
    .await?;
    ensure!(publish(conn, draft).await.is_err());
    conn.execute_batch("ROLLBACK").await?;
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    conn.execute(
        "UPDATE closure_work_items SET item = ?3 WHERE plan_key = ?1 AND ordinal = ?2",
        params![
            key.to_vec(),
            200u64.to_be_bytes().to_vec(),
            item_bytes(WorkItem::Finality)?
        ],
    )
    .await?;
    ensure!(publish(conn, draft).await.is_err());
    conn.execute_batch("ROLLBACK").await?;
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    let cursor = publish(conn, draft).await?;
    conn.execute_batch("COMMIT").await?;
    let published = for_origin(reopened, origin).await?;
    verify(reopened, published).await?;
    ensure!(published.cursor()? == cursor);
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    ensure!(append(conn, published, &[WorkItem::Observe]).await.is_err());
    conn.execute_batch("ROLLBACK").await?;
    let mut forged = cursor;
    forged.prefix = [90; 32];
    ensure!(next(conn, forged).await.is_err());
    forged = cursor;
    forged.count += 1;
    ensure!(next(conn, forged).await.is_err());
    let mut walk = cursor;
    let mut consumed = 0;
    while let Some((item, after)) = next(reopened, walk).await? {
        ensure!(item == WorkItem::Observe && after.index == walk.index + 1);
        walk = after;
        consumed += 1;
    }
    ensure!(consumed == 512 && walk.is_empty());
    let row = conn.query("SELECT COUNT(*), SUM(length(item) + length(previous) + length(digest) + length(ordinal)) FROM closure_work_items WHERE plan_key = ?1", [key.to_vec()])
        .await?.next().await?.context("work storage aggregate absent")?;
    ensure!(row.get::<i64>(0)? == 512 && row.get::<i64>(1)? == 512 * 73);
    Ok(cursor)
}
