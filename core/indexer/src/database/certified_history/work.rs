use anyhow::{Context, Result, ensure};
use libsql::{Connection, params};

use super::closure::Progress;
use super::{closure, finality, fixed, reconcile, replay_input};
use crate::protocol::coordinator::application_closure::{ClosurePlan, WorkItem};
use crate::protocol::coordinator::closure_work::{
    WorkCursor, WorkOrigin, decode_item, item_bytes, item_digest, plan_id,
};

pub(crate) const PAGE_ITEMS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StoredPlan {
    origin: WorkOrigin,
    count: u64,
    digest: [u8; 32],
    published: Option<[u8; 32]>,
    verdict: Option<[u8; 32]>,
}

impl StoredPlan {
    fn cursor(self) -> Result<WorkCursor> {
        let id = self.published.context("work plan is unpublished")?;
        ensure!(
            id == plan_id(self.origin, self.count, self.digest, self.verdict)?,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkKind {
    Initial,
    Finality,
    Reconcile,
}

impl WorkKind {
    pub(crate) fn replacement(action: WorkItem) -> Result<Self> {
        match action {
            WorkItem::Finality => Ok(Self::Finality),
            WorkItem::Reconcile => Ok(Self::Reconcile),
            _ => anyhow::bail!("ordinary stage cannot publish replacement work"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MutablePlan {
    stored: StoredPlan,
    kind: WorkKind,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SealedPlan {
    stored: StoredPlan,
    kind: WorkKind,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PublishedPlan {
    stored: StoredPlan,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WorkState {
    Building(MutablePlan),
    Sealed(SealedPlan),
    Published(PublishedPlan),
}

impl WorkState {
    pub(crate) fn building(self) -> Result<MutablePlan> {
        match self {
            Self::Building(plan) => Ok(plan),
            _ => anyhow::bail!("work is not mutable"),
        }
    }
    pub(crate) fn sealed(self) -> Result<SealedPlan> {
        match self {
            Self::Sealed(plan) => Ok(plan),
            _ => anyhow::bail!("work is not sealed and unpublished"),
        }
    }
    pub(crate) fn published(self) -> Result<PublishedPlan> {
        match self {
            Self::Published(plan) => Ok(plan),
            _ => anyhow::bail!("work is unpublished"),
        }
    }
}

pub(crate) enum PlanStep {
    More,
    Ready(Box<SealedPlan>),
}
impl PlanStep {
    #[cfg(any(test, feature = "protocol-qualification"))]
    pub(crate) fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }
}

impl MutablePlan {
    pub(super) fn summary(&self) -> (u64, [u8; 32]) {
        (self.stored.count, self.stored.digest)
    }
}

impl PublishedPlan {
    pub(super) fn summary(&self) -> (u64, [u8; 32]) {
        (self.stored.count, self.stored.digest)
    }
    pub(crate) fn origin(&self) -> WorkOrigin {
        self.stored.origin
    }
    pub(crate) fn cursor(&self) -> Result<WorkCursor> {
        self.stored.cursor()
    }
}

async fn load(conn: &Connection, key: [u8; 32]) -> Result<StoredPlan> {
    let row = conn.query("SELECT height, origin, item_count, digest, plan_id, verdict FROM closure_work_plans WHERE plan_key = ?1",
        [key.to_vec()]).await?.next().await?.context("work plan unavailable")?;
    let origin = WorkOrigin::decode(&row.get::<Vec<u8>>(1)?)?;
    ensure!(
        origin.key()? == key && origin.height == u64::from_be_bytes(fixed(row.get(0)?)?),
        "work origin binding differs"
    );
    let draft = StoredPlan {
        origin,
        count: u64::from_be_bytes(fixed(row.get(2)?)?),
        digest: fixed(row.get(3)?)?,
        published: row.get::<Option<Vec<u8>>>(4)?.map(fixed).transpose()?,
        verdict: row.get::<Option<Vec<u8>>>(5)?.map(fixed).transpose()?,
    };
    if draft.published.is_some() {
        draft.cursor()?;
    }
    Ok(draft)
}

pub(crate) async fn published(conn: &Connection, id: [u8; 32]) -> Result<PublishedPlan> {
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
    Ok(PublishedPlan { stored: draft })
}

pub(crate) async fn for_origin(
    conn: &Connection,
    origin: WorkOrigin,
    kind: WorkKind,
) -> Result<WorkState> {
    let draft = load(conn, origin.key()?).await?;
    ensure!(draft.origin == origin, "work origin differs");
    check_kind(conn, draft, kind).await?;
    Ok(classify(draft, kind))
}

fn classify(draft: StoredPlan, kind: WorkKind) -> WorkState {
    if draft.published.is_some() {
        WorkState::Published(PublishedPlan { stored: draft })
    } else if draft.verdict.is_some() {
        WorkState::Sealed(SealedPlan {
            stored: draft,
            kind,
        })
    } else {
        WorkState::Building(MutablePlan {
            stored: draft,
            kind,
        })
    }
}

pub(super) async fn initial(conn: &Connection, plan: &ClosurePlan) -> Result<WorkState> {
    let origin = closure::initial_origin(plan)?;
    let stored = load(conn, origin.key()?).await?;
    check_kind_for_plan(conn, stored, WorkKind::Initial, plan).await?;
    Ok(classify(stored, WorkKind::Initial))
}

async fn begin_row(conn: &Connection, origin: WorkOrigin) -> Result<()> {
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
    Ok(())
}

pub(crate) async fn begin_initial(conn: &Connection, plan: &ClosurePlan) -> Result<MutablePlan> {
    let origin = closure::initial_origin(plan)?;
    begin_row(conn, origin).await?;
    initial(conn, plan).await?.building()
}

// Progress must be loaded on this connection within the current transaction.
pub(crate) async fn begin_cause(
    conn: &Connection,
    progress: &Progress,
    kind: WorkKind,
) -> Result<WorkState> {
    ensure!(
        kind != WorkKind::Initial,
        "initial work is not a planning cause"
    );
    ensure!(!conn.is_autocommit(), "work cause requires transaction");
    let origin = progress.work_origin()?;
    ensure!(
        progress
            .next
            .is_some_and(|next| WorkKind::replacement(next.0).ok() == Some(kind)),
        "work cause differs from live planning stage"
    );
    begin_row(conn, origin).await?;
    match kind {
        WorkKind::Finality => finality::initialize_plan(conn, origin).await?,
        WorkKind::Reconcile => reconcile::initialize_plan(conn, origin).await?,
        WorkKind::Initial => unreachable!(),
    }
    let stored = load(conn, origin.key()?).await?;
    check_kind_for_plan(conn, stored, kind, &progress.plan).await?;
    Ok(classify(stored, kind))
}

async fn check_kind(conn: &Connection, stored: StoredPlan, kind: WorkKind) -> Result<()> {
    let plan = closure::plan(conn, stored.origin.height).await?;
    check_kind_for_plan(conn, stored, kind, &plan).await
}

async fn check_kind_for_plan(
    conn: &Connection,
    stored: StoredPlan,
    kind: WorkKind,
    plan: &ClosurePlan,
) -> Result<()> {
    ensure!(plan.id()? == stored.origin.closure, "work closure differs");
    let initial = closure::initial_origin(plan)?;
    let row = conn.query("SELECT (SELECT phase FROM closure_finality_plans WHERE plan_key=?1), (SELECT phase FROM closure_reconcile_plans WHERE plan_key=?1)", [stored.origin.key()?.to_vec()])
        .await?.next().await?.context("work cause lookup failed")?;
    let finality_phase = row.get::<Option<u64>>(0)?;
    let reconcile_phase = row.get::<Option<u64>>(1)?;
    if kind == WorkKind::Initial {
        ensure!(
            stored.origin == initial
                && stored.verdict.is_none()
                && finality_phase.is_none()
                && reconcile_phase.is_none(),
            "invalid initial work kind"
        );
    } else {
        ensure!(
            stored.origin != initial,
            "replacement collides with initial work origin"
        );
        let (phase, other) = match kind {
            WorkKind::Finality => (finality_phase, reconcile_phase),
            WorkKind::Reconcile => (reconcile_phase, finality_phase),
            WorkKind::Initial => unreachable!(),
        };
        ensure!(other.is_none(), "work has contradictory planning causes");
        let phase = phase.context("work lacks its planning cause")?;
        ensure!(
            phase <= 3 && (phase == 3) == stored.verdict.is_some(),
            "work verdict and planning phase differ"
        );
        if let Some(verdict) = stored.verdict {
            let recorded = match kind {
                WorkKind::Finality => finality::sealed_id(conn, stored.origin).await?,
                WorkKind::Reconcile => reconcile::sealed_id(conn, stored.origin).await?,
                WorkKind::Initial => unreachable!(),
            };
            ensure!(
                recorded == verdict,
                "work verdict differs from cause record"
            );
        }
        ensure!(
            stored.published.is_none() || stored.verdict.is_some(),
            "published replacement is unsealed"
        );
    }
    Ok(())
}

pub(crate) async fn check_replacement(
    conn: &Connection,
    plan: &PublishedPlan,
    kind: WorkKind,
) -> Result<()> {
    ensure!(kind != WorkKind::Initial, "replacement requires a cause");
    check_kind(conn, plan.stored, kind).await
}

pub(super) async fn summary(conn: &Connection, origin: WorkOrigin) -> Result<(u64, [u8; 32])> {
    let stored = load(conn, origin.key()?).await?;
    ensure!(stored.origin == origin, "work origin differs");
    Ok((stored.count, stored.digest))
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
    expected: MutablePlan,
    items: &[WorkItem],
) -> Result<MutablePlan> {
    ensure!(!conn.is_autocommit(), "work append requires transaction");
    ensure!(items.len() <= PAGE_ITEMS, "work append exceeds page size");
    let key = expected.stored.origin.key()?;
    let mut draft = load(conn, key).await?;
    ensure!(
        draft == expected.stored && draft.published.is_none() && draft.verdict.is_none(),
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
    Ok(MutablePlan {
        stored: draft,
        kind: expected.kind,
    })
}

pub(crate) async fn verify(conn: &Connection, plan: PublishedPlan, kind: WorkKind) -> Result<()> {
    check_kind(conn, plan.stored, kind).await?;
    verify_contents(conn, plan.stored, kind).await
}

#[cfg(feature = "protocol-qualification")]
async fn verify_mutable(conn: &Connection, plan: &MutablePlan) -> Result<()> {
    verify_contents(conn, plan.stored, plan.kind).await
}

async fn verify_contents(conn: &Connection, draft: StoredPlan, kind: WorkKind) -> Result<()> {
    if let Some(verdict) = draft.verdict {
        match kind {
            WorkKind::Finality => finality::verify(conn, draft.origin, verdict).await?,
            WorkKind::Reconcile => reconcile::verify(conn, draft.origin, verdict).await?,
            WorkKind::Initial => anyhow::bail!("initial work has a cause verdict"),
        }
    }
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

pub(super) async fn bind_verdict(
    conn: &Connection,
    expected: MutablePlan,
    verdict: [u8; 32],
) -> Result<SealedPlan> {
    ensure!(
        !conn.is_autocommit(),
        "verdict binding requires transaction"
    );
    let draft = load(conn, expected.stored.origin.key()?).await?;
    ensure!(
        draft == expected.stored && draft.published.is_none() && draft.verdict.is_none(),
        "verdict draft changed or was sealed"
    );
    match expected.kind {
        WorkKind::Finality => finality::verify(conn, draft.origin, verdict).await?,
        WorkKind::Reconcile => reconcile::verify(conn, draft.origin, verdict).await?,
        WorkKind::Initial => anyhow::bail!("initial work cannot bind a verdict"),
    }
    conn.execute(
        "UPDATE closure_work_plans SET verdict = ?2 WHERE plan_key = ?1",
        params![draft.origin.key()?.to_vec(), verdict.to_vec()],
    )
    .await?;
    for_origin(conn, draft.origin, expected.kind)
        .await?
        .sealed()
}

pub(crate) async fn publish_initial(
    conn: &Connection,
    expected: MutablePlan,
    plan: &ClosurePlan,
) -> Result<WorkCursor> {
    ensure!(
        expected.kind == WorkKind::Initial
            && expected.stored.origin == closure::initial_origin(plan)?,
        "initial publication origin differs"
    );
    let mut digest = expected.stored.origin.key()?;
    let items = plan.initial_work();
    for (index, item) in items.iter().enumerate() {
        digest = item_digest(digest, index as u64, *item)?;
    }
    ensure!(
        expected.stored.count == items.len() as u64 && expected.stored.digest == digest,
        "initial work differs from closure plan"
    );
    publish_checked(conn, expected.stored, WorkKind::Initial).await
}

pub(crate) async fn publish_replacement(
    conn: &Connection,
    expected: SealedPlan,
    ticket: &closure::StageTicket,
) -> Result<WorkCursor> {
    let kind = WorkKind::replacement(ticket.action())?;
    ensure!(
        kind == expected.kind && ticket.work_origin()? == expected.stored.origin,
        "replacement differs from stage ticket"
    );
    let progress = closure::progress(conn, expected.stored.origin.height).await?;
    ensure!(
        progress.work_origin()? == expected.stored.origin
            && progress.next.is_some_and(|next| next.0 == ticket.action())
            && closure::canonical_position(conn, progress.plan.context.chain).await?
                == expected.stored.origin.input,
        "replacement publication pre-state changed"
    );
    publish_checked(conn, expected.stored, kind).await
}

async fn publish_checked(
    conn: &Connection,
    expected: StoredPlan,
    kind: WorkKind,
) -> Result<WorkCursor> {
    ensure!(
        !conn.is_autocommit(),
        "work publication requires transaction"
    );
    let mut draft = load(conn, expected.origin.key()?).await?;
    ensure!(draft == expected, "work draft changed before publication");
    check_kind(conn, draft, kind).await?;
    verify_contents(conn, draft, kind).await?;
    if draft.published.is_none() {
        if let Some(verdict) = draft.verdict
            && kind == WorkKind::Finality
        {
            finality::publish_seeds(conn, draft.origin, verdict).await?;
        }
        let id = plan_id(draft.origin, draft.count, draft.digest, draft.verdict)?;
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
    let plan = published(conn, cursor.plan).await?.stored;
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
    // Deliberately foreign mutable storage must never become executable work.
    origin.previous = [91; 32];
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    begin_row(conn, origin).await?;
    let raw = load(conn, origin.key()?).await?;
    let mut draft = MutablePlan {
        stored: raw,
        kind: WorkKind::Finality,
    };
    ensure!(
        append(
            conn,
            MutablePlan {
                stored: raw,
                kind: WorkKind::Finality
            },
            &vec![WorkItem::Observe; PAGE_ITEMS + 1]
        )
        .await
        .is_err()
    );
    draft = append(conn, draft, &vec![WorkItem::Observe; PAGE_ITEMS]).await?;
    ensure!(
        append(
            conn,
            MutablePlan {
                stored: raw,
                kind: WorkKind::Finality
            },
            &[WorkItem::Observe]
        )
        .await
        .is_err()
    );
    conn.execute_batch("COMMIT").await?;
    ensure!(load(reopened, origin.key()?).await? == draft.stored);
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    let before = draft.stored;
    append(conn, draft, &[WorkItem::Finality]).await?;
    conn.execute_batch("ROLLBACK").await?;
    ensure!(load(reopened, origin.key()?).await? == before);
    draft = MutablePlan {
        stored: before,
        kind: WorkKind::Finality,
    };
    for _ in 0..3 {
        conn.execute_batch("BEGIN IMMEDIATE").await?;
        draft = append(conn, draft, &vec![WorkItem::Observe; PAGE_ITEMS]).await?;
        conn.execute_batch("COMMIT").await?;
    }
    let key = origin.key()?;
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    conn.execute(
        "DELETE FROM closure_work_items WHERE plan_key=?1 AND ordinal=?2",
        params![key.to_vec(), 200u64.to_be_bytes().to_vec()],
    )
    .await?;
    ensure!(verify_mutable(conn, &draft).await.is_err());
    conn.execute_batch("ROLLBACK").await?;
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    conn.execute(
        "UPDATE closure_work_items SET item=?3 WHERE plan_key=?1 AND ordinal=?2",
        params![
            key.to_vec(),
            200u64.to_be_bytes().to_vec(),
            item_bytes(WorkItem::Finality)?
        ],
    )
    .await?;
    ensure!(verify_mutable(conn, &draft).await.is_err());
    conn.execute_batch("ROLLBACK").await?;
    verify_mutable(reopened, &draft).await?;
    ensure!(for_origin(conn, origin, WorkKind::Finality).await.is_err());
    conn.execute_batch("BEGIN IMMEDIATE").await?;
    for kind in [WorkKind::Initial, WorkKind::Finality] {
        ensure!(publish_checked(conn, draft.stored, kind).await.is_err());
    }
    conn.execute_batch("ROLLBACK").await?;
    let row = conn.query("SELECT COUNT(*), SUM(length(item) + length(previous) + length(digest) + length(ordinal)) FROM closure_work_items WHERE plan_key=?1",[key.to_vec()]).await?.next().await?.context("work aggregate missing")?;
    ensure!(row.get::<i64>(0)? == 512 && row.get::<i64>(1)? == 512 * 73);

    let closure = closure::plan(conn, origin.height).await?;
    let published = for_origin(conn, closure::initial_origin(&closure)?, WorkKind::Initial)
        .await?
        .published()?;
    let cursor = published.cursor()?;
    verify(reopened, published, WorkKind::Initial).await?;
    ensure!(
        for_origin(conn, closure::initial_origin(&closure)?, WorkKind::Initial)
            .await?
            .building()
            .is_err()
    );
    let mut forged = cursor;
    forged.prefix = [90; 32];
    ensure!(next(conn, forged).await.is_err());
    forged = cursor;
    forged.count += 1;
    ensure!(next(conn, forged).await.is_err());
    let mut walk = cursor;
    let mut consumed = 0;
    while let Some((_, after)) = next(reopened, walk).await? {
        ensure!(after.index == walk.index + 1);
        walk = after;
        consumed += 1;
    }
    ensure!(consumed == cursor.count && walk.is_empty());
    Ok(cursor)
}
