use anyhow::{Context, Result, ensure};
use bitcoin::{BlockHash, Txid, hashes::Hash};
use libsql::{Connection, TransactionBehavior, params};

use super::{branch, closure, durable_writer, fixed, frontier, load, replay, replay_input, work};
use crate::protocol::canonical_application::DecisionExclusions;
use crate::protocol::canonical_codec::{Decoder, Encoder};
use crate::protocol::coordinator::application_closure::WorkItem;
use crate::protocol::coordinator::closure_work::WorkOrigin;
use crate::protocol::coordinator::replay_input::ReplayInput;
use crate::protocol::coordinator::v1::{FINALITY_WINDOW, deadline_for};
use crate::protocol::identity::domain_digest;

const PAGE: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Verdict {
    origin: WorkOrigin,
    from: Option<u64>,
    seeds: u64,
    seed_digest: [u8; 32],
}

impl Verdict {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Encoder::default();
        out.fixed(b"KFV1")?;
        out.bytes(&self.origin.encode()?)?;
        match self.from {
            None => {
                ensure!(self.seeds == 0, "clean verdict has exclusions");
                out.tag(0)?;
            }
            Some(from) => {
                ensure!(
                    from > 0 && from <= self.origin.input.storage_height,
                    "invalid finality rollback anchor"
                );
                out.tag(1)?;
                out.u64(from)?;
            }
        }
        out.u64(self.seeds)?;
        out.fixed(&self.seed_digest)?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KFV1",
            "unknown finality verdict encoding"
        );
        let origin = WorkOrigin::decode(input.bytes()?)?;
        let from = match input.tag()? {
            0 => None,
            1 => Some(input.u64()?),
            _ => anyhow::bail!("invalid rollback tag"),
        };
        let verdict = Self {
            origin,
            from,
            seeds: input.u64()?,
            seed_digest: input.fixed()?,
        };
        input.finish()?;
        verdict.encode()?;
        Ok(verdict)
    }

    fn id(&self) -> Result<[u8; 32]> {
        Ok(domain_digest(
            b"kontor/finality-verdict/v1",
            &self.encode()?,
        ))
    }
}

async fn prestate(conn: &Connection, origin: WorkOrigin) -> Result<()> {
    let progress = closure::progress(conn, origin.height).await?;
    let state = frontier(conn).await?;
    ensure!(
        state.authenticated_height == origin.height
            && state.closed_height < origin.height
            && progress.work_origin()? == origin
            && progress
                .next
                .is_some_and(|next| next.0 == WorkItem::Finality)
            && closure::canonical_position(conn, progress.plan.context.chain).await?
                == origin.input,
        "finality planning pre-state changed"
    );
    ensure!(
        branch::tip_at(conn, origin.height).await?.map(|tip| tip.0)
            == Some(origin.input.storage_height),
        "finality tip differs from certified branch"
    );
    Ok(())
}

async fn seed(conn: &Connection, origin: WorkOrigin, decision: u64, txid: Txid) -> Result<()> {
    let selected = replay::eligible(conn, origin.height, decision)
        .await?
        .context("finality seed on superseded interval")?;
    ensure!(!selected.is_block, "block cannot supply batch exclusion");
    let original = load(conn, decision).await?;
    ensure!(
        original
            .input()
            .transactions()?
            .iter()
            .any(|tx| tx.compute_txid() == txid),
        "finality seed absent from certified batch"
    );
    let deadline = deadline_for(selected.position.bitcoin_height);
    let key = origin.key()?;
    conn.execute("INSERT OR IGNORE INTO closure_finality_seeds (plan_key, decision, txid, deadline) VALUES (?1, ?2, ?3, ?4)",
        params![key.to_vec(), decision.to_be_bytes().to_vec(), txid.to_byte_array().to_vec(), deadline.to_be_bytes().to_vec()]).await?;
    Ok(())
}

// Only currently executed, overdue transactions can produce a new failure.
// Missing/late confirmations use the batch deadline, never evaluation wall time.
async fn probe(
    conn: &Connection,
    origin: WorkOrigin,
    after: i64,
    mut from: Option<u64>,
) -> Result<()> {
    let mut candidates = Vec::new();
    if let Some(last_due) = origin.input.storage_height.checked_sub(FINALITY_WINDOW) {
        let mut rows = conn
            .query(
                "SELECT t.id, t.batch_height, t.txid, b.anchor_height, b.anchor_hash, t.height
            FROM transactions t JOIN batches b ON b.consensus_height = t.batch_height
            JOIN blocks bl ON bl.height = b.anchor_height AND bl.hash = b.anchor_hash
            WHERE t.id > ?1 AND b.is_block = 0 AND b.anchor_height <= ?2
              AND (t.confirmed_height IS NULL OR t.confirmed_height > b.anchor_height + ?3)
            ORDER BY t.id LIMIT ?4",
                params![after, last_due, FINALITY_WINDOW, PAGE as u64],
            )
            .await?;
        while let Some(row) = rows.next().await? {
            candidates.push((
                row.get::<i64>(0)?,
                row.get::<u64>(1)?,
                row.get::<String>(2)?.parse::<Txid>()?,
                row.get::<u64>(3)?,
                row.get::<String>(4)?.parse::<BlockHash>()?,
                row.get::<u64>(5)?,
            ));
        }
    }
    let mut cursor = after;
    for &(id, decision, txid, anchor, hash, stored_height) in &candidates {
        cursor = id;
        let Some(selected) = replay::eligible(conn, origin.height, decision).await? else {
            continue;
        };
        ensure!(
            !selected.is_block
                && selected.position.bitcoin_height == anchor
                && selected.hash == hash
                && stored_height == anchor,
            "executed finality input differs from certified anchor"
        );
        seed(conn, origin, decision, txid).await?;
        from = Some(from.map_or(anchor, |old| old.min(anchor)));
    }
    let finished = candidates.len() < PAGE;
    conn.execute("UPDATE closure_finality_plans SET probe_after = ?2, from_height = ?3, phase = ?4 WHERE plan_key = ?1",
        params![origin.key()?.to_vec(), cursor, from.map(|h| h.to_be_bytes().to_vec()), if finished { 1 } else { 0 }]).await?;
    if finished && from.is_none() {
        seal(conn, origin, None).await?;
    }
    Ok(())
}

async fn capture(
    conn: &Connection,
    origin: WorkOrigin,
    from: u64,
    after: Option<replay::ExclusionCursor>,
) -> Result<()> {
    let page = replay::exclusion_page(conn, origin.height, after.as_ref()).await?;
    for entry in page.entries {
        seed(conn, origin, entry.decision, entry.txid.parse()?).await?;
    }
    let key = origin.key()?;
    if let Some(next) = page.next {
        conn.execute("UPDATE closure_finality_plans SET seed_after_decision = ?2, seed_after_txid = ?3 WHERE plan_key = ?1",
            params![key.to_vec(), next.decision.to_be_bytes().to_vec(), next.txid]).await?;
    } else {
        // Seeds below the replay boundary are unavailable before its first item.
        // In-range seeds take effect only at their own execution position.
        conn.execute(
            "INSERT INTO closure_replay_unavailable (plan_key, txid)
            SELECT DISTINCT s.plan_key, s.txid FROM closure_finality_seeds s
            JOIN certified_decisions d ON d.height = s.decision
            WHERE s.plan_key = ?1 AND d.bitcoin_height < ?2",
            params![key.to_vec(), from.to_be_bytes().to_vec()],
        )
        .await?;
        let context = frontier(conn)
            .await?
            .context
            .context("missing finality context")?;
        let boundary = branch::boundary(conn, context).await?;
        ensure!(
            from >= boundary.first_height,
            "finality rollback crosses baseline"
        );
        let draft = work::for_origin(conn, origin).await?;
        work::append(conn, draft, &[WorkItem::Rollback { height: from - 1 }]).await?;
        conn.execute(
            "UPDATE closure_finality_plans SET phase = 2 WHERE plan_key = ?1",
            [key.to_vec()],
        )
        .await?;
    }
    Ok(())
}

async fn unavailable(conn: &Connection, key: [u8; 32], txid: Txid) -> Result<bool> {
    Ok(conn
        .query(
            "SELECT 1 FROM closure_replay_unavailable WHERE plan_key = ?1 AND txid = ?2",
            params![key.to_vec(), txid.to_byte_array().to_vec()],
        )
        .await?
        .next()
        .await?
        .is_some())
}

async fn build_one(
    conn: &Connection,
    origin: WorkOrigin,
    from: u64,
    after: Option<replay::ReplayPosition>,
) -> Result<()> {
    let next = replay::page(conn, origin.height, from, after)
        .await?
        .into_iter()
        .next();
    let Some(selected) = next else {
        return seal(conn, origin, Some(from)).await;
    };
    let key = origin.key()?;
    let decision = selected.position.decision;
    let item = if selected.is_block {
        WorkItem::Execute { decision }
    } else {
        let certified = load(conn, decision).await?;
        let original = certified.input().transactions()?;
        let mut direct = Vec::new();
        let mut rows = conn.query("SELECT txid FROM closure_finality_seeds WHERE plan_key = ?1 AND decision = ?2 ORDER BY txid",
            params![key.to_vec(), decision.to_be_bytes().to_vec()]).await?;
        while let Some(row) = rows.next().await? {
            direct.push(fixed::<32>(row.get(0)?)?);
        }
        let mut dropped_positions = Vec::new();
        let mut kept = Vec::new();
        for (position, transaction) in original.iter().enumerate() {
            let txid = transaction.compute_txid();
            let mut drop = direct.binary_search(&txid.to_byte_array()).is_ok();
            for input in &transaction.input {
                if drop {
                    break;
                }
                drop = unavailable(conn, key, input.previous_output.txid).await?;
            }
            if drop {
                dropped_positions.push(position as u64);
                conn.execute("INSERT OR IGNORE INTO closure_replay_unavailable (plan_key, txid) VALUES (?1, ?2)",
                    params![key.to_vec(), txid.to_byte_array().to_vec()]).await?;
            } else {
                kept.push(transaction.clone());
                conn.execute(
                    "DELETE FROM closure_replay_unavailable WHERE plan_key = ?1 AND txid = ?2",
                    params![key.to_vec(), txid.to_byte_array().to_vec()],
                )
                .await?;
            }
        }
        let exclusions = DecisionExclusions::for_batch(decision, &original, &kept, &direct)?;
        let input = ReplayInput {
            origin,
            decision: selected.id,
            interval_since: selected.interval_since,
            exclusions,
            dropped_positions,
        };
        WorkItem::Replay {
            decision,
            input: replay_input::insert(conn, &input).await?,
        }
    };
    let draft = work::for_origin(conn, origin).await?;
    work::append(conn, draft, &[item]).await?;
    conn.execute("UPDATE closure_finality_plans SET replay_height = ?2, replay_decision = ?3 WHERE plan_key = ?1",
        params![key.to_vec(), selected.position.bitcoin_height.to_be_bytes().to_vec(), decision.to_be_bytes().to_vec()]).await?;
    Ok(())
}

async fn seed_commitment(conn: &Connection, origin: WorkOrigin) -> Result<(u64, [u8; 32])> {
    let mut digest = domain_digest(b"kontor/finality-seeds/v1", &origin.encode()?);
    let mut count = 0u64;
    let mut rows = conn.query("SELECT decision, txid, deadline FROM closure_finality_seeds WHERE plan_key = ?1 ORDER BY decision, txid", [origin.key()?.to_vec()]).await?;
    while let Some(row) = rows.next().await? {
        let mut entry = Encoder::default();
        entry.fixed(&digest)?;
        entry.u64(count)?;
        entry.fixed(&fixed::<8>(row.get(0)?)?)?;
        entry.fixed(&fixed::<32>(row.get(1)?)?)?;
        entry.fixed(&fixed::<8>(row.get(2)?)?)?;
        digest = domain_digest(b"kontor/finality-seed/v1", &entry.finish());
        count = count.checked_add(1).context("seed count exhausted")?;
    }
    Ok((count, digest))
}

async fn seal(conn: &Connection, origin: WorkOrigin, from: Option<u64>) -> Result<()> {
    let mut draft = work::for_origin(conn, origin).await?;
    if from.is_some() {
        draft = work::append(conn, draft, &[WorkItem::Finality]).await?;
    }
    let (seeds, seed_digest) = seed_commitment(conn, origin).await?;
    let verdict = Verdict {
        origin,
        from,
        seeds,
        seed_digest,
    };
    conn.execute(
        "UPDATE closure_finality_plans SET phase = 3, record = ?2 WHERE plan_key = ?1",
        params![origin.key()?.to_vec(), verdict.encode()?],
    )
    .await?;
    work::bind_verdict(conn, draft, verdict.id()?).await?;
    Ok(())
}

// Each call commits at most one bounded scan page or one bounded certified body.
// Staging cannot change canonical effects, and a changed pre-state cannot resume it.
pub(crate) async fn step(conn: &Connection, height: u64) -> Result<bool> {
    durable_writer(conn).await?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let progress = closure::progress(&tx, height).await?;
    let origin = progress.work_origin()?;
    prestate(&tx, origin).await?;
    work::begin(&tx, origin).await?;
    let key = origin.key()?;
    tx.execute(
        "INSERT OR IGNORE INTO closure_finality_plans (plan_key, phase) VALUES (?1, 0)",
        [key.to_vec()],
    )
    .await?;
    let row = tx.query("SELECT phase, probe_after, seed_after_decision, seed_after_txid, replay_height, replay_decision, from_height FROM closure_finality_plans WHERE plan_key = ?1", [key.to_vec()])
        .await?.next().await?.context("missing finality plan")?;
    let from = row
        .get::<Option<Vec<u8>>>(6)?
        .map(|bytes| fixed(bytes).map(u64::from_be_bytes))
        .transpose()?;
    match row.get::<u64>(0)? {
        0 => probe(&tx, origin, row.get(1)?, from).await?,
        1 => {
            let after = row
                .get::<Option<Vec<u8>>>(2)?
                .map(|bytes| -> Result<_> {
                    Ok(replay::ExclusionCursor {
                        decision: u64::from_be_bytes(fixed(bytes)?),
                        txid: row.get::<String>(3)?,
                    })
                })
                .transpose()?;
            capture(
                &tx,
                origin,
                from.context("exclusion scan lacks rollback anchor")?,
                after,
            )
            .await?;
        }
        2 => {
            let after = row
                .get::<Option<Vec<u8>>>(4)?
                .map(|bytes| -> Result<_> {
                    Ok(replay::ReplayPosition {
                        bitcoin_height: u64::from_be_bytes(fixed(bytes)?),
                        decision: u64::from_be_bytes(fixed(row.get(5)?)?),
                    })
                })
                .transpose()?;
            build_one(
                &tx,
                origin,
                from.context("replay lacks rollback anchor")?,
                after,
            )
            .await?;
        }
        3 => (),
        _ => anyhow::bail!("invalid finality plan phase"),
    }
    let draft = work::for_origin(&tx, origin).await?;
    let ready = draft.verdict.is_some();
    tx.commit().await?;
    Ok(ready)
}

pub(super) async fn verify(conn: &Connection, origin: WorkOrigin, id: [u8; 32]) -> Result<()> {
    let row = conn
        .query(
            "SELECT record FROM closure_finality_plans WHERE plan_key = ?1 AND phase = 3",
            [origin.key()?.to_vec()],
        )
        .await?
        .next()
        .await?
        .context("finality verdict is not ready")?;
    let verdict = Verdict::decode(&row.get::<Vec<u8>>(0)?)?;
    ensure!(
        verdict.origin == origin && verdict.id()? == id,
        "finality verdict binding differs"
    );
    ensure!(
        seed_commitment(conn, origin).await? == (verdict.seeds, verdict.seed_digest),
        "frozen finality seeds differ"
    );
    Ok(())
}

pub(super) async fn publish_seeds(
    conn: &Connection,
    origin: WorkOrigin,
    id: [u8; 32],
) -> Result<()> {
    ensure!(
        !conn.is_autocommit(),
        "finality publication requires transaction"
    );
    verify(conn, origin, id).await?;
    let mut rows = conn.query("SELECT decision, txid, deadline FROM closure_finality_seeds WHERE plan_key = ?1 ORDER BY decision, txid", [origin.key()?.to_vec()]).await?;
    while let Some(row) = rows.next().await? {
        let decision = u64::from_be_bytes(fixed(row.get(0)?)?);
        let txid = Txid::from_byte_array(fixed(row.get(1)?)?);
        let deadline = u64::from_be_bytes(fixed(row.get(2)?)?);
        conn.execute("INSERT OR IGNORE INTO excluded_batch_txids (batch_height, txid, deadline) VALUES (?1, ?2, ?3)", params![decision, txid.to_string(), deadline]).await?;
    }
    Ok(())
}
