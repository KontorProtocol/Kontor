use anyhow::{Context, Result, ensure};
use libsql::{Connection, params};

use super::{closure, fixed, load_verified_input, replay, work};
use crate::protocol::coordinator::application_closure::WorkItem;
use crate::protocol::coordinator::closure_work::WorkOrigin;
use crate::protocol::coordinator::replay_input::ReplayInput;

async fn validate(conn: &Connection, input: &ReplayInput) -> Result<()> {
    let selected = replay::eligible(conn, input.origin.height, input.exclusions.consensus_height)
        .await?
        .context("replay input is on a superseded branch interval")?;
    ensure!(
        !selected.is_block
            && selected.id == input.decision
            && selected.interval_since == input.interval_since,
        "replay input branch or decision differs"
    );
    let certified = load_verified_input(conn, input.exclusions.consensus_height).await?;
    input.transactions(&certified.input().transactions()?)?;
    Ok(())
}

pub(crate) async fn insert(conn: &Connection, input: &ReplayInput) -> Result<[u8; 32]> {
    ensure!(!conn.is_autocommit(), "replay input requires transaction");
    let progress = closure::progress(conn, input.origin.height).await?;
    ensure!(
        progress.work_origin()? == input.origin
            && progress
                .next
                .is_some_and(|next| next.0 == WorkItem::Finality)
            && closure::canonical_position(conn, progress.plan.context.chain).await?
                == input.origin.input,
        "replay input must be frozen at its verdict pre-state"
    );
    let draft = work::for_origin(conn, input.origin).await?;
    ensure!(draft.cursor().is_err(), "replay plan is already published");
    validate(conn, input).await?;
    let id = input.id()?;
    conn.execute(
        "INSERT OR IGNORE INTO closure_replay_inputs (input_id, plan_key, decision, record) VALUES (?1, ?2, ?3, ?4)",
        params![id.to_vec(), input.origin.key()?.to_vec(), input.exclusions.consensus_height.to_be_bytes().to_vec(), input.encode()?],
    ).await?;
    ensure!(
        get(conn, id, input.origin, input.exclusions.consensus_height).await? == *input,
        "stored replay input differs"
    );
    Ok(id)
}

pub(crate) async fn get(
    conn: &Connection,
    id: [u8; 32],
    origin: WorkOrigin,
    decision: u64,
) -> Result<ReplayInput> {
    let row = conn
        .query(
            "SELECT plan_key, decision, record FROM closure_replay_inputs WHERE input_id = ?1",
            [id.to_vec()],
        )
        .await?
        .next()
        .await?
        .context("frozen replay input unavailable")?;
    let input = ReplayInput::decode(&row.get::<Vec<u8>>(2)?)?;
    ensure!(
        input.id()? == id
            && input.origin == origin
            && input.exclusions.consensus_height == decision
            && fixed::<32>(row.get(0)?)? == origin.key()?
            && u64::from_be_bytes(fixed(row.get(1)?)?) == decision,
        "frozen replay input binding differs"
    );
    validate(conn, &input).await?;
    Ok(input)
}
