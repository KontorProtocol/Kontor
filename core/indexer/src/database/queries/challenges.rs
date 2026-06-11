use libsql::{Connection, Row, de::from_row, params};

use super::Error;
use super::versioned::{latest_one, max_height_of};
use crate::database::types::{ChallengeRow, ChallengeStatus, ChallengeWithStatus};

/// Insert a write-once issuance row. The matching initial `challenge_status`
/// (`active`) row is the caller's responsibility (see [`append_challenge_status`]).
pub async fn insert_challenge(conn: &Connection, row: &ChallengeRow) -> Result<(), Error> {
    conn.execute(
        r#"INSERT INTO challenges (
            challenge_id,
            prover_id,
            agreement_id,
            num_challenges,
            seed,
            deadline_height,
            height
        ) VALUES (?, ?, ?, ?, ?, ?, ?)"#,
        params![
            row.challenge_id.clone(),
            row.prover_id,
            row.agreement_id.clone(),
            row.num_challenges,
            row.seed.clone(),
            row.deadline_height,
            row.height
        ],
    )
    .await?;
    Ok(())
}

/// Append a status transition. The latest row by height is the current status;
/// reorg cascade reverts to the prior one automatically. `OR REPLACE` makes a
/// re-applied transition at the same height idempotent on replay.
pub async fn append_challenge_status(
    conn: &Connection,
    challenge_id: &str,
    status: ChallengeStatus,
    height: u64,
) -> Result<(), Error> {
    conn.execute(
        "INSERT OR REPLACE INTO challenge_status (challenge_id, status, height) VALUES (?, ?, ?)",
        params![challenge_id, status.as_str(), height],
    )
    .await?;
    Ok(())
}

/// The current status of a single challenge, or `None` if it has no status row.
pub async fn latest_challenge_status(
    conn: &Connection,
    challenge_id: &str,
) -> Result<Option<ChallengeStatus>, Error> {
    let mut rows = conn
        .query(
            &latest_one("challenge_status", "challenge_id", "status"),
            params![challenge_id],
        )
        .await?;
    match rows.next().await? {
        Some(row) => Ok(Some(parse_status(row.get::<String>(0)?)?)),
        None => Ok(None),
    }
}

/// Fetch a single issuance row by id (status not joined).
pub async fn get_challenge(
    conn: &Connection,
    challenge_id: &str,
) -> Result<Option<ChallengeRow>, Error> {
    let mut rows = conn
        .query(
            r#"SELECT
                challenge_id,
                prover_id,
                agreement_id,
                num_challenges,
                seed,
                deadline_height,
                height
            FROM challenges
            WHERE challenge_id = ?"#,
            params![challenge_id],
        )
        .await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

/// All challenges for a prover with their current status, optionally filtered
/// to a single status. Filters on the immutable issuance side (`prover_id`) and
/// `LEFT JOIN`s out to the latest status via `max_height_of` in the `ON` clause.
pub async fn get_challenges_by_prover(
    conn: &Connection,
    prover_id: u64,
    status: Option<ChallengeStatus>,
) -> Result<Vec<ChallengeWithStatus>, Error> {
    let base = challenge_with_status_select();
    let rows = match status {
        Some(s) => {
            conn.query(
                &format!("{base} WHERE c.prover_id = ? AND st.status = ?"),
                params![prover_id, s.as_str()],
            )
            .await?
        }
        None => {
            conn.query(&format!("{base} WHERE c.prover_id = ?"), params![prover_id])
                .await?
        }
    };
    collect_challenges(rows).await
}

/// Active challenges whose deadline has passed as of `current_height` — the
/// reactor's expiry sweep input. (`deadline_height < current_height`: the
/// deadline block is the last block a proof is accepted in.)
pub async fn get_overdue_active_challenges(
    conn: &Connection,
    current_height: u64,
) -> Result<Vec<ChallengeWithStatus>, Error> {
    let base = challenge_with_status_select();
    let rows = conn
        .query(
            &format!("{base} WHERE st.status = ? AND c.deadline_height < ?"),
            params![ChallengeStatus::Active.as_str(), current_height],
        )
        .await?;
    collect_challenges(rows).await
}

/// `SELECT` + `LEFT JOIN` body shared by the status-joined reads. The latest
/// status is pinned by a `max_height_of` scalar in the `ON` clause — the only
/// latest-by-height form usable inside a join condition.
fn challenge_with_status_select() -> String {
    format!(
        r#"SELECT
        c.challenge_id,
        c.prover_id,
        c.agreement_id,
        c.num_challenges,
        c.seed,
        c.deadline_height,
        c.height,
        st.status
    FROM challenges c
    LEFT JOIN challenge_status st ON st.challenge_id = c.challenge_id
        AND st.height = {latest}"#,
        latest = max_height_of("challenge_status", "challenge_id", "c.challenge_id"),
    )
}

async fn collect_challenges(mut rows: libsql::Rows) -> Result<Vec<ChallengeWithStatus>, Error> {
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        out.push(challenge_with_status_from_row(&row)?);
    }
    Ok(out)
}

// Manual extraction (rather than `from_row`) so the nullable `status` TEXT maps
// cleanly to `Option<ChallengeStatus>` via `FromStr`.
fn challenge_with_status_from_row(row: &Row) -> Result<ChallengeWithStatus, Error> {
    let status = row
        .get::<Option<String>>(7)?
        .map(parse_status)
        .transpose()?;
    Ok(ChallengeWithStatus {
        challenge_id: row.get(0)?,
        prover_id: row.get::<i64>(1)? as u64,
        agreement_id: row.get(2)?,
        num_challenges: row.get::<i64>(3)? as u64,
        seed: row.get(4)?,
        deadline_height: row.get::<i64>(5)? as u64,
        height: row.get::<i64>(6)? as u64,
        status,
    })
}

fn parse_status(s: String) -> Result<ChallengeStatus, Error> {
    s.parse().map_err(Error::InvalidData)
}
