use anyhow::{Context, Result, ensure};
use bitcoin::{BlockHash, hashes::Hash};
use libsql::{Connection, Row, params};

use super::{fixed, frontier};
use crate::protocol::coordinator::certified_decision::Decision;

pub(crate) const PAGE_DECISIONS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ReplayPosition {
    pub(crate) bitcoin_height: u64,
    pub(crate) decision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedDecision {
    pub(crate) position: ReplayPosition,
    pub(crate) id: [u8; 32],
    pub(crate) hash: BlockHash,
    pub(crate) is_block: bool,
    pub(crate) interval_since: u64,
}

fn selected(row: &Row, verdict: u64) -> Result<SelectedDecision> {
    let decision = Decision::decode(&row.get::<Vec<u8>>(0)?)?;
    let id = fixed::<32>(row.get(1)?)?;
    let height = u64::from_be_bytes(fixed(row.get(2)?)?);
    let hash = BlockHash::from_byte_array(fixed(row.get(3)?)?);
    let kind = row.get::<i64>(4)?;
    let since = u64::from_be_bytes(fixed(row.get(5)?)?);
    let until = row
        .get::<Option<Vec<u8>>>(6)?
        .map(|value| fixed(value).map(u64::from_be_bytes))
        .transpose()?;
    let indexed_decision = u64::from_be_bytes(fixed(row.get(7)?)?);
    ensure!(
        decision.id()? == id
            && decision.height == indexed_decision
            && decision.descriptor.command.position() == (height, hash, kind == 1)
            && matches!(kind, 0 | 1),
        "replay decision index binding differs"
    );
    ensure!(
        decision.height <= verdict
            && since <= decision.height
            && since <= verdict
            && until.is_none_or(|end| verdict < end)
            && (kind == 0 || decision.height == since),
        "replay decision belongs to another branch incarnation"
    );
    Ok(SelectedDecision {
        position: ReplayPosition {
            bitcoin_height: height,
            decision: decision.height,
        },
        id,
        hash,
        is_block: kind == 1,
        interval_since: since,
    })
}

// Anchor order precedes consensus order. The interval at the verdict, not hash
// equality alone, decides whether an older batch belongs to the surviving branch.
pub(crate) async fn page(
    conn: &Connection,
    verdict: u64,
    from_height: u64,
    after: Option<ReplayPosition>,
) -> Result<Vec<SelectedDecision>> {
    ensure!(
        verdict <= frontier(conn).await?.authenticated_height,
        "replay verdict exceeds authenticated history"
    );
    let after = after.unwrap_or(ReplayPosition {
        bitcoin_height: 0,
        decision: 0,
    });
    let mut rows = conn.query(
        "SELECT d.record, d.decision_id, d.bitcoin_height, d.bitcoin_hash, d.is_block,
                b.since_decision, b.until_decision, d.height
         FROM certified_decisions d INDEXED BY certified_decision_execution_order
         JOIN certified_bitcoin_branch b ON b.bitcoin_height = d.bitcoin_height AND b.block_hash = d.bitcoin_hash
         WHERE d.bitcoin_height >= ?1 AND (d.bitcoin_height, d.height) > (?2, ?3)
           AND d.height <= ?4 AND b.since_decision <= ?4
           AND (b.until_decision IS NULL OR b.until_decision > ?4)
           AND d.height >= b.since_decision AND (d.is_block = 0 OR d.height = b.since_decision)
         ORDER BY d.bitcoin_height, d.height LIMIT ?5",
        params![from_height.to_be_bytes().to_vec(), after.bitcoin_height.to_be_bytes().to_vec(),
            after.decision.to_be_bytes().to_vec(), verdict.to_be_bytes().to_vec(), PAGE_DECISIONS as u64],
    ).await?;
    let mut result = Vec::new();
    let mut previous = after;
    while let Some(row) = rows.next().await? {
        let entry = selected(&row, verdict)?;
        ensure!(
            entry.position > previous,
            "overlapping replay branch intervals or unordered page"
        );
        previous = entry.position;
        result.push(entry);
    }
    Ok(result)
}

pub(crate) async fn eligible(
    conn: &Connection,
    verdict: u64,
    height: u64,
) -> Result<Option<SelectedDecision>> {
    ensure!(
        height > 0 && height <= verdict && verdict <= frontier(conn).await?.authenticated_height,
        "exclusion decision or verdict exceeds authenticated history"
    );
    // An exclusion refers to retained history. Missing records are corruption,
    // whereas an existing decision on a superseded interval is simply ineligible.
    ensure!(
        conn.query(
            "SELECT 1 FROM certified_decisions WHERE height = ?1",
            [height.to_be_bytes().to_vec()]
        )
        .await?
        .next()
        .await?
        .is_some(),
        "exclusion decision history unavailable"
    );
    let mut rows = conn.query(
        "SELECT d.record, d.decision_id, d.bitcoin_height, d.bitcoin_hash, d.is_block,
                b.since_decision, b.until_decision, d.height
         FROM certified_decisions d
         JOIN certified_bitcoin_branch b ON b.bitcoin_height = d.bitcoin_height AND b.block_hash = d.bitcoin_hash
         WHERE d.height = ?1 AND b.since_decision <= ?2
           AND (b.until_decision IS NULL OR b.until_decision > ?2)
           AND d.height >= b.since_decision AND (d.is_block = 0 OR d.height = b.since_decision)",
        params![height.to_be_bytes().to_vec(), verdict.to_be_bytes().to_vec()],
    ).await?;
    let entry = rows
        .next()
        .await?
        .map(|row| selected(&row, verdict))
        .transpose()?;
    ensure!(
        rows.next().await?.is_none(),
        "overlapping replay branch intervals"
    );
    Ok(entry)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExclusionCursor {
    pub(crate) decision: u64,
    pub(crate) txid: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExclusionPage {
    pub(crate) entries: Vec<ExclusionCursor>,
    pub(crate) next: Option<ExclusionCursor>,
}

// Cursor advancement follows scanned rows, including superseded seeds. An empty
// filtered page must not stop the scan before later surviving exclusions.
pub(crate) async fn exclusion_page(
    conn: &Connection,
    verdict: u64,
    after: Option<&ExclusionCursor>,
) -> Result<ExclusionPage> {
    ensure!(
        verdict <= frontier(conn).await?.authenticated_height,
        "exclusion verdict exceeds authenticated history"
    );
    let (height, txid) = after.map_or((0, ""), |cursor| (cursor.decision, cursor.txid.as_str()));
    let mut rows = conn
        .query(
            "SELECT e.batch_height, e.txid FROM excluded_batch_txids e
         WHERE (e.batch_height, e.txid) > (?1, ?2) AND e.batch_height <= ?3
           AND NOT EXISTS (SELECT 1 FROM transactions t WHERE t.txid = e.txid
             AND t.confirmed_height IS NOT NULL AND t.confirmed_height <= e.deadline
             AND (t.batch_height IS NULL OR t.batch_height = e.batch_height))
         ORDER BY e.batch_height, e.txid LIMIT ?4",
            params![height, txid, verdict, PAGE_DECISIONS as u64],
        )
        .await?;
    let mut candidates = Vec::new();
    while let Some(row) = rows.next().await? {
        candidates.push(ExclusionCursor {
            decision: u64::try_from(row.get::<i64>(0)?).context("negative exclusion height")?,
            txid: row.get(1)?,
        });
    }
    let next = (candidates.len() == PAGE_DECISIONS).then(|| candidates.last().unwrap().clone());
    let mut entries = Vec::new();
    for entry in candidates {
        if let Some(selected) = eligible(conn, verdict, entry.decision).await? {
            ensure!(
                !selected.is_block,
                "exclusion attributed to a block decision"
            );
            entries.push(entry);
        }
    }
    Ok(ExclusionPage { entries, next })
}
