use anyhow::{Context, Result, ensure};
use bitcoin::{BlockHash, hashes::Hash};
use libsql::{Connection, params};

use super::{context_bytes, fixed, frontier};
use crate::protocol::coordinator::certified_decision::Decision;
use crate::protocol::coordinator::certified_input::{Command, EraContext};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct Rejected(&'static str);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Boundary {
    pub(crate) first_height: u64,
    pub(crate) parent: Option<BlockHash>,
}

pub(super) async fn reserve(
    conn: &Connection,
    context: EraContext,
    first_height: u64,
    fresh: bool,
) -> Result<()> {
    ensure!(
        !conn.is_autocommit(),
        "branch reservation requires genesis transaction"
    );
    ensure!(first_height > 0, "Bitcoin start height must be positive");
    if fresh {
        conn.execute(
            "INSERT INTO certified_bitcoin_boundary (singleton, context, first_height) VALUES (1, ?1, ?2)",
            params![context_bytes(context)?, first_height.to_be_bytes().to_vec()],
        ).await?;
    }
    ensure!(
        boundary(conn, context).await?.first_height == first_height,
        "certified Bitcoin start height changed"
    );
    Ok(())
}

pub(crate) async fn boundary(conn: &Connection, context: EraContext) -> Result<Boundary> {
    let row = conn.query(
        "SELECT context, first_height, parent FROM certified_bitcoin_boundary WHERE singleton = 1", (),
    ).await?.next().await?.context("certified Bitcoin boundary unavailable")?;
    ensure!(
        row.get::<Vec<u8>>(0)? == context_bytes(context)?,
        "Bitcoin boundary context differs"
    );
    let first_height = u64::from_be_bytes(fixed(row.get(1)?)?);
    ensure!(first_height > 0, "invalid certified Bitcoin start height");
    let parent = row
        .get::<Option<Vec<u8>>>(2)?
        .map(|bytes| fixed(bytes).map(BlockHash::from_byte_array))
        .transpose()?;
    Ok(Boundary {
        first_height,
        parent,
    })
}

pub(crate) async fn tip(conn: &Connection) -> Result<Option<(u64, BlockHash)>> {
    let row = conn.query(
        "SELECT bitcoin_height, block_hash FROM certified_bitcoin_branch WHERE until_decision IS NULL ORDER BY bitcoin_height DESC LIMIT 1", (),
    ).await?.next().await?;
    row.map(|row| {
        Ok((
            u64::from_be_bytes(fixed(row.get(0)?)?),
            BlockHash::from_byte_array(fixed(row.get(1)?)?),
        ))
    })
    .transpose()
}

async fn current(conn: &Connection, height: u64) -> Result<Option<BlockHash>> {
    let row = conn.query(
        "SELECT block_hash FROM certified_bitcoin_branch WHERE bitcoin_height = ?1 AND until_decision IS NULL",
        [height.to_be_bytes().to_vec()],
    ).await?.next().await?;
    row.map(|row| fixed(row.get(0)?).map(BlockHash::from_byte_array))
        .transpose()
}

/// Resolve the certified branch at the original decision position, even after
/// later replacement or canonical execution rollback.
pub(crate) async fn at(
    conn: &Connection,
    bitcoin_height: u64,
    decision_height: u64,
) -> Result<Option<BlockHash>> {
    ensure!(
        decision_height <= frontier(conn).await?.authenticated_height,
        "branch query exceeds authenticated history"
    );
    let mut rows = conn
        .query(
            "SELECT block_hash FROM certified_bitcoin_branch WHERE bitcoin_height = ?1
         AND since_decision <= ?2 AND (until_decision IS NULL OR until_decision > ?2)",
            params![
                bitcoin_height.to_be_bytes().to_vec(),
                decision_height.to_be_bytes().to_vec()
            ],
        )
        .await?;
    let result = rows
        .next()
        .await?
        .map(|row| fixed(row.get(0)?).map(BlockHash::from_byte_array))
        .transpose()?;
    ensure!(
        rows.next().await?.is_none(),
        "overlapping certified branch intervals"
    );
    Ok(result)
}

pub(crate) async fn validate(
    conn: &Connection,
    context: EraContext,
    command: &Command,
) -> Result<()> {
    let boundary = boundary(conn, context).await?;
    match command {
        Command::Batch {
            anchor_height,
            anchor_hash,
        } => {
            ensure!(
                boundary.parent.is_some(),
                Rejected("batch precedes first certified Bitcoin block")
            );
            ensure!(
                current(conn, *anchor_height).await? == Some(*anchor_hash),
                Rejected("batch anchor is not on the certified Bitcoin branch")
            );
        }
        Command::Block {
            height,
            hash,
            parent,
            ..
        } => {
            ensure!(
                *height >= boundary.first_height,
                Rejected("block precedes certified Bitcoin boundary")
            );
            let tip = tip(conn).await?;
            if let Some((tip_height, _)) = tip {
                ensure!(
                    boundary.parent.is_some(),
                    "certified branch lacks parent boundary"
                );
                ensure!(
                    *height <= tip_height || tip_height.checked_add(1) == Some(*height),
                    Rejected("certified Bitcoin height gap")
                );
                ensure!(
                    current(conn, *height).await? != Some(*hash),
                    Rejected("repeated certified Bitcoin block")
                );
            } else {
                ensure!(
                    boundary.parent.is_none(),
                    "certified branch disappeared after first block"
                );
                ensure!(
                    *height == boundary.first_height,
                    Rejected("first certified Bitcoin height differs")
                );
            }
            if *height == boundary.first_height {
                if let Some(expected) = boundary.parent {
                    ensure!(
                        *parent == expected,
                        Rejected("Bitcoin reorg crosses immutable baseline parent boundary")
                    );
                }
            } else {
                ensure!(
                    current(conn, height - 1).await? == Some(*parent),
                    Rejected("certified Bitcoin parent differs")
                );
            }
        }
    }
    Ok(())
}

pub(super) async fn record(conn: &Connection, decision: &Decision) -> Result<()> {
    ensure!(
        !conn.is_autocommit(),
        "branch update requires decision transaction"
    );
    validate(
        conn,
        decision.descriptor.context,
        &decision.descriptor.command,
    )
    .await?;
    if let Command::Block {
        height,
        hash,
        parent,
        ..
    } = decision.descriptor.command
    {
        // Closing intervals preserves what was a valid anchor when an earlier
        // batch was decided. Canonical rollback never touches this journal.
        conn.execute(
            "UPDATE certified_bitcoin_branch SET until_decision = ?1 WHERE bitcoin_height >= ?2 AND until_decision IS NULL",
            params![decision.height.to_be_bytes().to_vec(), height.to_be_bytes().to_vec()],
        ).await?;
        conn.execute(
            "INSERT INTO certified_bitcoin_branch (bitcoin_height, since_decision, block_hash) VALUES (?1, ?2, ?3)",
            params![height.to_be_bytes().to_vec(), decision.height.to_be_bytes().to_vec(), hash.to_byte_array().to_vec()],
        ).await?;
        conn.execute(
            "UPDATE certified_bitcoin_boundary SET parent = ?1 WHERE singleton = 1 AND parent IS NULL",
            [parent.to_byte_array().to_vec()],
        ).await?;
    }
    Ok(())
}

#[cfg(feature = "protocol-qualification")]
pub(crate) mod qualification;
