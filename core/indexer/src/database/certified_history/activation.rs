use anyhow::{Context, Result, ensure};
use bitcoin::{BlockHash, hashes::Hash};
use libsql::{Connection, Row, params};

use super::{control, fixed, protocol};
use crate::database::canonical_history::{self, HistoryState, MigrationReceipt};
use crate::database::queries::{max_block_height, select_block_at_height};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::control::{ControlState, validate_target};
use crate::protocol::coordinator::manifest::ProtocolManifest;
use crate::protocol::identity::{ExecutionIdentity, ProtocolId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalActivation {
    pub(crate) application: CanonicalApplication,
    pub(crate) before: ControlState,
}

impl CanonicalActivation {
    pub(crate) fn target(&self) -> Result<&ProtocolManifest> {
        let pending = self
            .before
            .pending
            .as_ref()
            .context("activation lacks pending plan")?;
        ensure!(!pending.consumed, "activation plan was already consumed");
        validate_target(&pending.manifest, &self.before.current_manifest)?;
        let ApplicationSource::Migration {
            anchor_height,
            plan,
            definition,
            ..
        } = self.application.source
        else {
            anyhow::bail!("activation has no migration application");
        };
        ensure!(
            self.application.chain == self.before.context.chain
                && self.application.chain == pending.manifest.chain
                && self.before.current_manifest.id()? == self.before.context.protocol
                && self.application.storage_height == anchor_height
                && anchor_height == pending.activation
                && plan == pending.id
                && definition == pending.manifest.migration
                && self.application.input.is_none()
                && self.application.execution
                    == (ExecutionIdentity::Protocol {
                        protocol: pending.manifest.id()?,
                        execution: pending.manifest.executor,
                    }),
            "activation differs from its authorized migration"
        );
        Ok(&pending.manifest)
    }

    pub(crate) fn consumed_control(&self) -> Result<ControlState> {
        self.target()?;
        let mut state = self.before.clone();
        state.pending = None;
        // Preserve the historical context. Admission projects the currently
        // selected manifest and ordering era without rewriting this snapshot.
        Ok(state)
    }
}

pub(crate) async fn pending(
    conn: &Connection,
    height: u64,
    hash: BlockHash,
) -> Result<Option<ControlState>> {
    ensure!(
        max_block_height(conn).await? == Some(height)
            && select_block_at_height(conn, height)
                .await?
                .is_some_and(|block| block.hash == hash),
        "activation position differs from canonical Bitcoin tip"
    );
    let Some(state) = control::current(conn).await? else {
        return Ok(None);
    };
    let Some(plan) = state.pending.as_ref().filter(|plan| !plan.consumed) else {
        return Ok(None);
    };
    ensure!(
        height <= plan.activation,
        "canonical execution passed a pending activation"
    );
    if height != plan.activation {
        return Ok(None);
    }
    let row = conn
        .query(
            "SELECT record FROM canonical_applications ORDER BY ordinal DESC LIMIT 1",
            (),
        )
        .await?
        .next()
        .await?
        .context("activation lacks completed block lifecycle")?;
    let application = CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?;
    ensure!(
        application.source
            == (ApplicationSource::BlockLifecycle {
                height,
                hash: hash.to_byte_array()
            })
            && application.chain == state.context.chain,
        "activation must follow its block lifecycle before anchored batches"
    );
    Ok(Some(state))
}

async fn activation(conn: &Connection, row: &Row) -> Result<CanonicalActivation> {
    let control_ordinal = row.get::<u64>(4)?;
    let value = CanonicalActivation {
        application: CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?,
        before: control::at_ordinal(conn, control_ordinal)
            .await?
            .context("activation control disappeared")?,
    };
    ensure!(
        value.application.ordinal == row.get::<u64>(1)?
            && control_ordinal < value.application.ordinal
            && value.application.lineage()? == fixed::<32>(row.get(2)?)?
            && value.target()?.id()? == ProtocolId(fixed(row.get(3)?)?)
            && row.get::<i64>(5)? == 1,
        "canonical activation binding differs"
    );
    Ok(value)
}

pub(crate) async fn current(conn: &Connection) -> Result<Option<CanonicalActivation>> {
    at_storage_height(conn, u64::MAX).await
}

pub(crate) async fn at_storage_height(
    conn: &Connection,
    height: u64,
) -> Result<Option<CanonicalActivation>> {
    let row = conn.query(
        "SELECT a.record, p.ordinal, p.lineage, p.protocol_id, p.control_ordinal, a.authentic
         FROM canonical_protocol_activations p JOIN canonical_applications a ON a.ordinal = p.ordinal
         WHERE a.storage_height <= ?1 ORDER BY p.ordinal DESC LIMIT 1",
        [i64::try_from(height).unwrap_or(i64::MAX)],
    ).await?.next().await?;
    match row {
        Some(row) => activation(conn, &row).await.map(Some),
        None => Ok(None),
    }
}

// The migration-owned unit also commits its closure stage. This function cannot
// install a protocol from a supplied manifest or from receipt of a certificate.
pub(crate) async fn record(
    conn: &Connection,
    receipt: &MigrationReceipt,
) -> Result<CanonicalActivation> {
    ensure!(
        !conn.is_autocommit(),
        "activation requires the migration transaction"
    );
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        anyhow::bail!("activation lacks canonical history");
    };
    ensure!(
        cursor.authentic
            && cursor.chain == receipt.application.chain
            && cursor.ordinal == receipt.application.ordinal
            && cursor.lineage == receipt.application.lineage()?
            && canonical_history::surviving_migration_result(
                conn,
                receipt.application.migration_key()?
            )
            .await?
                == Some(receipt.clone()),
        "activation is not the current completed migration"
    );
    let value = CanonicalActivation {
        application: receipt.application.clone(),
        before: control::current(conn)
            .await?
            .context("activation lacks a surviving schedule")?,
    };
    let target = value.target()?;
    let id = target.id()?;
    let control_ordinal = conn.query(
        "SELECT ordinal FROM canonical_upgrade_controls WHERE control = ?1 ORDER BY ordinal DESC LIMIT 1",
        [value.before.head.to_vec()],
    ).await?.next().await?.context("activation control source disappeared")?.get::<u64>(0)?;
    ensure!(
        control::at_ordinal(conn, control_ordinal).await? == Some(value.before.clone()),
        "activation control source differs"
    );
    conn.execute(
        "INSERT OR IGNORE INTO certified_protocols (protocol_id, manifest) VALUES (?1, ?2)",
        params![id.0.to_vec(), target.encode()?],
    )
    .await?;
    ensure!(
        protocol(conn, id).await? == *target,
        "activation manifest differs from retained definition"
    );
    conn.execute(
        "INSERT INTO canonical_protocol_activations (ordinal, lineage, protocol_id, control_ordinal)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            cursor.ordinal,
            cursor.lineage.to_vec(),
            id.0.to_vec(),
            control_ordinal
        ],
    )
    .await?;
    Ok(value)
}
