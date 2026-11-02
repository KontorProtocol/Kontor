#[cfg(test)]
use crate::database::queries::select_block_at_height;
pub(crate) use crate::protocol::execution::ExecutorVersion;
use crate::protocol::execution::SelectionEnvelope;
use anyhow::{Context, Result, bail, ensure};
use bitcoin::{BlockHash, Network, hashes::Hash};
use libsql::Connection;

use super::registry;
use crate::database::canonical_history::{self, ApplicationCursor, HistoryState};
use crate::database::certified_history::{activation, eras, protocol};
use crate::protocol::identity::{ExecutionDefinitionId, ExecutionIdentity, ProtocolId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApplicationPosition {
    View,
    Committee,
    #[cfg_attr(
        not(any(test, feature = "protocol-qualification")),
        allow(dead_code, reason = "K3 position; live activation is wired in K7")
    )]
    Migration {
        anchor_height: u64,
        anchor_hash: BlockHash,
    },
    Initialization {
        step: u64,
    },
    Maintenance {
        rollback_height: Option<u64>,
    },
    Preparation {
        anchor_height: u64,
        anchor_hash: Option<BlockHash>,
    },
    Block {
        height: u64,
        hash: BlockHash,
        consensus_height: u64,
    },
    Batch {
        anchor_height: u64,
        anchor_hash: BlockHash,
        consensus_height: u64,
    },
    Simulation {
        height: u64,
    },
}

// This is a local freshness marker for the existing unversioned database, not
// a network identity or a certified migration commitment. The receipt epoch is
// node-local; its generation distinguishes rollback/replay at the same height.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LegacyCanonicalBase {
    receipt_epoch: String,
    rollback_generation: u64,
    block_height: Option<u64>,
    block_hash: Option<String>,
    latest_transaction: u64,
    checkpoint_height: Option<u64>,
    checkpoint_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalBinding {
    cursor: ApplicationCursor,
    protocol: ProtocolId,
    execution: ExecutionDefinitionId,
}

// A selection does not authorize storage access. CanonicalRootLease retains
// that responsibility; cloning this value cannot create a live root or writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExecutionSelection {
    version: ExecutorVersion,
    network: Network,
    base: LegacyCanonicalBase,
    position: ApplicationPosition,
    canonical: Option<CanonicalBinding>,
}

impl ExecutionSelection {
    pub(crate) fn envelope(&self) -> SelectionEnvelope {
        let position = match self.position {
            ApplicationPosition::View => (0, 0, None, 0),
            ApplicationPosition::Committee => (1, 0, None, 0),
            ApplicationPosition::Migration {
                anchor_height,
                anchor_hash,
            } => (8, anchor_height, Some(anchor_hash.to_byte_array()), 0),
            ApplicationPosition::Initialization { step } => (7, 0, None, step),
            ApplicationPosition::Maintenance { rollback_height } => (
                6,
                rollback_height.unwrap_or(0),
                None,
                u64::from(rollback_height.is_some()),
            ),
            ApplicationPosition::Preparation {
                anchor_height,
                anchor_hash,
            } => (
                2,
                anchor_height,
                anchor_hash.map(|hash| hash.to_byte_array()),
                0,
            ),
            ApplicationPosition::Block {
                height,
                hash,
                consensus_height,
            } => (3, height, Some(hash.to_byte_array()), consensus_height),
            ApplicationPosition::Batch {
                anchor_height,
                anchor_hash,
                consensus_height,
            } => (
                4,
                anchor_height,
                Some(anchor_hash.to_byte_array()),
                consensus_height,
            ),
            ApplicationPosition::Simulation { height } => (5, height, None, 0),
        };
        (
            self.version.tag(),
            self.network.magic().to_bytes(),
            (
                self.base.receipt_epoch.clone(),
                self.base.rollback_generation,
                self.base.block_height,
                self.base.block_hash.clone(),
                self.base.latest_transaction,
                self.base.checkpoint_height,
                self.base.checkpoint_hash.clone(),
            ),
            position,
        )
    }

    pub(crate) fn version(&self) -> ExecutorVersion {
        self.version
    }

    pub(crate) fn execution_identity(
        &self,
        definition: ExecutionDefinitionId,
    ) -> Result<ExecutionIdentity> {
        match &self.canonical {
            Some(binding) => {
                ensure!(
                    definition == binding.execution,
                    "executor definition differs from canonical selection"
                );
                Ok(ExecutionIdentity::Protocol {
                    protocol: binding.protocol,
                    execution: definition,
                })
            }
            None => Ok(ExecutionIdentity::Baseline(definition)),
        }
    }

    pub(crate) fn is_migration(&self) -> bool {
        matches!(self.position, ApplicationPosition::Migration { .. })
    }

    pub(crate) fn is_public_view(&self) -> bool {
        matches!(self.position, ApplicationPosition::View)
    }

    pub(crate) fn ensure_canonical_root(&self, simulation: bool) -> Result<()> {
        let valid = matches!(
            (&self.position, simulation),
            (ApplicationPosition::Simulation { .. }, true)
                | (
                    ApplicationPosition::Block { .. }
                        | ApplicationPosition::Batch { .. }
                        | ApplicationPosition::Committee
                        | ApplicationPosition::Maintenance { .. }
                        | ApplicationPosition::Initialization { .. }
                        | ApplicationPosition::Migration { .. },
                    false,
                )
        );
        ensure!(
            valid,
            "executor selection purpose does not match canonical root"
        );
        Ok(())
    }

    pub(crate) fn ensure_runtime(&self, network: Network, version: ExecutorVersion) -> Result<()> {
        ensure!(
            self.network == network,
            "executor selection network mismatch"
        );
        ensure!(
            self.version == version,
            "runtime does not match selected executor"
        );
        Ok(())
    }

    pub(crate) async fn verify_view(
        &self,
        conn: &Connection,
        network: Network,
        version: ExecutorVersion,
    ) -> Result<()> {
        self.ensure_runtime(network, version)?;
        ensure!(
            matches!(self.position, ApplicationPosition::View),
            "executor selection is not a public view"
        );
        ensure!(
            !conn.is_autocommit(),
            "public view selection requires a pinned transaction"
        );
        self.verify_base(conn).await
    }

    #[cfg(any(test, feature = "protocol-qualification"))]
    pub(crate) async fn verify_committee(
        &self,
        conn: &Connection,
        network: Network,
        version: ExecutorVersion,
    ) -> Result<()> {
        self.ensure_runtime(network, version)?;
        ensure!(
            matches!(self.position, ApplicationPosition::Committee),
            "executor selection is not committee derivation"
        );
        ensure!(
            !conn.is_autocommit(),
            "committee selection requires a pinned transaction"
        );
        self.verify_base(conn).await
    }

    pub(crate) fn same_recognition_rules(&self, current: &Self) -> bool {
        self.version == current.version
            && self.network == current.network
            && self
                .canonical
                .as_ref()
                .map(|binding| (binding.protocol, binding.execution))
                == current
                    .canonical
                    .as_ref()
                    .map(|binding| (binding.protocol, binding.execution))
    }

    pub(crate) fn can_reuse_preparation(&self, current: &Self) -> bool {
        // RPC verdicts contain no canonical-state authority. Other batches may
        // advance this anchor while RPC runs; callers must recheck DB predicates.
        // A reorg or rule change does invalidate the preparation itself.
        self.same_recognition_rules(current)
            && matches!(self.position, ApplicationPosition::Preparation { .. })
            && self.position == current.position
            && self.base.receipt_epoch == current.base.receipt_epoch
            && self.base.rollback_generation == current.base.rollback_generation
    }

    pub(crate) async fn verify_base(&self, conn: &Connection) -> Result<()> {
        let current = if self.canonical.is_some() {
            select_canonical(conn, self.network, self.position.clone()).await?
        } else {
            select_legacy_p1(conn, self.network, self.position.clone()).await?
        };
        ensure!(
            *self == current,
            "executor selection canonical base changed"
        );
        Ok(())
    }

    pub(crate) fn ensure_execution(&self, network: Network, height: u64) -> Result<()> {
        ensure!(
            self.network == network,
            "executor selection network mismatch"
        );
        let selected_height = match self.position {
            ApplicationPosition::Block { height, .. }
            | ApplicationPosition::Simulation { height } => height,
            ApplicationPosition::Batch { anchor_height, .. } => anchor_height,
            ApplicationPosition::Preparation { .. } => {
                bail!("preparation selection cannot execute")
            }
            ApplicationPosition::View => {
                bail!("view selection cannot execute canonical transactions")
            }
            ApplicationPosition::Maintenance { .. }
            | ApplicationPosition::Migration { .. }
            | ApplicationPosition::Initialization { .. } => {
                bail!("maintenance selection cannot execute canonical transactions")
            }
            ApplicationPosition::Committee => {
                bail!("committee selection cannot execute canonical transactions")
            }
        };
        ensure!(
            selected_height == height,
            "executor selection position mismatch"
        );
        Ok(())
    }

    pub(crate) fn ensure_block_execution(
        &self,
        network: Network,
        height: u64,
        hash: BlockHash,
    ) -> Result<()> {
        self.ensure_execution(network, height)?;
        if matches!(self.position, ApplicationPosition::Simulation { .. }) {
            return Ok(());
        }
        self.ensure_block(height, hash)
    }

    pub(crate) fn ensure_block(&self, height: u64, hash: BlockHash) -> Result<()> {
        ensure!(
            matches!(self.position, ApplicationPosition::Block {
            height: selected_height, hash: selected_hash, ..
        } if selected_height == height && selected_hash == hash),
            "executor selection block mismatch"
        );
        Ok(())
    }
}

// Legacy admission is explicit. K3 must supply persisted protocol and migration
// identities before this entry point can be replaced by an upgrade-aware selector.
// Never infer a completed migration or frozen historical artifact from this marker.
pub(crate) async fn select_legacy_p1(
    conn: &Connection,
    network: Network,
    position: ApplicationPosition,
) -> Result<ExecutionSelection> {
    // One statement pins all fields to one SQLite snapshot, including callers
    // preparing pure recognition outside a canonical write transaction.
    let mut rows = conn
        .query(
            "SELECT epoch, generation,
                (SELECT height FROM blocks ORDER BY height DESC LIMIT 1),
                (SELECT hash FROM blocks ORDER BY height DESC LIMIT 1),
                COALESCE((SELECT MAX(id) FROM transactions), 0),
                (SELECT height FROM checkpoints ORDER BY height DESC LIMIT 1),
                (SELECT hash FROM checkpoints ORDER BY height DESC LIMIT 1)
         FROM receipt_stream_state WHERE singleton = 1",
            (),
        )
        .await?;
    let row = rows
        .next()
        .await?
        .context("missing canonical selection lineage")?;
    Ok(ExecutionSelection {
        version: ExecutorVersion::LegacyP1,
        network,
        base: LegacyCanonicalBase {
            receipt_epoch: row.get(0)?,
            rollback_generation: row.get(1)?,
            block_height: row.get(2)?,
            block_hash: row.get(3)?,
            latest_transaction: row.get(4)?,
            checkpoint_height: row.get(5)?,
            checkpoint_hash: row.get(6)?,
        },
        position,
        canonical: None,
    })
}

// The ordering era authenticates decisions; it does not select execution during
// reconstruction. Only the surviving activation at this application position does.
pub(crate) async fn select_canonical(
    conn: &Connection,
    network: Network,
    position: ApplicationPosition,
) -> Result<ExecutionSelection> {
    let mut selected = select_legacy_p1(conn, network, position.clone()).await?;
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        bail!("canonical executor selection requires authentic genesis");
    };
    ensure!(
        cursor.authentic,
        "canonical executor selection has unauthenticated lineage"
    );
    let manifest = match position {
        ApplicationPosition::Migration {
            anchor_height,
            anchor_hash,
        } => {
            activation::pending(conn, anchor_height, anchor_hash)
                .await?
                .context("migration selection lacks a surviving due plan")?
                .pending
                .context("migration selection lost its plan")?
                .manifest
        }
        _ => protocol(conn, eras::selected_protocol(conn).await?).await?,
    };
    ensure!(
        manifest.chain == cursor.chain,
        "canonical protocol chain differs"
    );
    let installed = registry::resolve(&manifest)?;
    // Preparation may read without a pinned transaction. Bracket the immutable
    // manifest lookup with lineage and receipt-generation checks, then recheck
    // the full selection inside the owned root before executing anything.
    ensure!(
        canonical_history::state(conn).await? == HistoryState::Ready(cursor)
            && select_legacy_p1(conn, network, selected.position.clone())
                .await?
                .base
                == selected.base,
        "canonical executor selection changed during admission"
    );
    selected.version = installed.executor;
    selected.canonical = Some(CanonicalBinding {
        cursor,
        protocol: manifest.id()?,
        execution: manifest.executor,
    });
    Ok(selected)
}

#[cfg(test)]
pub(crate) async fn select_test_block(
    conn: &Connection,
    network: Network,
    height: u64,
) -> Result<ExecutionSelection> {
    let block = select_block_at_height(conn, height)
        .await?
        .context("test block is missing")?;
    select_legacy_p1(
        conn,
        network,
        ApplicationPosition::Block {
            height,
            hash: block.hash,
            consensus_height: 0,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use indexer_types::{BlockRow, TransactionRow};

    use super::*;
    use crate::database::certified_history;
    use crate::database::queries::{insert_block, insert_transaction, rollback_to_height};
    use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
    use crate::protocol::coordinator::baseline::Baseline;
    use crate::protocol::identity::ChainId;
    use crate::test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db};

    fn preparation(height: u64) -> ApplicationPosition {
        ApplicationPosition::Preparation {
            anchor_height: height,
            anchor_hash: Some(new_mock_block_hash(height as u32)),
        }
    }

    #[tokio::test]
    async fn canonical_selection_binds_protocol_definition_and_application_lineage() -> Result<()> {
        let (_reader, writer, _dir) = new_test_db().await?;
        let conn = writer.connection();
        assert!(
            select_canonical(&conn, Network::Regtest, ApplicationPosition::Committee)
                .await
                .is_err()
        );
        certified_history::initialize(&conn).await?;
        let baseline = Baseline::for_node(ChainId([1; 32]))?;
        certified_history::begin_baseline(&conn, &baseline, 1).await?;
        conn.execute("BEGIN", ()).await?;
        canonical_history::bind_genesis(&conn, baseline.context.chain).await?;
        conn.execute("COMMIT", ()).await?;
        let selected = select_canonical(&conn, Network::Regtest, preparation(1)).await?;
        assert_eq!(
            selected.execution_identity(baseline.manifest.executor)?,
            ExecutionIdentity::Protocol {
                protocol: baseline.context.protocol,
                execution: baseline.manifest.executor,
            }
        );
        assert!(
            selected
                .execution_identity(ExecutionDefinitionId([2; 32]))
                .is_err()
        );
        assert!(!selected.same_recognition_rules(
            &select_legacy_p1(&conn, Network::Regtest, preparation(1)).await?
        ));
        selected.verify_base(&conn).await?;
        conn.execute("BEGIN", ()).await?;
        let HistoryState::Ready(cursor) = canonical_history::state(&conn).await? else {
            panic!()
        };
        canonical_history::append(
            &conn,
            &CanonicalApplication {
                chain: cursor.chain,
                ordinal: cursor.ordinal + 1,
                parent_lineage: cursor.lineage,
                execution: selected.execution_identity(baseline.manifest.executor)?,
                storage_height: 0,
                source: ApplicationSource::Genesis { stage: 0 },
                input: None,
            },
        )
        .await?;
        conn.execute("COMMIT", ()).await?;
        let after = select_canonical(&conn, Network::Regtest, preparation(1)).await?;
        assert!(selected.verify_base(&conn).await.is_err());
        assert_eq!(
            selected.base, after.base,
            "legacy freshness fields did not change"
        );
        assert!(selected.can_reuse_preparation(&after));
        assert!(
            select_canonical(
                &conn,
                Network::Regtest,
                ApplicationPosition::Migration {
                    anchor_height: 1,
                    anchor_hash: new_mock_block_hash(1),
                }
            )
            .await
            .is_err()
        );
        Ok(())
    }

    async fn block(conn: &Connection, height: u64) -> Result<()> {
        insert_block(
            conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .build(),
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn root_base_and_reusable_preparation_have_distinct_checks() -> Result<()> {
        let (_reader, writer, _dir) = new_test_db().await?;
        let conn = writer.connection();
        block(&conn, 1).await?;
        let before = select_legacy_p1(&conn, Network::Regtest, preparation(1)).await?;
        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(1)
                .txid(new_mock_transaction(42).txid.to_string())
                .build(),
        )
        .await?;
        let after = select_legacy_p1(&conn, Network::Regtest, preparation(1)).await?;
        ensure!(before != after);
        ensure!(before.verify_base(&conn).await.is_err());
        ensure!(before.can_reuse_preparation(&after));
        ensure!(before.ensure_execution(Network::Regtest, 1).is_err());
        ensure!(!before.can_reuse_preparation(
            &select_legacy_p1(&conn, Network::Regtest, preparation(2)).await?
        ));
        ensure!(!before.can_reuse_preparation(
            &select_legacy_p1(&conn, Network::Bitcoin, preparation(1)).await?
        ));
        Ok(())
    }

    #[tokio::test]
    async fn same_hash_replay_cannot_reuse_pre_rollback_selection() -> Result<()> {
        let (_reader, writer, _dir) = new_test_db().await?;
        let conn = writer.connection();
        block(&conn, 1).await?;
        block(&conn, 2).await?;
        let before = select_legacy_p1(&conn, Network::Regtest, preparation(2)).await?;
        rollback_to_height(&conn, 1).await?;
        block(&conn, 2).await?;
        let after = select_legacy_p1(&conn, Network::Regtest, preparation(2)).await?;
        ensure!(before.base.block_hash == after.base.block_hash);
        ensure!(before.base.checkpoint_hash == after.base.checkpoint_hash);
        ensure!(before.base.latest_transaction == after.base.latest_transaction);
        ensure!(!before.can_reuse_preparation(&after));
        ensure!(before.verify_base(&conn).await.is_err());
        ensure!(before.same_recognition_rules(&after));
        Ok(())
    }

    #[tokio::test]
    async fn selection_uses_the_callers_pinned_snapshot() -> Result<()> {
        let (reader, writer, _dir) = new_test_db().await?;
        let conn = writer.connection();
        block(&conn, 1).await?;
        let view = reader.connection().await?;
        view.execute("BEGIN", ()).await?;
        let before = select_legacy_p1(&view, Network::Regtest, preparation(1)).await?;
        block(&conn, 2).await?;
        ensure!(select_legacy_p1(&view, Network::Regtest, preparation(1)).await? == before);
        before.verify_base(&view).await?;
        ensure!(before.verify_base(&conn).await.is_err());
        view.execute("ROLLBACK", ()).await?;
        ensure!(select_legacy_p1(&view, Network::Regtest, preparation(1)).await? != before);
        Ok(())
    }

    #[tokio::test]
    async fn selection_checks_network_position_and_missing_lineage() -> Result<()> {
        let (_reader, writer, _dir) = new_test_db().await?;
        let conn = writer.connection();
        block(&conn, 1).await?;
        let selected = select_test_block(&conn, Network::Regtest, 1).await?;
        selected.ensure_block_execution(Network::Regtest, 1, new_mock_block_hash(1))?;
        ensure!(selected.ensure_execution(Network::Bitcoin, 1).is_err());
        ensure!(selected.ensure_execution(Network::Regtest, 2).is_err());
        ensure!(selected.ensure_block(1, new_mock_block_hash(2)).is_err());
        let view = select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::View).await?;
        let committee =
            select_legacy_p1(&conn, Network::Regtest, ApplicationPosition::Committee).await?;
        for rollback_height in [None, Some(0), Some(1)] {
            let maintenance = select_legacy_p1(
                &conn,
                Network::Regtest,
                ApplicationPosition::Maintenance { rollback_height },
            )
            .await?;
            maintenance.ensure_canonical_root(false)?;
            ensure!(maintenance.ensure_canonical_root(true).is_err());
            ensure!(maintenance.ensure_execution(Network::Regtest, 1).is_err());
            ensure!(
                maintenance.envelope().3
                    == (
                        6,
                        rollback_height.unwrap_or(0),
                        None,
                        u64::from(rollback_height.is_some())
                    )
            );
        }
        ensure!(committee.ensure_execution(Network::Regtest, 1).is_err());
        ensure!(
            committee
                .verify_committee(&conn, Network::Regtest, ExecutorVersion::LegacyP1)
                .await
                .is_err()
        );
        ensure!(view.ensure_execution(Network::Regtest, 1).is_err());
        ensure!(
            view.verify_view(&conn, Network::Regtest, ExecutorVersion::LegacyP1)
                .await
                .is_err()
        );
        conn.execute("BEGIN", ()).await?;
        committee
            .verify_committee(&conn, Network::Regtest, ExecutorVersion::LegacyP1)
            .await?;
        ensure!(
            committee
                .verify_view(&conn, Network::Regtest, ExecutorVersion::LegacyP1)
                .await
                .is_err()
        );
        ensure!(
            view.verify_committee(&conn, Network::Regtest, ExecutorVersion::LegacyP1)
                .await
                .is_err()
        );
        view.verify_view(&conn, Network::Regtest, ExecutorVersion::LegacyP1)
            .await?;
        ensure!(
            selected
                .verify_view(&conn, Network::Regtest, ExecutorVersion::LegacyP1)
                .await
                .is_err()
        );
        ensure!(
            view.verify_view(&conn, Network::Bitcoin, ExecutorVersion::LegacyP1)
                .await
                .is_err()
        );
        conn.execute("ROLLBACK", ()).await?;
        conn.execute("DELETE FROM receipt_stream_state", ()).await?;
        ensure!(
            select_legacy_p1(&conn, Network::Regtest, preparation(1))
                .await
                .is_err()
        );
        Ok(())
    }
}
