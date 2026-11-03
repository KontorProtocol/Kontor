use anyhow::{Context, Result, ensure};
use indexer_types::OpWithResult;
use libsql::Connection;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[cfg(kontor_managed)]
use crate::build_record;
use crate::database::canonical_history::{self, HistoryState};
use crate::database::certified_history::{self, Status, eras};
use crate::protocol::coordinator::baseline::Baseline;
use crate::protocol::coordinator::manifest::ProtocolManifest;
use crate::protocol::coordinator::registry::{self, UnavailableProtocol};
#[cfg(kontor_managed)]
use crate::protocol::coordinator::successor;

/// Local execution provenance, not a certified state root or inclusion promise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ExecutionContextInfo {
    pub protocol_id: Option<String>,
    pub execution_definition: String,
    pub application_ordinal: Option<String>,
    pub lineage: Option<String>,
    pub bitcoin_height: Option<String>,
    pub bitcoin_hash: Option<String>,
    pub checkpoint_height: Option<String>,
    pub checkpoint_hash: Option<String>,
    pub receipt_epoch: String,
    pub rollback_generation: String,
    pub simulation_height: Option<String>,
}

#[derive(Debug, Serialize, TS)]
pub struct SimulationReport {
    pub context: ExecutionContextInfo,
    pub operations: Vec<OpWithResult>,
}

#[derive(Debug, Serialize, TS)]
pub struct ProtocolDescriptor {
    pub protocol_id: String,
    pub protocol_number: String,
    pub predecessor: String,
    pub execution_definition: String,
    pub consensus_definition: String,
    pub certificate_codec: u32,
    pub transaction_formats: Vec<u32>,
    pub host_abis: Vec<u32>,
    pub input_state_schema: u32,
    pub output_state_schema: u32,
    pub migration_definition: String,
    pub native_contracts_root: String,
    pub installed: bool,
}

impl ProtocolDescriptor {
    fn from_manifest(manifest: &ProtocolManifest) -> Result<Self> {
        let installed = match registry::resolve(manifest) {
            Ok(_) => true,
            Err(error) if error.is::<UnavailableProtocol>() => false,
            Err(error) => return Err(error),
        };
        Ok(Self {
            protocol_id: hex::encode(manifest.id()?.0),
            protocol_number: manifest.protocol_number.to_string(),
            predecessor: hex::encode(manifest.predecessor.0),
            execution_definition: hex::encode(manifest.executor.0),
            consensus_definition: hex::encode(manifest.consensus),
            certificate_codec: manifest.certificate_codec,
            transaction_formats: manifest.transaction_formats.clone(),
            host_abis: manifest.host_abis.clone(),
            input_state_schema: manifest.input_state_schema,
            output_state_schema: manifest.output_state_schema,
            migration_definition: hex::encode(manifest.migration.0),
            native_contracts_root: hex::encode(manifest.native_contracts_root),
            installed,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolAvailability {
    Uninitialized,
    HistoryUnavailable,
    Recovering,
    Unsupported,
    Ready,
}

#[derive(Debug, Serialize, TS)]
pub struct CertifiedProgress {
    pub authenticated_height: String,
    pub authenticated_decision: Option<String>,
    pub closed_height: String,
    pub closure_id: Option<String>,
    pub ordering_protocol_id: Option<String>,
    pub ordering_era_id: Option<String>,
}

#[derive(Debug, Serialize, TS)]
pub struct CanonicalProtocol {
    pub protocol: ProtocolDescriptor,
    pub application_ordinal: String,
    pub lineage: String,
    pub storage_height: String,
}

#[derive(Debug, Serialize, TS)]
pub struct BuildProvenance {
    pub target: String,
    pub profile: String,
    pub compiler_sha256: String,
    pub source_inputs_sha256: String,
    pub lock_sha256: String,
    pub consensus_runtime_definition: String,
}

#[derive(Debug, Serialize, TS)]
pub struct ProtocolSnapshot {
    pub availability: ProtocolAvailability,
    pub chain_id: Option<String>,
    pub certified: Option<CertifiedProgress>,
    pub canonical: Option<CanonicalProtocol>,
    pub installed_protocols: Vec<ProtocolDescriptor>,
    pub build: Option<BuildProvenance>,
}

pub(crate) async fn snapshot(conn: &Connection) -> Result<ProtocolSnapshot> {
    ensure!(
        !conn.is_autocommit(),
        "protocol diagnostics require one database snapshot"
    );
    let mut result = ProtocolSnapshot {
        availability: ProtocolAvailability::Uninitialized,
        chain_id: None,
        certified: None,
        canonical: None,
        installed_protocols: Vec::new(),
        build: None,
    };
    #[cfg(kontor_managed)]
    {
        result.build = Some(build_record::diagnostics()?);
    }
    let tables = conn
        .query(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table'
         AND name IN ('certified_history_state', 'canonical_history_state')",
            (),
        )
        .await?
        .next()
        .await?
        .context("schema table count")?
        .get::<u64>(0)?;
    if tables == 0 {
        return Ok(result);
    }
    if tables != 2 {
        result.availability = ProtocolAvailability::HistoryUnavailable;
        return Ok(result);
    }
    let frontier = certified_history::frontier(conn).await?;
    result.certified = Some(CertifiedProgress {
        authenticated_height: frontier.authenticated_height.to_string(),
        authenticated_decision: frontier.authenticated_id.map(hex::encode),
        closed_height: frontier.closed_height.to_string(),
        closure_id: frontier.closure_id.map(hex::encode),
        ordering_protocol_id: frontier
            .context
            .map(|context| hex::encode(context.protocol.0)),
        ordering_era_id: frontier.context.map(|context| hex::encode(context.era)),
    });
    let history = canonical_history::state(conn).await?;
    result.availability = match (frontier.status, history) {
        (Status::Unavailable, _) | (_, HistoryState::Unavailable) => {
            ProtocolAvailability::HistoryUnavailable
        }
        (Status::Pending | Status::Initializing, _) | (_, HistoryState::PendingGenesis) => {
            ProtocolAvailability::Uninitialized
        }
        (Status::Ready, HistoryState::Ready(cursor)) if cursor.authentic => {
            ProtocolAvailability::Recovering
        }
        _ => ProtocolAvailability::HistoryUnavailable,
    };
    if result.availability != ProtocolAvailability::Recovering {
        return Ok(result);
    }
    let HistoryState::Ready(cursor) = history else {
        unreachable!()
    };
    result.chain_id = Some(hex::encode(cursor.chain.0));
    let manifest = certified_history::protocol(conn, eras::selected_protocol(conn).await?).await?;
    ensure!(
        manifest.chain == cursor.chain,
        "canonical protocol chain differs"
    );
    let descriptor = ProtocolDescriptor::from_manifest(&manifest)?;
    if !descriptor.installed {
        result.availability = ProtocolAvailability::Unsupported;
    } else if frontier.authenticated_height == frontier.closed_height {
        result.availability = ProtocolAvailability::Ready;
    }
    result.canonical = Some(CanonicalProtocol {
        protocol: descriptor,
        application_ordinal: cursor.ordinal.to_string(),
        lineage: hex::encode(cursor.lineage),
        storage_height: cursor.storage_height.to_string(),
    });
    result
        .installed_protocols
        .push(ProtocolDescriptor::from_manifest(
            &Baseline::for_node(cursor.chain)?.manifest,
        )?);
    #[cfg(kontor_managed)]
    result
        .installed_protocols
        .push(ProtocolDescriptor::from_manifest(&successor::manifest(
            cursor.chain,
        )?)?);
    #[cfg(all(kontor_managed, feature = "protocol-qualification"))]
    result
        .installed_protocols
        .push(ProtocolDescriptor::from_manifest(
            &successor::qualification_third(cursor.chain)?,
        )?);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Address, signing::PrivateKey};
    use crate::protocol::coordinator::registration_history::{
        ObservationPosition, RegistrationSnapshot,
    };
    use crate::protocol::identity::ChainId;
    use crate::test_utils::new_test_db;

    #[tokio::test]
    async fn diagnostics_are_snapshot_consistent_and_do_not_admit_unavailable_history() -> Result<()>
    {
        let (reader, writer, _directory) = new_test_db().await?;
        let conn = writer.connection();
        certified_history::initialize(&conn).await?;
        assert!(snapshot(&conn).await.is_err());
        let read = reader.connection().await?;
        read.execute("BEGIN", ()).await?;
        assert_eq!(
            snapshot(&read).await?.availability,
            ProtocolAvailability::Uninitialized
        );
        read.execute("ROLLBACK", ()).await?;

        let baseline = Baseline::for_node(ChainId([9; 32]))?;
        certified_history::begin_baseline(&conn, &baseline, 1).await?;
        conn.execute("BEGIN", ()).await?;
        canonical_history::bind_genesis(&conn, baseline.context.chain).await?;
        conn.execute("COMMIT", ()).await?;
        let key = PrivateKey::from([8; 32]).public_key();
        let observation = RegistrationSnapshot::observe(
            None,
            ObservationPosition {
                context: baseline.context,
                height: 0,
                decision: certified_history::genesis_predecessor(baseline.context)?,
                stage: 0,
                lineage: baseline.context.chain.0,
            },
            (
                vec![(
                    Address::from_public_key(&key).into_inner(),
                    *key.as_bytes(),
                    1,
                )],
                vec![("validator".into(), Some((key.as_bytes().to_vec(), 1, 0, 0)))],
            ),
        )?;
        certified_history::finish_genesis(&conn, &observation).await?;
        read.execute("BEGIN", ()).await?;
        let before = snapshot(&read).await?;
        assert_eq!(before.availability, ProtocolAvailability::Ready);
        let canonical = before.canonical.as_ref().unwrap();
        assert_eq!(
            canonical.protocol.protocol_id,
            hex::encode(baseline.context.protocol.0)
        );
        assert_eq!(
            canonical.protocol.transaction_formats,
            baseline.manifest.transaction_formats
        );
        assert_eq!(canonical.protocol.host_abis, baseline.manifest.host_abis);
        assert!(canonical.protocol.installed);

        conn.execute(
            "UPDATE canonical_history_state SET status = 'unavailable', chain_id = NULL,
             lineage = NULL, ordinal = 0, storage_height = 0, authentic = 0",
            (),
        )
        .await?;
        assert_eq!(
            serde_json::to_value(snapshot(&read).await?)?,
            serde_json::to_value(before)?
        );
        read.execute("COMMIT", ()).await?;
        read.execute("BEGIN", ()).await?;
        let unavailable = snapshot(&read).await?;
        assert_eq!(
            unavailable.availability,
            ProtocolAvailability::HistoryUnavailable
        );
        assert!(unavailable.canonical.is_none());
        assert_eq!(unavailable.certified.unwrap().closed_height, "0");
        read.execute("COMMIT", ()).await?;
        assert!(matches!(
            canonical_history::state(&conn).await?,
            HistoryState::Unavailable
        ));
        Ok(())
    }

    #[test]
    fn discovery_does_not_claim_arbitrary_manifests_are_installed() -> Result<()> {
        let mut manifest = Baseline::for_node(ChainId([9; 32]))?.manifest;
        let installed = ProtocolDescriptor::from_manifest(&manifest)?;
        manifest.protocol_number += 1;
        let unknown = ProtocolDescriptor::from_manifest(&manifest)?;
        assert!(!unknown.installed);
        assert_ne!(unknown.protocol_id, installed.protocol_id);
        assert_eq!(unknown.execution_definition, installed.execution_definition);
        Ok(())
    }
}
