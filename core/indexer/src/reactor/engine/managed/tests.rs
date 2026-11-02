use crate::reactor::engine::ValidatorStart;
use tempfile::TempDir;

use super::*;
use crate::database::certified_history;
use crate::protocol::coordinator::baseline::Baseline;
use crate::protocol::coordinator::genesis::{configured_chain, envelope};
use crate::test_utils::test_genesis;

fn engine_config(dir: &TempDir) -> EngineConfig {
    EngineConfig {
        private_key: PrivateKey::from([37; 32]),
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        persistent_peers: vec![],
        data_dir: dir.path().to_path_buf(),
        consensus_enabled: true,
        validator_start: ValidatorStart::Bootstrap,
        discovery: Default::default(),
    }
}

#[tokio::test]
async fn admission_precedes_authority_and_exclusive_ownership_precedes_writer() -> Result<()> {
    let dir = TempDir::new()?;
    let config = engine_config(&dir);
    let genesis = test_genesis(&[]);
    let (coordinator, reader, writer) =
        NodeCoordinator::open_database(&config, "state.db", Network::Regtest, 1, &genesis).await?;
    let first = coordinator.owner.reserve(coordinator.validator)?;
    assert_eq!(first.generation(), 1);
    let network_key = first.network_key();
    assert!(
        NodeCoordinator::open_database(&config, "must-not-exist.db", Network::Regtest, 1, &genesis)
            .await
            .is_err()
    );
    assert!(!dir.path().join("must-not-exist.db").exists());
    drop((first, coordinator, reader, writer));
    let (coordinator, reader, writer) =
        NodeCoordinator::open_database(&config, "state.db", Network::Regtest, 1, &genesis).await?;
    let second = coordinator.owner.reserve(coordinator.validator)?;
    assert_eq!(second.generation(), 2);
    assert_eq!(second.network_key(), network_key);
    drop((second, coordinator, reader, writer));

    let unsupported = TempDir::new()?;
    let writer = Writer::new(unsupported.path(), "state.db").await?;
    let conn = writer.connection();
    let chain = configured_chain(Network::Regtest, 1, &envelope(&genesis))?;
    certified_history::initialize(&conn).await?;
    certified_history::begin_baseline(&conn, &Baseline::current(chain)?, 1).await?;
    let before = certified_history::frontier(&conn).await?;
    let mut config = config;
    config.data_dir = unsupported.path().to_path_buf();
    assert!(
        NodeCoordinator::open_database(&config, "state.db", Network::Regtest, 1, &genesis)
            .await
            .is_err()
    );
    assert!(!unsupported.path().join("consensus-authority").exists());
    assert_eq!(certified_history::frontier(&conn).await?, before);
    Ok(())
}

#[tokio::test]
async fn admitted_node_starts_managed_engine_and_reuses_owner_after_join() -> Result<()> {
    super::qualification::run().await?;
    Ok(())
}
