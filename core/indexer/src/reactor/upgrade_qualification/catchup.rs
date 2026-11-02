use crate::reactor::engine::ValidatorStart;
use std::fs;
use std::time::Duration;

use anyhow::{Context, Error, Result, ensure};
use bitcoin::{BlockHash, hashes::Hash};
use indexer_types::BlockRow;
use libsql::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use super::{DATABASE, NETWORK, accepted_schedule, wait_closed};
use crate::bitcoin_client::Client;
use crate::consensus::signing::PrivateKey;
use crate::database::certified_history::{self, completion};
use crate::database::connection::new_read_only_connection;
use crate::database::queries::insert_block;
use crate::protocol::coordinator::bootstrap;
use crate::protocol::coordinator::genesis::envelope;
use crate::protocol::coordinator::linked::{canonical_session, initialize};
use crate::protocol::identity::ProtocolId;
use crate::reactor::engine::{EngineConfig, NodeCoordinator};
use crate::reactor::execution::ExecutionContext;
use crate::reactor::executor::RuntimeExecutor;
use crate::reactor::mempool_fee_index::MempoolFeeIndex;
use crate::reactor::{PruneConfig, Reactor, start_linked_consensus};
use crate::runtime::GenesisParameters;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

pub(super) async fn run(
    genesis: &GenesisParameters,
    target: ProtocolId,
    peer: String,
    source: &Connection,
) -> Result<Value> {
    let directory = TempDir::new()?;
    let config = EngineConfig {
        private_key: PrivateKey::from([29; 32]),
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        persistent_peers: vec![peer],
        data_dir: directory.path().to_path_buf(),
        consensus_enabled: false,
        validator_start: ValidatorStart::Resume,
        discovery: Default::default(),
    };
    let (coordinator, _reader, writer) =
        NodeCoordinator::open_database(&config, DATABASE, NETWORK, 1, genesis).await?;
    let conn = writer.connection();
    let service = OwnerService::new();
    let result = async {
        let genesis_envelope = envelope(genesis);
        let (baseline, fresh) = bootstrap::prepare(&conn, NETWORK, 1, &genesis_envelope).await?;
        ensure!(fresh);
        insert_block(
            &conn,
            BlockRow::builder()
                .height(0)
                .hash(BlockHash::all_zeros())
                .build(),
        )
        .await?;
        let session = canonical_session(conn.clone(), NETWORK).await?;
        initialize(&service, &session, NETWORK, 1, genesis_envelope).await?;
        // Match the activation fixture's genesis precondition, never copy its
        // decisions or state. Authorization is covered by the separate suite.
        ensure!(accepted_schedule(&conn, &baseline).await? == target);
        bootstrap::complete(&service, &session, NETWORK, &baseline).await?;
        ensure!(
            certified_history::frontier(&conn)
                .await?
                .authenticated_height
                == 0
        );
        let consensus = start_linked_consensus(
            config.clone(),
            Some(&coordinator),
            &session,
            &service,
            NETWORK,
            None,
            None,
            0,
            MempoolFeeIndex::new(None),
        )
        .await?;
        let generations = directory.path().join("consensus-authority/generations.log");
        let initial_generation = fs::read(&generations)?;
        let execution = ExecutionContext::new(
            RuntimeExecutor::new(Client::new(
                "http://127.0.0.1:1".into(),
                String::new(),
                String::new(),
            )?),
            session,
            NETWORK,
            service.clone(),
            baseline.context,
            PruneConfig {
                enabled: false,
                retain_blocks: 144,
            },
            0,
            None,
        );
        // Neither channel supplies history. All certified input must arrive
        // from the already-P2 peer through the running Malachite sync service.
        let (_block_tx, blocks) = mpsc::channel(1);
        let (_mempool_tx, mempool) = mpsc::channel(1);
        let (address_tx, _addresses) = watch::channel(None);
        let shutdown = Shutdown::new();
        let mut reactor = Reactor::from_execution(
            execution,
            blocks,
            mempool,
            shutdown.signal(),
            None,
            None,
            None,
            consensus,
            address_tx,
        );
        reactor.coordinator = Some(coordinator);
        reactor.engine_config = Some(config);
        let observer = new_read_only_connection(directory.path(), DATABASE).await?;
        let observed = async {
            let result = timeout(Duration::from_secs(60), wait_closed(&observer, target, 2))
                .await
                .context("fresh follower did not catch up through activation")?;
            result?;
            // The source can certify empty batches while the follower starts.
            // Compare the same immutable prefix, not two independently moving tips.
            let expected = completion::completed(source, 2).await?;
            let actual = completion::completed(&observer, 2).await?;
            ensure!(actual == expected,
                "cold catch-up closure at height 2 differs: actual={actual:?}, expected={expected:?}");
            for height in 1..=2 {
                let expected = certified_history::load(source, height).await?;
                let actual = certified_history::load(&observer, height).await?;
                ensure!(
                    actual.decision() == expected.decision() && actual.input() == expected.input()
                );
            }
            Ok::<_, Error>(())
        };
        let observe = async {
            let result = observed.await;
            shutdown.cancel();
            result
        };
        let running = async {
            let result = reactor.run().await;
            shutdown.cancel();
            result
        };
        let (running, observed) = tokio::join!(running, observe);
        running?;
        observed?;
        ensure!(fs::read(&generations)? == initial_generation);
        ensure!(
            !directory
                .path()
                .join("consensus-authority/signers")
                .exists()
        );
        ensure!(directory.path().join("consensus-catchup.wal").exists());
        ensure!(!directory.path().join("consensus-validator.wal").exists());
        Ok(
            json!({"source_already_p2": true, "initial_certified_height": 0,
            "verified_through": 2, "same_engine_generation": true,
            "matching_certified_prefix_and_application_position": true, "transport": "malachite-value-sync",
            "signing_enabled": false, "authorization_test": false}),
        )
    }
    .await;
    service.shutdown();
    result
}
