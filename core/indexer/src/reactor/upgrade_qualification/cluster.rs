use crate::reactor::engine::ValidatorStart;
use std::num::NonZeroU64;
use std::time::Duration;

use anyhow::{Context, Error, Result, anyhow, ensure};
use bitcoin::{
    Block, BlockHash, blockdata::constants::genesis_block, consensus::serialize, hashes::Hash,
};
use indexer_types::{BlockRow, ContractArtifactSource, ContractProvenanceResponse, ViewResult};
use libsql::{Connection, params};
use malachitebft_app_channel::app::config::{BootstrapProtocol, DiscoveryConfig, Selector};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use super::confirmation::transaction;
use super::services::Services;
use super::{DATABASE, NETWORK, accepted_schedule_at};
use crate::bitcoin_client::Client;
use crate::config::Config;
use crate::consensus::signing::{ConsensusMode, PrivateKey};
use crate::database::certified_history::{self, activation, completion, eras};
use crate::database::connection::new_read_only_connection;
use crate::database::queries::insert_block;
use crate::keygen;
use crate::protocol::coordinator::bootstrap;
use crate::protocol::coordinator::durable_signer::{GenerationOwner, SignerRecovery};
use crate::protocol::coordinator::genesis::envelope;
use crate::protocol::coordinator::linked::{canonical_session, initialize};
use crate::protocol::identity::ProtocolId;
use crate::protocol_qualification::application_state as state;
use crate::reactor::engine::{EngineConfig, NodeCoordinator};
use crate::reactor::status::EngineAuthority;
use crate::reactor::{self, PruneConfig};
use crate::runtime::ownership::OwnerService;
use crate::runtime::{Decimal, GenesisParameters, GenesisValidator};
use crate::stopper::Shutdown;

struct Node {
    directory: Option<TempDir>,
    observer: Connection,
    service: OwnerService,
    services: Services,
    addresses: watch::Receiver<Option<String>>,
    task: Option<JoinHandle<Result<()>>>,
    shutdown: Shutdown,
    first: ProtocolId,
    target: ProtocolId,
    listener: String,
}

impl Node {
    async fn start(
        key: PrivateKey,
        genesis: GenesisParameters,
        peers: Vec<String>,
        validator_start: ValidatorStart,
    ) -> Result<Self> {
        let directory = TempDir::new()?;
        let config = EngineConfig {
            private_key: key,
            listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
            persistent_peers: peers,
            data_dir: directory.path().to_path_buf(),
            consensus_enabled: true,
            validator_start,
            discovery: DiscoveryConfig {
                enabled: true,
                bootstrap_protocol: BootstrapProtocol::Full,
                selector: Selector::Random,
                ..Default::default()
            },
        };
        let (coordinator, reader, writer) =
            NodeCoordinator::open_database(&config, DATABASE, NETWORK, 1, &genesis).await?;
        let client = Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?;
        let service = OwnerService::new();
        let setup = async {
            let conn = writer.connection();
            let genesis_envelope = envelope(&genesis);
            let (baseline, fresh) =
                bootstrap::prepare(&conn, NETWORK, 1, &genesis_envelope).await?;
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
            let target = accepted_schedule_at(&conn, &baseline, 2).await?;
            bootstrap::complete(&service, &session, NETWORK, &baseline).await?;
            let observer = new_read_only_connection(directory.path(), DATABASE).await?;
            Ok::<_, Error>((baseline.context.protocol, target, observer))
        }
        .await;
        let (first, target, observer) = match setup {
            Ok(value) => value,
            Err(error) => {
                service.shutdown();
                return Err(error);
            }
        };
        let (address_tx, addresses) = watch::channel(None);
        let shutdown = Shutdown::new();
        let api_config = Config {
            network: NETWORK,
            data_dir: directory.path().to_path_buf(),
            consensus_mode: ConsensusMode::Validator,
            consensus_listen_addr: config.listen_addr.clone(),
            consensus_peers: config.persistent_peers.clone(),
            ..Config::new_na()
        };
        let (services, io) = match Services::start(
            api_config,
            reader,
            service.clone(),
            client.clone(),
            addresses.clone(),
            &shutdown,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                service.shutdown();
                return Err(error);
            }
        };
        let task = reactor::run(
            1,
            shutdown.signal(),
            service.clone(),
            writer,
            io.blocks,
            io.mempool,
            Some(io.ready),
            Some(io.events),
            Some(io.simulate),
            Some(io.upgrade),
            config,
            coordinator,
            client,
            genesis,
            None,
            500,
            Some(io.fees),
            address_tx,
            io.runtime_status,
            NETWORK,
            PruneConfig {
                enabled: false,
                retain_blocks: 144,
            },
        );
        Ok(Self {
            directory: Some(directory),
            observer,
            service,
            services,
            addresses,
            task: Some(task),
            shutdown,
            first,
            target,
            listener: String::new(),
        })
    }

    async fn ready(&mut self) -> Result<()> {
        self.services.ready().await?;
        self.listener = timeout(
            Duration::from_secs(30),
            self.addresses.wait_for(Option::is_some),
        )
        .await
        .context("cluster listener timed out")??
        .clone()
        .context("cluster listener")?;
        self.healthy().await
    }

    async fn healthy(&mut self) -> Result<()> {
        self.services.healthy()?;
        if self.task.as_ref().is_some_and(JoinHandle::is_finished) {
            self.task
                .take()
                .context("node task")?
                .await
                .context("node task panicked")??;
            return Err(anyhow!("node stopped without a shutdown request"));
        }
        ensure!(self.task.is_some(), "node task already stopped");
        Ok(())
    }

    async fn view(&self) -> Result<Value> {
        Ok(match self.services.view().await? {
            ViewResult::Ok { value } => json!({"Ok": value}),
            ViewResult::Err { message } => json!({"Err": message}),
        })
    }

    async fn provenance(&self, name: &str) -> Result<ContractProvenanceResponse> {
        self.services.provenance(name).await
    }

    async fn join(&mut self) -> Result<()> {
        let result = if let Some(mut task) = self.task.take() {
            match timeout(Duration::from_secs(40), &mut task).await {
                Ok(result) => result
                    .context("cluster node panicked")
                    .and_then(|result| result),
                Err(_) => {
                    // A timed-out task may still own SQLite/WAL files. Keep its
                    // directory instead of deleting live engine storage.
                    let path = self.directory.take().context("node directory")?.keep();
                    Err(anyhow!(
                        "cluster node did not join; retained {}",
                        path.display()
                    ))
                }
            }
        } else {
            Ok(())
        };
        let services = self.services.join().await;
        if services.is_err() {
            if let Some(directory) = self.directory.take() {
                eprintln!(
                    "retained node directory after service failure: {}",
                    directory.keep().display()
                );
            }
        }
        self.service.shutdown();
        result.and(services)
    }
}

async fn wait_all(
    nodes: &mut [Node],
    height: u64,
    hash: BlockHash,
    protocol: ProtocolId,
) -> Result<u64> {
    loop {
        let mut complete = true;
        let mut decision = None;
        for (index, node) in nodes.iter_mut().enumerate() {
            node.healthy()
                .await
                .with_context(|| format!("validator {index}"))?;
            let frontier = certified_history::frontier(&node.observer).await?;
            // Empty batches can be certified while the real follower polls.
            // Locate this block's decision rather than equating the two clocks.
            let row = node.observer.query(
                "SELECT since_decision FROM certified_bitcoin_branch WHERE bitcoin_height = ?1 AND block_hash = ?2 AND until_decision IS NULL",
                params![height.to_be_bytes().to_vec(), hash.to_byte_array().to_vec()],
            ).await?.next().await?;
            let Some(row) = row else {
                complete = false;
                continue;
            };
            let bytes: [u8; 8] = row
                .get::<Vec<u8>>(0)?
                .try_into()
                .map_err(|_| anyhow!("invalid certified block decision height"))?;
            let current = u64::from_be_bytes(bytes);
            if let Some(expected) = decision {
                ensure!(
                    current == expected,
                    "validators certified the block at different heights"
                );
            }
            decision = Some(current);
            complete &= frontier.closed_height >= current
                && frontier
                    .context
                    .is_some_and(|context| context.protocol == protocol);
        }
        if complete {
            for node in nodes.iter_mut() {
                node.services.progress().await?;
            }
            return decision.context("closed block decision");
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn broadcast(nodes: &[Node], height: u64, block: Block) -> Result<()> {
    for node in nodes {
        node.services.advance(height, &block);
    }
    Ok(())
}

async fn check_client_context(
    node: &Node,
    height: u64,
    hash: BlockHash,
    protocol: ProtocolId,
) -> Result<Value> {
    let discovery = node.services.protocol().await?;
    let selected = &discovery["canonical"]["protocol"];
    ensure!(selected["protocol_id"] == hex::encode(protocol.0));
    ensure!(selected["installed"] == true);
    ensure!(
        selected["transaction_formats"]
            .as_array()
            .is_some_and(|formats| !formats.is_empty())
    );
    ensure!(
        selected["host_abis"]
            .as_array()
            .is_some_and(|abis| !abis.is_empty())
    );
    let simulation = node.services.simulate(&serialize(&transaction()?)).await?;
    let context = &simulation["context"];
    ensure!(context["protocol_id"] == selected["protocol_id"]);
    ensure!(context["execution_definition"] == selected["execution_definition"]);
    ensure!(context["bitcoin_height"] == height.to_string());
    ensure!(context["bitcoin_hash"] == hash.to_string());
    ensure!(context["simulation_height"] == (height + 1).to_string());
    ensure!(context["lineage"].as_str().is_some());
    ensure!(
        simulation["operations"]
            .as_array()
            .is_some_and(|operations| !operations.is_empty())
    );
    let runtime = node.services.runtime(EngineAuthority::Validator).await?;
    ensure!(runtime.committee_member && runtime.required_join_height.is_none());
    Ok(context.clone())
}

pub(crate) async fn run() -> Result<Value> {
    let keys: Vec<_> = (0..3)
        .map(|index| keygen::derive_validator(&[0x73; 32], index))
        .collect();
    let genesis = GenesisParameters {
        sigma_min: Decimal::from("1"),
        validators: keys
            .iter()
            .map(|key| GenesisValidator {
                x_only_pubkey: hex::encode(key.x_only_pubkey),
                ed25519_pubkey: key.ed25519_pubkey.to_vec(),
                stake: Decimal::from("100"),
            })
            .collect(),
    };
    let mut nodes = Vec::<Node>::new();
    let result = timeout(Duration::from_secs(240), async {
        for key in keys {
            let peers = nodes.first().map(|node| vec![node.listener.clone()]).unwrap_or_default();
            nodes.push(Node::start(PrivateKey::from(key.ed25519_private), genesis.clone(), peers, ValidatorStart::Bootstrap).await?);
            let node = nodes.last_mut().context("started node")?;
            node.ready().await?;
            ensure!(node.view().await?.get("Err").is_some(), "P1 exposes P2 view");
        }
        let original_provenance = nodes[0].provenance("token").await?;
        ensure!(original_provenance.effective_artifact.source == ContractArtifactSource::Publication);
        ensure!(original_provenance.effective_artifact.sha256 == original_provenance.effective_artifact.published_sha256);
        ensure!(original_provenance.effective_artifact.protocol_id == Some(hex::encode(nodes[0].first.0)));
        let first = nodes[0].first;
        let target = nodes[0].target;
        let block = genesis_block(NETWORK);
        broadcast(&nodes, 1, block.clone()).await?;
        let c1 = wait_all(&mut nodes, 1, block.block_hash(), first).await?;
        let p1_preview = check_client_context(&nodes[0], 1, block.block_hash(), first).await?;
        for node in &nodes {
            ensure!(node.view().await?.get("Err").is_some(), "activation ran before H");
        }
        let mut next = block.clone();
        next.header.prev_blockhash = next.block_hash();
        next.header.nonce = next.header.nonce.wrapping_add(1);
        broadcast(&nodes, 2, next.clone()).await?;
        let c2 = wait_all(&mut nodes, 2, next.block_hash(), target).await?;
        let p2_preview = check_client_context(&nodes[0], 2, next.block_hash(), target).await?;
        for node in &nodes {
            ensure!(node.view().await? == json!({"Ok":"2"}), "P2 fixture initialization differs");
        }
        let upgraded_provenance = nodes[0].provenance("token").await?;
        ensure!(upgraded_provenance.entries == original_provenance.entries);
        ensure!(upgraded_provenance.effective_artifact.source == ContractArtifactSource::Publication);
        ensure!(upgraded_provenance.effective_artifact.published_sha256 == original_provenance.effective_artifact.sha256);
        ensure!(upgraded_provenance.effective_artifact.sha256 == original_provenance.effective_artifact.sha256);
        ensure!(upgraded_provenance.effective_artifact.execution_definition != original_provenance.effective_artifact.execution_definition);
        ensure!(upgraded_provenance.effective_artifact.protocol_id == Some(hex::encode(target.0)));
        let unaffected = nodes[0].provenance("staking").await?;
        ensure!(unaffected.effective_artifact.source == ContractArtifactSource::Publication);
        ensure!(unaffected.effective_artifact.sha256 == unaffected.effective_artifact.published_sha256);
        let original_activation = activation::current(&nodes[0].observer).await?
            .context("original activation")?;
        let mut third = next;
        third.header.prev_blockhash = third.block_hash();
        third.header.nonce = third.header.nonce.wrapping_add(1);
        broadcast(&nodes, 3, third.clone()).await?;
        let c3 = wait_all(&mut nodes, 3, third.block_hash(), target).await?;
        let mut retained = Vec::new();
        for height in 1..=c3 {
            retained.push(certified_history::load(&nodes[0].observer, height).await?.decision().id()?);
        }
        let initial_context = eras::genesis(&nodes[0].observer).await?;
        let first_era = eras::at(&nodes[0].observer, c2).await?.context("first handoff era")?;
        ensure!(first_era.start_height()? == c2 + 1);

        // The schedule predates the fork, so it survives. Replacing height 1
        // removes activation at H=2 and requires P1 in a fresh consensus era.
        let mut replacement = block;
        replacement.header.nonce = replacement.header.nonce.wrapping_add(10);
        broadcast(&nodes, 1, replacement.clone()).await?;
        let c4 = wait_all(&mut nodes, 1, replacement.block_hash(), first).await?;
        let restored_preview = check_client_context(&nodes[0], 1, replacement.block_hash(), first).await?;
        ensure!(restored_preview["rollback_generation"] != p1_preview["rollback_generation"]);
        let restored_era = eras::at(&nodes[0].observer, c4).await?.context("restored P1 era")?;
        ensure!(restored_era.start_height()? == c4 + 1);
        ensure!(restored_era.next != initial_context && restored_era.next.protocol == first);
        for node in &nodes {
            ensure!(activation::current(&node.observer).await?.is_none(), "orphaned activation survived");
            ensure!(node.view().await?.get("Err").is_some(), "reader retained P2 after rollback");
            ensure!(node.provenance("token").await? == original_provenance, "rollback retained P2 provenance");
        }
        replacement.header.prev_blockhash = replacement.block_hash();
        replacement.header.nonce = replacement.header.nonce.wrapping_add(1);
        broadcast(&nodes, 2, replacement.clone()).await?;
        let c5 = wait_all(&mut nodes, 2, replacement.block_hash(), target).await?;
        let reapplied_preview = check_client_context(&nodes[0], 2, replacement.block_hash(), target).await?;
        ensure!(reapplied_preview["lineage"] != p2_preview["lineage"]);
        let reapplied = activation::current(&nodes[0].observer).await?.context("reapplied activation")?;
        ensure!(reapplied.application.migration_key()? != original_activation.application.migration_key()?,
            "replacement branch reused old migration receipt");
        replacement.header.prev_blockhash = replacement.block_hash();
        replacement.header.nonce = replacement.header.nonce.wrapping_add(1);
        broadcast(&nodes, 3, replacement.clone()).await?;
        let c6 = wait_all(&mut nodes, 3, replacement.block_hash(), target).await?;
        let expected = completion::completed(&nodes[0].observer, c6).await?;
        let expected_state = state(&nodes[0].observer).await?;
        let expected_era = eras::at(&nodes[0].observer, c5).await?.context("second P2 era")?;
        ensure!(expected_era.start_height()? == c5 + 1 && expected_era.next != first_era.next);
        for node in &mut nodes {
            node.healthy().await?;
            ensure!(completion::completed(&node.observer, c6).await? == expected);
            ensure!(state(&node.observer).await? == expected_state);
            ensure!(eras::at(&node.observer, c5).await? == Some(expected_era.clone()));
            ensure!(activation::current(&node.observer).await? == Some(reapplied.clone()));
            ensure!(node.view().await? == json!({"Ok":"2"}), "reapplied fixture initialization differs");
            ensure!(node.addresses.borrow().as_ref() == Some(&node.listener));
            ensure!(node.provenance("token").await? == upgraded_provenance, "reapplied provenance differs");
            for (index, id) in retained.iter().enumerate() {
                let decision = certified_history::load(&node.observer, index as u64 + 1).await?;
                ensure!(decision.decision().id()? == *id, "reorg rewrote retained certificate history");
                ensure!(decision.input().descriptor().context.protocol == if index as u64 + 1 <= c2 { first } else { target });
            }
            ensure!(certified_history::load(&node.observer, c4).await?.input().descriptor().context.protocol == target);
            ensure!(certified_history::load(&node.observer, c5).await?.input().descriptor().context.protocol == first);
            ensure!(certified_history::load(&node.observer, c6).await?.input().descriptor().context == expected_era.next,
                "final P2 engine did not certify the next decision");
        }
        Ok::<_, Error>(json!({"validators": nodes.len(), "closed_decisions": c6, "block_decisions": [c1, c2, c3, c4, c5, c6],
            "handoff_heights": [c2 + 1, c4 + 1, c5 + 1], "same_listeners": true, "matching_closure_and_state": true,
            "first_protocol": hex::encode(first.0), "second_protocol": hex::encode(target.0),
            "restored_p1_in_fresh_era": true, "reapplied_migration": true, "retained_history_unchanged": true,
            "authorization_test": false,
            "http_rpc_continuity": true, "bitcoin_follower_continuity": true,
            "client_contexts": [p1_preview, p2_preview, restored_preview, reapplied_preview],
            "scope": "seeded surviving schedule; real multi-validator P1/P2/P1/P2 execution and rollback with one continuous Malachite runtime; production HTTP router and Bitcoin follower with fixture Bitcoin RPC and ZMQ publisher",
            "native_provenance": {"publication": original_provenance, "upgraded": upgraded_provenance,
                "restored_on_rollback": true, "unaffected_native_uses_publication": true},
            "state": expected_state}))
    }).await.context("multi-validator upgrade timed out").and_then(|result| result);
    for node in &nodes {
        node.shutdown.cancel();
    }
    let mut cleanup = Ok(());
    for node in &mut nodes {
        if let Err(error) = node.join().await {
            cleanup = Err(error);
        }
    }
    match result {
        Ok(value) => {
            cleanup?;
            Ok(value)
        }
        Err(error) => {
            if let Err(cleanup) = cleanup {
                eprintln!("cleanup also failed: {cleanup:#}");
            }
            Err(error)
        }
    }
}

pub(crate) async fn run_join() -> Result<Value> {
    let keys: Vec<_> = (0..4)
        .map(|index| keygen::derive_validator(&[0x74; 32], index))
        .collect();
    let genesis = GenesisParameters {
        sigma_min: Decimal::from("1"),
        validators: keys
            .iter()
            .map(|key| GenesisValidator {
                x_only_pubkey: hex::encode(key.x_only_pubkey),
                ed25519_pubkey: key.ed25519_pubkey.to_vec(),
                stake: Decimal::from("100"),
            })
            .collect(),
    };
    let mut nodes = Vec::<Node>::new();
    let result = timeout(Duration::from_secs(180), async {
        for key in keys.iter().take(3) {
            let peers = nodes
                .first()
                .map(|node| vec![node.listener.clone()])
                .unwrap_or_default();
            nodes.push(
                Node::start(
                    PrivateKey::from(key.ed25519_private),
                    genesis.clone(),
                    peers,
                    ValidatorStart::Bootstrap,
                )
                .await?,
            );
            nodes
                .last_mut()
                .context("initial validator")?
                .ready()
                .await?;
        }
        let first = nodes[0].first;
        let target = nodes[0].target;
        let mut block = genesis_block(NETWORK);
        broadcast(&nodes, 1, block.clone()).await?;
        wait_all(&mut nodes, 1, block.block_hash(), first).await?;
        block.header.prev_blockhash = block.block_hash();
        block.header.nonce = block.header.nonce.wrapping_add(1);
        broadcast(&nodes, 2, block.clone()).await?;
        let floor = wait_all(&mut nodes, 2, block.block_hash(), target).await?;
        // Two of four members cannot certify new work. Offer H+1 before the
        // fourth member joins so its later vote restores a genuinely absent quorum.
        nodes[0].shutdown.cancel();
        nodes[0].join().await?;
        let mut pending = block.clone();
        pending.header.prev_blockhash = block.block_hash();
        pending.header.nonce = pending.header.nonce.wrapping_add(1);
        broadcast(&nodes[1..], 3, pending.clone()).await?;
        for node in &mut nodes[1..] {
            node.services.progress().await?;
        }
        match timeout(
            Duration::from_secs(3),
            wait_all(&mut nodes[1..], 3, pending.block_hash(), target),
        )
        .await
        {
            Err(_) => {}
            Ok(Err(error)) => return Err(error),
            Ok(Ok(_)) => return Err(anyhow!("two of four members certified H+1")),
        }
        let peers = nodes[1..]
            .iter()
            .map(|node| node.listener.clone())
            .collect();
        nodes.push(
            Node::start(
                PrivateKey::from(keys[3].ed25519_private),
                genesis,
                peers,
                ValidatorStart::Join {
                    minimum_closed_height: NonZeroU64::new(floor).context("join floor")?,
                },
            )
            .await?,
        );
        nodes[3].ready().await?;
        wait_all(&mut nodes[1..], 2, block.block_hash(), target).await?;
        for height in 1..=floor {
            let original = certified_history::load(&nodes[0].observer, height).await?;
            let joined = certified_history::load(&nodes[3].observer, height).await?;
            ensure!(
                original.decision().id()? == joined.decision().id()?
                    && original.input() == joined.input(),
                "joined history differs"
            );
        }
        nodes[3].services.advance(1, &genesis_block(NETWORK));
        nodes[3].services.advance(2, &block);
        broadcast(&nodes[1..], 3, pending.clone()).await?;
        let decided = wait_all(&mut nodes[1..], 3, pending.block_hash(), target).await?;
        let promoted_status = nodes[3]
            .services
            .runtime(EngineAuthority::Validator)
            .await?;
        ensure!(promoted_status.committee_member && promoted_status.required_join_height.is_none());
        ensure!(
            nodes[3].addresses.borrow().as_ref() == Some(&nodes[3].listener),
            "promotion changed listener"
        );
        nodes[3].shutdown.cancel();
        nodes[3].join().await?;
        let directory = nodes[3]
            .directory
            .as_ref()
            .context("joined node directory")?;
        let context = certified_history::frontier(&nodes[3].observer)
            .await?
            .context
            .context("joined context")?;
        let owner =
            GenerationOwner::open(&directory.path().join("consensus-authority"), context.chain)?;
        let SignerRecovery::Retained(retained) =
            owner.inspect_signer_recovery(keys[3].ed25519_pubkey)?
        else {
            return Err(anyhow!("promoted validator has no signing history"));
        };
        let authorized = retained
            .latest_authorization
            .context("promotion authorization")?;
        ensure!(
            authorized.generation == 2 && authorized.height > floor,
            "promotion did not follow a separate non-signing generation"
        );
        ensure!(
            retained
                .highest_signed_height
                .is_some_and(|height| height >= decided),
            "joining member did not sign the post-promotion decision"
        );
        ensure!(
            directory.path().join("consensus-catchup.wal").exists()
                && directory.path().join("consensus-validator.wal").exists()
        );
        Ok::<_, Error>(json!({"validators": 4, "initial_signers": 3,
            "source_already_p2": true, "verified_floor": floor,
            "stalled_without_quorum": true,
            "signed_decision": decided, "promotion_generation": authorized.generation,
            "same_listener": true, "matching_verified_prefix": true,
            "promoted_runtime": promoted_status,
            "separate_wals": true, "required_promoted_vote": true}))
    })
    .await
    .context("validator join qualification timed out")
    .and_then(|value| value);
    for node in &nodes {
        node.shutdown.cancel();
    }
    let mut cleanup = Ok(());
    for node in &mut nodes {
        if node.task.is_some() {
            if let Err(error) = node.join().await {
                cleanup = Err(error);
            }
        }
    }
    match result {
        Ok(value) => {
            cleanup?;
            Ok(value)
        }
        Err(error) => {
            if let Err(cleanup) = cleanup {
                eprintln!("cleanup also failed: {cleanup:#}");
            }
            Err(error)
        }
    }
}
