use std::env;
use std::fs;
use std::future::pending;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Error, Result, ensure};
use bitcoin::blockdata::constants::genesis_block;
use libsql::Connection;
use malachitebft_app_channel::AppMsg;
use malachitebft_core_types::Round;
use serde_json::{Value as Json, json};
use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

use super::fixture::{genesis, open, seed, snapshot};
use super::{DATABASE, NETWORK};
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Height, ProposalData, Value};
use crate::database::certified_history::{self, activation, completion};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::durable_signer::SigningError;
use crate::protocol_qualification::snapshot::full_state;
use crate::reactor::certified::qualification::fixture::issuance_transaction;
use crate::reactor::consensus_state::certified_startup;
use crate::reactor::engine::{EngineConfig, NodeCoordinator};
use crate::reactor::execution::ExecutionStep;
use crate::reactor::message::Message;
use crate::reactor::transport::Engine;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

pub(super) const STAGES: [&str; 5] = ["certified", "activated", "closed", "engine-ready", "signed"];

pub(super) fn configuration(path: &Path) -> EngineConfig {
    EngineConfig {
        private_key: PrivateKey::from([7; 32]),
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        persistent_peers: vec![],
        data_dir: path.to_path_buf(),
        consensus_enabled: true,
        discovery: Default::default(),
    }
}

async fn ready(engine: &mut Engine) -> Result<(String, Message)> {
    let message = timeout(Duration::from_secs(20), engine.next())
        .await
        .context("engine readiness timeout")??;
    let message = message.context("engine stopped before readiness")?;
    ensure!(
        matches!(
            &message,
            Message::Application(AppMsg::ConsensusReady { .. })
        ),
        "engine did not reach readiness"
    );
    Ok((
        engine
            .listen_address()
            .await?
            .context("engine listener missing")?,
        message,
    ))
}

async fn proposal(conn: &Connection, conflicting: bool) -> Result<ProposalData> {
    let (context, height, _) = certified_startup(conn).await?;
    ensure!(height == Height::new(2));
    let transactions = if conflicting {
        vec![issuance_transaction()?]
    } else {
        vec![]
    };
    Ok(ProposalData::new(Value::from_input(ExactInput::batch(
        context,
        1,
        genesis_block(NETWORK).block_hash(),
        &transactions,
    )?)?))
}

async fn sign(engine: &mut Engine, proposal: &ProposalData) -> Result<String> {
    let signature = engine
        .sign_proposal_fin(
            2,
            0,
            proposal.value().descriptor_bytes().to_vec(),
            proposal.signing_digest(Height::new(2), Round::new(0)),
        )
        .await?;
    Ok(hex::encode(signature.to_bytes()))
}

async fn park(path: &Path, observation: Json) -> Result<()> {
    fs::write(
        path.join("crash-ready.tmp"),
        serde_json::to_vec(&observation)?,
    )?;
    fs::rename(path.join("crash-ready.tmp"), path.join("crash-ready.json"))?;
    pending().await
}

pub(crate) async fn child(path: &Path, stage: &str) -> Result<()> {
    ensure!(STAGES.contains(&stage), "unknown crash checkpoint");
    let service = OwnerService::new();
    let mut execution = open(path, &service).await?;
    if stage == "certified" {
        return park(path, json!({"stage": stage})).await;
    }
    if stage == "activated" {
        let cancelled = Shutdown::new();
        cancelled.cancel();
        ensure!(!execution.recover(&cancelled.signal()).await?);
        for _ in 0..16 {
            if matches!(
                execution.step_certified_closure(1).await?,
                ExecutionStep::Activation
            ) {
                ensure!(activation::current(&execution.db_conn()).await?.is_some());
                ensure!(
                    certified_history::frontier(&execution.db_conn())
                        .await?
                        .closed_height
                        == 0
                );
                return park(path, json!({"stage": stage})).await;
            }
        }
        anyhow::bail!("activation checkpoint not reached");
    }
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    if stage == "closed" {
        return park(path, json!({"stage": stage})).await;
    }
    let config = configuration(path);
    let (coordinator, _reader, _writer) =
        NodeCoordinator::open_database(&config, DATABASE, NETWORK, 1, &genesis()).await?;
    let mut output = coordinator.start(&config, &execution.db_conn()).await?;
    let (listener, _ready) = ready(&mut output.engine).await?;
    let (context, _, _) = certified_startup(&execution.db_conn()).await?;
    ensure!(
        path.join(format!("consensus-{}.wal", hex::encode(context.era)))
            .exists()
    );
    // Keep ConsensusReady unanswered so no unsolicited proposal races this
    // first proposal-Fin signature through the production managed transport.
    let signature = if stage == "signed" {
        Some(
            sign(
                &mut output.engine,
                &proposal(&execution.db_conn(), false).await?,
            )
            .await?,
        )
    } else {
        None
    };
    park(
        path,
        json!({"stage": stage, "listener": listener, "signature": signature}),
    )
    .await
}

pub(super) async fn run(service: &OwnerService) -> Result<Json> {
    let mut results = Vec::new();
    for stage in STAGES {
        let directory = TempDir::new()?;
        let reference_directory = TempDir::new()?;
        let target = seed(directory.path(), service, 1).await?;
        let (expected, closure, certificate, decision) = {
            let seeded = open(directory.path(), service).await?;
            snapshot(&seeded.db_conn(), reference_directory.path()).await?;
            drop(seeded);
            let mut reference = open(reference_directory.path(), service).await?;
            ensure!(reference.recover(&Shutdown::new().signal()).await?);
            let conn = reference.db_conn();
            let retained = certified_history::load(&conn, 1).await?;
            (
                full_state(&conn).await?,
                completion::completed(&conn, 1).await?,
                retained.proof().to_vec(),
                retained.decision().id()?,
            )
        };
        let log = fs::File::create(directory.path().join("child.log"))?;
        let mut child = Command::new(env::current_exe()?)
            .arg("qualify-transition-crash")
            .arg(directory.path())
            .arg(stage)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()?;
        timeout(Duration::from_secs(45), async {
            while !directory.path().join("crash-ready.json").exists() {
                ensure!(
                    child.try_wait()?.is_none(),
                    "crash child exited before {stage}: {}",
                    fs::read_to_string(directory.path().join("child.log"))?
                );
                sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, Error>(())
        })
        .await
        .context("child did not reach crash checkpoint")??;
        child.kill().await?;
        ensure!(!child.wait().await?.success(), "child exited cleanly");
        let marker: Json =
            serde_json::from_slice(&fs::read(directory.path().join("crash-ready.json"))?)?;
        ensure!(marker["stage"] == stage);
        let mut recovered = open(directory.path(), service).await?;
        ensure!(recovered.recover(&Shutdown::new().signal()).await?);
        let conn = recovered.db_conn();
        ensure!(
            full_state(&conn).await? == expected,
            "state differs after crash at {stage}"
        );
        ensure!(completion::completed(&conn, 1).await? == closure);
        let retained = certified_history::load(&conn, 1).await?;
        ensure!(retained.proof() == certificate && retained.decision().id()? == decision);
        let (context, height, _) = certified_startup(&conn).await?;
        ensure!(context.protocol == target && height == Height::new(2));
        let mut config = configuration(directory.path());
        if let Some(listener) = marker["listener"].as_str() {
            config.listen_addr = listener.into();
        }
        let (coordinator, _reader, _writer) =
            NodeCoordinator::open_database(&config, DATABASE, NETWORK, 1, &genesis()).await?;
        let mut output = coordinator.start(&config, &conn).await?;
        let (listener, _ready) = ready(&mut output.engine).await?;
        if let Some(previous) = marker["listener"].as_str() {
            ensure!(listener == previous);
        }
        let exact = proposal(&conn, false).await?;
        let signature = sign(&mut output.engine, &exact).await?;
        if stage == "signed" {
            ensure!(
                marker["signature"].as_str() == Some(signature.as_str()),
                "signature retry changed after process crash"
            );
        }
        let error = sign(&mut output.engine, &proposal(&conn, true).await?)
            .await
            .err()
            .context("conflicting signature accepted")?;
        ensure!(
            error.downcast_ref::<SigningError>() == Some(&SigningError::Conflict),
            "unexpected signing rejection: {error:#}"
        );
        ensure!(output.engine.stop(Duration::from_secs(10)).await?);
        ensure!(service.active_roots().await == 0);
        results.push(
            json!({"stage": stage, "process_killed": true, "state_matches": true,
            "certificate_preserved": true, "successor_started": true,
            "signature_retry_preserved": stage == "signed", "conflict_rejected": true}),
        );
    }
    Ok(json!(results))
}
