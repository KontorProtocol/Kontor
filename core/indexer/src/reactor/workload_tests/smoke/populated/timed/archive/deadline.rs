use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Address, Block as BitcoinBlock, BlockHash, Network};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::mpsc;

use super::super::super::super::{
    ANCHOR_HEIGHT, BitcoinProcess, EngineCleanup, Snapshot, apply, database_projection,
    decode_block, reactor, receipts, stop_engine,
};
use super::super::super::batch::BatchProof;
use super::super::super::batch::pending::Pending;
use super::super::super::checkpoint::Checkpoint;
use super::super::super::replay_identity::ReplayIdentity;
use super::format::Saved;
use crate::bitcoin_client::client::RegtestRpc;
use crate::consensus::finality_types::{FINALITY_WINDOW, FinalityEvent, StateEvent};
use crate::database::Writer;
use crate::database::certified_history;
use crate::database::queries::{
    get_transaction_by_txid, get_transaction_execution_usage, select_applicable_exclusions,
    select_latest_consensus_height,
};
use crate::reactor::consensus_state::ObservationChannels;
use crate::reactor::executor::RuntimeExecutor;
use crate::reg_tester::workload_bitcoin;
use crate::runtime::{ComponentCache, Runtime, Storage};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires timed archive and bitcoind; real withheld-batch finality rollback"]
async fn workload_saved_timed_missing_confirmation_rolls_back_at_deadline() -> Result<()> {
    let path =
        std::env::var_os("KONTOR_WORKLOAD_TIMED_MANIFEST").context("timed manifest missing")?;
    let saved = Saved::load(
        Path::new(&path),
        &std::env::var("KONTOR_WORKLOAD_TIMED_MANIFEST_SHA256")?,
    )?;
    let manifest = &saved.manifest;
    let identity = ReplayIdentity::load(
        &saved.root,
        saved.digest.as_deref().context("unsealed archive")?,
        &serde_json::to_value(&manifest.source)?,
        &manifest.binary_sha256,
    )?;
    let inputs = saved.inputs()?;
    let bitcoin_directory = TempDir::new()?;
    let (child, client) = workload_bitcoin(bitcoin_directory.path()).await?;
    let mut bitcoin = BitcoinProcess(child);
    let info: Value = client.call("getnetworkinfo", vec![]).await?;
    ensure!(info["version"].as_u64() == Some(manifest.bitcoin_version));
    for block in &inputs.chain {
        client.submit_workload_block(block).await?;
    }
    ensure!(client.get_block_hash(ANCHOR_HEIGHT).await? == manifest.anchor_hash);
    let first = inputs.blocks.first().context("archive lacks first block")?;
    let raw: BitcoinBlock = deserialize(&first.raw)?;
    let reveals = first
        .reveals
        .get(..10)
        .context("archive lacks first batch")?;
    // Admit each actual signed pair without broadcasting or mining it. The
    // alternative chain must genuinely omit these transactions at the deadline.
    for (index, reveal) in reveals.iter().enumerate() {
        let pair = [
            hex::encode(serialize(&raw.txdata[2 * index + 1])),
            hex::encode(serialize(reveal)),
        ];
        let verdicts = client.test_mempool_accept(&pair).await?;
        ensure!(verdicts.len() == 2 && verdicts.iter().all(|v| v.allowed));
    }
    ensure!(client.get_raw_mempool().await?.is_empty());
    let address = Address::from_script(
        &inputs.chain[0].txdata[0].output[0].script_pubkey,
        Network::Regtest,
    )?;
    let anchor_height = ANCHOR_HEIGHT + 1;
    let hashes = client
        .generate_to_address(FINALITY_WINDOW + 1, &address.to_string())
        .await?;
    let mut parent = manifest.anchor_hash;
    let mut blocks = Vec::new();
    for (index, hash) in hashes.iter().enumerate() {
        let hash = BlockHash::from_str(hash)?;
        let raw = client.get_block(&hash).await?;
        ensure!(raw.txdata.len() == 1);
        let block = decode_block(
            &serialize(&raw),
            ANCHOR_HEIGHT + u64::try_from(index)? + 1,
            hash,
            parent,
        )?;
        ensure!(block.transactions.is_empty());
        parent = hash;
        blocks.push(block);
    }
    let directory = TempDir::new()?;
    let snapshot = Snapshot {
        path: saved.root.join(&manifest.snapshot.name),
        sha256: manifest.snapshot.sha256.clone(),
    };
    snapshot.copy_to(&directory.path().join("deadline.db"))?;
    let writer = Writer::new(directory.path(), "deadline.db").await?;
    let initial: Value = serde_json::from_slice(&saved.bytes(&manifest.initial)?)?;
    ensure!(database_projection(&writer.connection()).await? == initial);
    ensure!(
        select_latest_consensus_height(&writer.connection()).await?
            == Some(manifest.initial_consensus_height)
    );
    let storage = Storage::builder()
        .height(ANCHOR_HEIGHT)
        .conn(writer.connection())
        .build();
    let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
    runtime.network = Network::Regtest;
    let mut cleanup = EngineCleanup::default();
    let engine_directory = TempDir::new_in(directory.path())?;
    let mut trial = reactor(
        runtime,
        client.clone(),
        engine_directory.path(),
        ANCHOR_HEIGHT,
        Some(manifest.anchor_hash),
        true,
        &mut cleanup,
    )
    .await?;
    let (replay_tx, mut replay_rx) = mpsc::channel(1);
    trial.execution.executor = RuntimeExecutor::new(client.clone()).with_replay_tx(replay_tx);
    let (decided_tx, _decided_rx) = mpsc::channel(64);
    let (finality_tx, mut finality_rx) = mpsc::channel(64);
    let (state_tx, mut state_rx) = mpsc::channel(64);
    trial.consensus.observation = Some(ObservationChannels {
        decided_tx,
        finality_tx,
        state_tx,
    });
    // Keep synthetic setup below the invalidated anchor, so rollback retains
    // the archived contracts rather than requiring setup-only writes to replay.
    apply(&mut trial, blocks[0].clone()).await?;
    trial.advance().await?;
    let checkpoints = Checkpoint::directory()?;
    let proof = BatchProof::execute_many(&mut trial, reveals, 0, checkpoints.path()).await?;
    let consensus = select_latest_consensus_height(&trial.db_conn())
        .await?
        .context("batch decision missing")?;
    let deadline = anchor_height + FINALITY_WINDOW;
    let mut planned = first.block.clone();
    planned.height = deadline;
    let confirmations = proof.confirmation_plan(&planned)?;
    let mut pending = Pending::new(anchor_height);
    pending.record(proof, confirmations)?;
    let txids: HashSet<_> = reveals
        .iter()
        .map(|tx| tx.compute_txid().to_string())
        .collect();
    let mut transaction_ids = Vec::new();
    for txid in &txids {
        transaction_ids.push(
            get_transaction_by_txid(&trial.db_conn(), txid)
                .await?
                .context("executed transaction missing")?
                .id,
        );
    }
    for block in &blocks[1..] {
        apply(&mut trial, block.clone()).await?;
        if block.height < deadline {
            trial.advance().await?;
            ensure!(pending.check_block(&trial, block).await?.is_empty());
            ensure!(pending.len() == reveals.len());
            ensure!(
                select_applicable_exclusions(&trial.db_conn())
                    .await?
                    .is_empty()
            );
            ensure!(finality_rx.try_recv().is_err());
        } else {
            let before = database_projection(&trial.db_conn()).await?;
            let error = pending
                .check_block(&trial, block)
                .await
                .err()
                .context("missing deadline confirmations were accepted")?;
            ensure!(error.to_string() == "pending confirmation missing or at wrong position");
            ensure!(pending.len() == reveals.len());
            ensure!(database_projection(&trial.db_conn()).await? == before);
            trial.advance().await?;
        }
    }
    // Replay consumes certified bodies before advance returns, without poller redelivery.
    ensure!(replay_rx.try_recv().is_err());
    let frontier = certified_history::frontier(&trial.db_conn()).await?;
    ensure!(frontier.closed_height == frontier.authenticated_height);
    let events: Vec<_> = std::iter::from_fn(|| finality_rx.try_recv().ok()).collect();
    let [
        FinalityEvent::Rollback {
            from_anchor,
            invalidated_batches,
            missing,
        },
    ] = events.as_slice()
    else {
        bail!("expected exactly one deadline rollback, got {events:?}");
    };
    ensure!(*from_anchor == anchor_height);
    ensure!(invalidated_batches.len() == 1 && invalidated_batches[0].as_u64() == consensus);
    ensure!(missing.len() == 1 && missing[0].consensus_height.as_u64() == consensus);
    ensure!(missing[0].anchor_height == anchor_height);
    ensure!(
        missing[0]
            .txids
            .iter()
            .map(ToString::to_string)
            .collect::<HashSet<_>>()
            == txids
    );
    let states: Vec<_> = std::iter::from_fn(|| state_rx.try_recv().ok()).collect();
    ensure!(states.iter().any(|event| matches!(event,
        StateEvent::RollbackExecuted { to_anchor, .. } if *to_anchor == anchor_height)));
    ensure!(states.iter().any(|event| matches!(event,
        StateEvent::BatchApplied { consensus_height, txid_count: 0, .. }
            if consensus_height.as_u64() == consensus)));
    ensure!((trial.execution.last_height, trial.execution.last_hash) == (deadline, Some(parent)));
    let exclusions = select_applicable_exclusions(&trial.db_conn()).await?;
    ensure!(exclusions.len() == 1 && exclusions.get(&consensus) == Some(&txids));
    for txid in &txids {
        ensure!(
            get_transaction_by_txid(&trial.db_conn(), txid)
                .await?
                .is_none()
        );
    }
    for id in transaction_ids {
        ensure!(
            get_transaction_execution_usage(&trial.db_conn(), id)
                .await?
                .is_none()
        );
    }
    ensure!(
        receipts(&trial.db_conn(), anchor_height)
            .await?
            .iter()
            .all(|row| row.txid.as_ref().is_none_or(|txid| !txids.contains(txid)))
    );
    ensure!(trial.consensus.unfinalized_batches.is_empty());
    let settled = database_projection(&trial.db_conn()).await?;
    trial.advance().await?;
    ensure!(database_projection(&trial.db_conn()).await? == settled);
    ensure!(finality_rx.try_recv().is_err());
    stop_engine(&mut trial).await?;
    bitcoin.0.kill().await?;
    saved.verify()?;
    identity.finish()?;
    eprintln!(
        "workload_missing_confirmation_control={}",
        json!({
            "anchor":anchor_height,"deadline":deadline,"transactions":txids.len(),
            "consensus_height":consensus,"rollback_count":1,"replay_tip":trial.execution.last_height
        })
    );
    Ok(())
}
