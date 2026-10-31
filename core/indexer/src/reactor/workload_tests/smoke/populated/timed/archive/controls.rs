use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use bitcoin::consensus::serialize;
use indexer_types::{Inst, InstKind};
use serde_json::json;
use tempfile::TempDir;
use tokio::process::Command;

use super::super::super::super::{BitcoinProcess, capture, checked_signed_instructions, hash_file};
use super::format::{EncodedRequest, Manifest, Saved};
use super::tests::{copied_fixture, reseal};
use crate::block::filter_map;
use crate::bls::taproot_derivation_path;
use crate::reg_tester::{derive_taproot_keypair_from_seed, workload_bitcoin};
use crate::runtime::filestorage::address as filestorage_address;

fn original() -> Result<Saved> {
    let path =
        std::env::var_os("KONTOR_WORKLOAD_TIMED_MANIFEST").context("timed manifest missing")?;
    Saved::load(
        Path::new(&path),
        &std::env::var("KONTOR_WORKLOAD_TIMED_MANIFEST_SHA256")?,
    )
}

fn save_requests(
    directory: &Path,
    manifest: &mut Manifest,
    inputs: &[EncodedRequest],
) -> Result<()> {
    let path = directory.join(&manifest.requests.name);
    fs::write(&path, serde_json::to_vec(inputs)?)?;
    manifest.requests.sha256 = hash_file(&path)?;
    Ok(())
}

async fn reject_association(saved: Saved, request: usize) -> Result<()> {
    let source = capture::source()?;
    let binary = std::env::current_exe()?;
    let binary_digest = hash_file(&binary)?;
    let run_directory = TempDir::new()?;
    let run = run_directory.path().join("run.json");
    fs::write(
        &run,
        serde_json::to_vec(&json!({
            "schema_version":1,
            "fixture_manifest_sha256":saved.digest,
            "expected_consumer_source":source,
            "expected_consumer_binary_sha256":binary_digest,
            "run_label":"deliberately corrupted input control, no compatibility qualification"
        }))?,
    )?;
    // A separate consumer binds the altered fixture digest explicitly, allowing
    // controls to reuse an older producer without bypassing identity checks.
    let output = Command::new(&binary)
        .args([
            "--exact",
            "reactor::workload_tests::smoke::populated::timed::archive::workload_saved_timed_events_replay",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("KONTOR_WORKLOAD_TIMED_MANIFEST", saved.root.join("manifest.json"))
        .env("KONTOR_WORKLOAD_TIMED_MANIFEST_SHA256", saved.digest.as_deref().context("unsealed control")?)
        .env("KONTOR_WORKLOAD_REPLAY_RUN", &run)
        .env("KONTOR_WORKLOAD_REPLAY_RUN_SHA256", hash_file(&run)?)
        .kill_on_drop(true)
        .output()
        .await?;
    let transcript = format!(
        "{}{}",
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?
    );
    ensure!(
        output.status.code() == Some(101)
            && transcript.contains("workload_saved_timed_bitcoin_admitted=true")
            && transcript.contains(&format!(
                "saved timed API instruction association differs at request {request}"
            ))
            && !transcript.contains("workload_saved_timed_execution_started="),
        "wrong input-control rejection: {transcript}"
    );
    saved.verify()?;
    ensure!(capture::source()? == source && hash_file(&binary)? == binary_digest);
    eprintln!("workload_timed_input_control={transcript}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires timed archive and bitcoind; signed occurrence-association negative"]
async fn workload_saved_timed_rejects_reassociated_api_inputs() -> Result<()> {
    let original = original()?;
    let (directory, mut manifest) = copied_fixture()?;
    let inputs = original.inputs()?;
    let operations = inputs
        .requests
        .iter()
        .map(|input| {
            Ok(filter_map((0, input.reveal.clone()))
                .context("API input missing")?
                .inputs[0]
                .insts
                .ops
                .clone())
        })
        .collect::<Result<Vec<_>>>()?;
    let other = operations
        .iter()
        .position(|ops| *ops != operations[0])
        .context("fixture lacks distinct API instruction vectors")?;
    let mut encoded: Vec<EncodedRequest> =
        serde_json::from_slice(&fs::read(directory.path().join(&manifest.requests.name))?)?;
    encoded.swap(0, other);
    encoded[0].ordinal = 0;
    encoded[other].ordinal = other;
    save_requests(directory.path(), &mut manifest, &encoded)?;
    reject_association(reseal(directory.path(), manifest)?, 0).await?;
    original.verify()?;
    let path = directory.path().to_path_buf();
    directory.close()?;
    ensure!(!path.exists());
    Ok(())
}

fn registration_id(instruction: &Inst) -> Option<&str> {
    let InstKind::Call { contract, expr } = &instruction.kind else {
        return None;
    };
    if *contract != filestorage_address() || !expr.starts_with("create-agreement(") {
        return None;
    }
    // These generated fixture IDs are unescaped hex strings, not arbitrary WAVE.
    expr.split_once("file-id: \"")?.1.split('"').next()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires timed archive and bitcoind; signed canonical-file substitution negative"]
async fn workload_saved_timed_rejects_canonical_file_in_api() -> Result<()> {
    let original = original()?;
    let inputs = original.inputs()?;
    let canonical = inputs
        .blocks
        .iter()
        .flat_map(|block| &block.block.transactions)
        .flat_map(|tx| &tx.inputs)
        .flat_map(|input| &input.insts.ops)
        .find(|inst| registration_id(inst).is_some())
        .context("canonical registration missing")?
        .clone();
    let canonical_id = registration_id(&canonical).context("canonical file ID missing")?;
    let mut selected = None;
    for (request, input) in inputs.requests.iter().enumerate() {
        let decoded = filter_map((0, input.reveal.clone())).context("API input missing")?;
        let mut ops = decoded.inputs[0].insts.ops.clone();
        if let Some(position) = ops.iter().position(|inst| registration_id(inst).is_some()) {
            ensure!(registration_id(&ops[position]) != Some(canonical_id));
            ops[position] = canonical.clone();
            selected = Some((request, ops));
            break;
        }
    }
    let (request, ops) = selected.context("API registration missing")?;
    let funding = inputs.requests[request].commit.input[0].previous_output;
    let output = inputs
        .chain
        .iter()
        .flat_map(|block| &block.txdata)
        .find(|tx| tx.compute_txid() == funding.txid)
        .context("API funding transaction missing")?
        .output
        .get(usize::try_from(funding.vout)?)
        .context("API funding output missing")?
        .clone();
    let bitcoin_directory = TempDir::new()?;
    let (child, client) = workload_bitcoin(bitcoin_directory.path()).await?;
    let mut bitcoin = BitcoinProcess(child);
    for block in &inputs.chain {
        client.submit_workload_block(block).await?;
    }
    let key =
        derive_taproot_keypair_from_seed(&[99; 64], &taproot_derivation_path(Network::Regtest))?;
    ensure!(key.x_only_public_key().0.to_string() == original.manifest.api_signer);
    let (commit, reveal, _) =
        checked_signed_instructions(&client, &key, (funding, output), ops).await?;
    ensure!(commit.input[0].previous_output == funding);
    bitcoin.0.kill().await?;
    let (directory, mut manifest) = copied_fixture()?;
    let mut encoded: Vec<EncodedRequest> =
        serde_json::from_slice(&fs::read(directory.path().join(&manifest.requests.name))?)?;
    encoded[request].commit = hex::encode(serialize(&commit));
    encoded[request].reveal = hex::encode(serialize(&reveal));
    save_requests(directory.path(), &mut manifest, &encoded)?;
    reject_association(reseal(directory.path(), manifest)?, request).await?;
    original.verify()?;
    let path = directory.path().to_path_buf();
    directory.close()?;
    ensure!(!path.exists());
    Ok(())
}
