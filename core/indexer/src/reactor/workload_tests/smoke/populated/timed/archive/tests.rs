use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use indexer_types::OpWithResult;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::super::super::super::hash_file;
use super::super::super::checkpoint::Checkpoint;
use super::super::Action;
use super::super::run::Settings;
use super::format::{BlockRef, EventRef, FileRef, Manifest, Saved};
use super::replay;
use crate::test_utils::new_mock_block_hash;

fn file(name: &str) -> FileRef {
    FileRef {
        name: name.into(),
        sha256: "a".repeat(64),
    }
}

fn manifest() -> Result<Manifest> {
    let settings: Settings = serde_json::from_value(json!({
        "population":{"active_validators":4,"replacements":2,"agreements":2,"members_per_agreement":3},
        "mixed":{"transactions":50,"live_keys":257,"new_files":5,"batch_operations":20,"simulation_operations":2,"view_concurrency":8},
        "schedule":{"profile":"representative","fresh_backlog":0,"intervals":1}
    }))?;
    let schedule = settings.validate()?;
    let signer = |seed| -> Result<String> {
        Ok(
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[seed; 32])?)
                .x_only_public_key()
                .0
                .to_string(),
        )
    };
    let source = serde_json::from_value(
        json!({"git_head_log":"head\n","git_status_log":"","embedded_source_commit":"head","rustc_verbose":"compiler","target":"target","profile":"dev","features":[],"core_lockfile_sha256":"a".repeat(64)}),
    )?;
    let mut consensus = 13;
    let events = schedule
        .events
        .iter()
        .map(|event| {
            if !matches!(event.action, Action::Simulation { .. }) {
                consensus += 1;
            }
            EventRef {
                event: event.clone(),
                consensus_height: consensus,
                anchor_hash: new_mock_block_hash(101),
                before: "a".repeat(64),
                state: file(&format!("event-{:06}.json", event.ordinal)),
                api_result: if let Action::Simulation { request, .. } = event.action {
                    Some(file(&format!("api-result-{request:06}.json")))
                } else {
                    None
                },
            }
        })
        .collect();
    Ok(Manifest {
        schema_version: 3,
        source,
        binary_sha256: "a".repeat(64),
        settings,
        schedule,
        bitcoin_version: 310000,
        initial_consensus_height: 13,
        anchor_hash: new_mock_block_hash(101),
        canonical_signer: signer(31)?,
        api_signer: signer(32)?,
        snapshot: file("snapshot.db"),
        initial: file("initial.json"),
        chain: file("chain.json"),
        requests: file("api-inputs.json"),
        blocks: vec![BlockRef {
            hash: new_mock_block_hash(102),
            parent: new_mock_block_hash(101),
            input: file("block-000.bin"),
        }],
        events,
    })
}

#[test]
fn workload_timed_archive_rejects_changed_event_envelope() -> Result<()> {
    let original = serde_json::to_value(manifest()?)?;
    manifest()?.inventory()?;
    for case in 0..10 {
        let mut value = original.clone();
        match case {
            0 => {
                value["events"].as_array_mut().unwrap().remove(0);
            }
            1 => {
                value["events"].as_array_mut().unwrap().swap(0, 1);
            }
            2 => value["events"][1] = value["events"][0].clone(),
            3 => value["events"][0]["event"]["at_seconds"] = json!(1),
            4 => value["events"][0]["consensus_height"] = json!(13),
            5 => value["events"][0]["anchor_hash"] = json!(new_mock_block_hash(100)),
            6 => value["events"][1]["before"] = json!("b".repeat(64)),
            7 => value["events"][1]["api_result"] = Value::Null,
            8 => value["blocks"][0]["input"]["name"] = json!("../block.bin"),
            9 => value["api_signer"] = value["canonical_signer"].clone(),
            _ => unreachable!(),
        }
        let changed: Manifest = serde_json::from_value(value)?;
        ensure!(
            changed.inventory().is_err(),
            "accepted event mutation {case}"
        );
    }
    let bytes = serde_json::to_string(&manifest()?)?;
    ensure!(
        serde_json::from_str::<Manifest>(&bytes.replace(
            "\"schema_version\":3",
            "\"schema_version\":3,\"schema_version\":3"
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn workload_timed_archive_requires_complete_immutable_inventory() -> Result<()> {
    let directory = TempDir::new()?;
    let original = manifest()?;
    for name in original.inventory()?.keys() {
        fs::write(directory.path().join(name), b"[]")?;
    }
    let digest = hash_file(&directory.path().join("initial.json"))?;
    let bytes = serde_json::to_string(&original)?.replace(&"a".repeat(64), &digest);
    let path = directory.path().join("manifest.json");
    ensure!(Saved::load(&path, &digest).is_err());
    fs::write(&path, bytes)?;
    let digest = hash_file(&path)?;
    let saved = Saved::load(&path, &digest)?;
    fs::write(directory.path().join("extra"), b"[]")?;
    ensure!(saved.verify().is_err());
    fs::remove_file(directory.path().join("extra"))?;
    fs::write(directory.path().join("event-000000.json"), b"[1]")?;
    ensure!(saved.verify().is_err());
    fs::remove_file(directory.path().join("event-000000.json"))?;
    ensure!(saved.verify().is_err());
    #[cfg(unix)]
    {
        symlink("initial.json", directory.path().join("event-000000.json"))?;
        ensure!(saved.verify().is_err());
    }
    Ok(())
}

pub(super) fn copied_fixture() -> Result<(TempDir, Manifest)> {
    let path =
        std::env::var_os("KONTOR_WORKLOAD_TIMED_MANIFEST").context("timed manifest missing")?;
    let digest = std::env::var("KONTOR_WORKLOAD_TIMED_MANIFEST_SHA256")?;
    let saved = Saved::load(Path::new(&path), &digest)?;
    saved.inputs()?;
    let directory = Checkpoint::directory()?;
    for entry in fs::read_dir(&saved.root)? {
        let entry = entry?;
        fs::copy(entry.path(), directory.path().join(entry.file_name()))?;
    }
    Ok((directory, saved.manifest))
}

pub(super) fn reseal(directory: &Path, manifest: Manifest) -> Result<Saved> {
    let path = directory.join("manifest.json");
    fs::write(&path, serde_json::to_vec(&manifest)?)?;
    let saved = Saved::load(&path, &hash_file(&path)?)?;
    saved.inputs()?;
    Ok(saved)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires generated timed archive and local bitcoind; rehashed runtime checkpoint negative"]
async fn workload_saved_timed_rejects_corrupt_intermediate_checkpoint() -> Result<()> {
    let (directory, mut manifest) = copied_fixture()?;
    ensure!(
        matches!(manifest.events[0].event.action, Action::Batch { .. }),
        "control needs zero-backlog fixture"
    );
    let first = directory.path().join(&manifest.events[0].state.name);
    let mut projection: Value = serde_json::from_slice(&fs::read(&first)?)?;
    projection
        .as_array_mut()
        .context("projection shape")?
        .push(json!({"table":"unexpected_archive_state","rows":[]}));
    let changed = serde_json::to_vec(&projection)?;
    fs::write(&first, &changed)?;
    let changed_digest = hash_file(&first)?;
    let mut previous = manifest.initial.sha256.clone();
    for (ordinal, event) in manifest.events.iter_mut().enumerate() {
        event.before = previous.clone();
        if ordinal == 0
            || (matches!(event.event.action, Action::Simulation { .. })
                && previous == changed_digest)
        {
            // A rolled-back simulation must retain its predecessor, including this
            // deliberate corruption, so the control passes envelope preflight.
            let path = directory.path().join(&event.state.name);
            fs::write(&path, &changed)?;
            event.state.sha256 = changed_digest.clone();
        }
        previous = event.state.sha256.clone();
    }
    let saved = reseal(directory.path(), manifest)?;
    let error = replay::run(saved)
        .await
        .err()
        .context("accepted altered timed checkpoint")?;
    ensure!(
        format!("{error:#}").contains("replay checkpoint 0 differs"),
        "wrong rejection: {error:#}"
    );
    eprintln!("workload_timed_archive_negative={error:#}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires generated timed archive and local bitcoind; rehashed API-only negative"]
async fn workload_saved_timed_rejects_corrupt_api_result() -> Result<()> {
    let (directory, mut manifest) = copied_fixture()?;
    let file = manifest
        .events
        .iter_mut()
        .find_map(|event| event.api_result.as_mut())
        .context("API result missing")?;
    let path = directory.path().join(&file.name);
    let mut results: Vec<OpWithResult> = serde_json::from_slice(&fs::read(&path)?)?;
    match results.first_mut().context("API result empty")? {
        OpWithResult::Materialized {
            result: Some(row), ..
        } => row.value = Some("corrupt archived result".into()),
        _ => anyhow::bail!("control requires materialized result"),
    }
    fs::write(&path, serde_json::to_vec(&results)?)?;
    file.sha256 = hash_file(&path)?;
    let saved = reseal(directory.path(), manifest)?;
    let error = replay::run(saved)
        .await
        .err()
        .context("accepted altered API result")?;
    ensure!(
        format!("{error:#}").contains("saved timed API result differs at request 0"),
        "wrong rejection: {error:#}"
    );
    eprintln!("workload_timed_archive_negative={error:#}");
    Ok(())
}
