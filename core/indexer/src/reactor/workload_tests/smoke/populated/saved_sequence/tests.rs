use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::super::super::hash_file;
use super::super::checkpoint::Checkpoint;
use super::format::{Manifest, Saved};
use super::replay;

fn manifest() -> Value {
    let digest = "a".repeat(64);
    let hash = "0".repeat(64);
    let file = |name: &str| json!({"name":name,"sha256":digest});
    let checkpoint = |name: &str| json!({"before":digest,"state":file(name)});
    json!({
        "schema_version":2,
        "source":{"git_head_log":"head\n","git_status_log":"","embedded_source_commit":"head",
            "rustc_verbose":"compiler","target":"target","profile":"dev","features":[],"core_lockfile_sha256":digest},
        "binary_sha256":digest,
        "population":{"active_validators":4,"replacements":2,"agreements":2,"members_per_agreement":3},
        "mixed":{"transactions":50,"live_keys":257,"new_files":5,"batch_operations":20},
        "bitcoin_version":310000,"anchor_height":101,"anchor_hash":hash,
        "snapshot":file("snapshot.db"),"chain":file("chain.json"),"initial":file("initial.json"),
        "steps":(0..2).map(|ordinal| json!({
            "height":102+ordinal,"hash":hash,"parent":hash,"block":file(&format!("block-{ordinal:03}.bin")),
            "simulations":null,
            "batches":(0..5).map(|index| json!({"anchor_height":101+ordinal,"anchor_hash":hash,
                "transaction_ids":(0..10).map(|tx| format!("{:064x}", ordinal*50+index*10+tx+1)).collect::<Vec<_>>(),
                "checkpoint":checkpoint(&format!("step-{ordinal:03}-batch-{index:03}.json"))})).collect::<Vec<_>>(),
            "checkpoint":checkpoint(&format!("step-{ordinal:03}-block.json"))
        })).collect::<Vec<_>>()
    })
}

fn rejects(value: Value) -> Result<()> {
    ensure!(
        Manifest::parse(&serde_json::to_vec(&value)?).is_err(),
        "accepted malformed sequence"
    );
    Ok(())
}

#[test]
fn workload_sequence_manifest_rejects_ambiguous_and_reordered_work() -> Result<()> {
    let valid = manifest();
    let bytes = serde_json::to_string(&valid)?;
    Manifest::parse(bytes.as_bytes())?;
    for malformed in [
        bytes.replace(
            "\"schema_version\":2",
            "\"schema_version\":2,\"schema_version\":2",
        ),
        bytes.replace(
            "\"profile\":\"dev\"",
            "\"profile\":\"dev\",\"profile\":\"dev\"",
        ),
        bytes.replacen(
            "\"anchor_height\":101",
            "\"anchor_height\":101,\"unknown\":0",
            1,
        ),
        bytes.replacen(
            "\"name\":\"snapshot.db\"",
            "\"name\":\"snapshot.db\",\"name\":\"snapshot.db\"",
            1,
        ),
        bytes.replacen("\"height\":102", "\"height\":102,\"height\":102", 1),
    ] {
        ensure!(Manifest::parse(malformed.as_bytes()).is_err());
    }
    for (pointer, value) in [
        ("/schema_version", json!(1)),
        ("/anchor_height", json!(100)),
        ("/snapshot/name", json!("../snapshot.db")),
        ("/snapshot/sha256", json!("bad")),
        ("/steps/1/height", json!(102)),
        ("/steps/1/parent", json!("1".repeat(64))),
        ("/steps/0/batches/0/anchor_height", json!(102)),
        ("/steps/0/batches/0/anchor_hash", json!("1".repeat(64))),
        (
            "/steps/0/batches/0/checkpoint/before",
            json!("b".repeat(64)),
        ),
        ("/steps/0/checkpoint/before", json!("b".repeat(64))),
        (
            "/steps/1/batches/0/transaction_ids/0",
            valid["steps"][0]["batches"][0]["transaction_ids"][0].clone(),
        ),
        (
            "/steps/0/simulations",
            json!({"name":"simulation-000.json","sha256":"a".repeat(64)}),
        ),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        rejects(changed)?;
    }
    let mut changed = valid.clone();
    changed["steps"].as_array_mut().unwrap().swap(0, 1);
    rejects(changed)?;
    let mut changed = valid.clone();
    changed["steps"][0]["batches"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    rejects(changed)?;
    let mut changed = valid.clone();
    let duplicate = changed["steps"][0]["batches"][0].clone();
    changed["steps"][0]["batches"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    rejects(changed)?;
    let mut changed = valid;
    changed["steps"].as_array_mut().unwrap().pop();
    rejects(changed)?;
    Ok(())
}

#[test]
fn workload_sequence_inventory_and_intermediate_bytes_are_exact() -> Result<()> {
    let directory = TempDir::new()?;
    let original = json!({"state":[1,2,3],"tail":"x".repeat(150_000)});
    let checkpoint = Checkpoint::capture(directory.path(), &original)?;
    let digest = checkpoint.export(directory.path(), "expected.json")?;
    checkpoint.check_file(&directory.path().join("expected.json"))?;
    ensure!(digest == hash_file(&directory.path().join("expected.json"))?);
    ensure!(
        checkpoint
            .export(directory.path(), "expected.json")
            .is_err()
    );
    let mut changed = original;
    changed["state"][1] = json!(4);
    fs::write(
        directory.path().join("expected.json"),
        serde_json::to_vec(&changed)?,
    )?;
    // Even when an altered file is given a matching digest, replay compares bytes.
    ensure!(hash_file(&directory.path().join("expected.json"))? != digest);
    ensure!(
        checkpoint
            .check_file(&directory.path().join("expected.json"))
            .is_err()
    );

    let directory = TempDir::new()?;
    let mut manifest: Manifest = serde_json::from_value(manifest())?;
    let bytes = b"[]";
    for name in manifest.inventory()?.keys() {
        fs::write(directory.path().join(name), bytes)?;
    }
    let digest = hash_file(&directory.path().join("initial.json"))?;
    manifest.snapshot.sha256 = digest.clone();
    manifest.chain.sha256 = digest.clone();
    manifest.initial.sha256 = digest.clone();
    for step in &mut manifest.steps {
        step.block.sha256 = digest.clone();
        step.checkpoint.before = digest.clone();
        step.checkpoint.state.sha256 = digest.clone();
        for batch in &mut step.batches {
            batch.checkpoint.before = digest.clone();
            batch.checkpoint.state.sha256 = digest.clone();
        }
    }
    let path = directory.path().join("manifest.json");
    fs::write(&path, serde_json::to_vec(&manifest)?)?;
    let manifest_digest = hash_file(&path)?;
    Saved::load(&path, &manifest_digest)?;
    ensure!(Saved::load(&path, &"b".repeat(64)).is_err());
    fs::write(directory.path().join("extra"), bytes)?;
    ensure!(Saved::load(&path, &manifest_digest).is_err());
    fs::remove_file(directory.path().join("extra"))?;
    fs::remove_file(directory.path().join("block-001.bin"))?;
    ensure!(Saved::load(&path, &manifest_digest).is_err());
    fs::write(directory.path().join("block-001.bin"), b"tampered")?;
    ensure!(Saved::load(&path, &manifest_digest).is_err());
    Ok(())
}

fn saved_fixture() -> Result<(TempDir, Value)> {
    let source = std::env::var_os("KONTOR_WORKLOAD_SAVED_MANIFEST")
        .context("missing saved sequence manifest")?;
    let digest = std::env::var("KONTOR_WORKLOAD_SAVED_MANIFEST_SHA256")
        .context("missing saved sequence digest")?;
    let saved = Saved::load(Path::new(&source), &digest)?;
    saved.inputs()?;
    let directory = Checkpoint::directory()?;
    for entry in fs::read_dir(&saved.root)? {
        let entry = entry?;
        fs::copy(entry.path(), directory.path().join(entry.file_name()))?;
    }
    Ok((directory, serde_json::to_value(saved.manifest)?))
}

fn save_manifest(directory: &Path, manifest: &Value) -> Result<String> {
    let path = directory.join("manifest.json");
    fs::write(&path, serde_json::to_vec(manifest)?)?;
    hash_file(&path)
}

#[test]
#[ignore = "requires a generated saved sequence and its pinned digest"]
fn workload_saved_sequence_rejects_changed_batch_association() -> Result<()> {
    let (directory, mut manifest) = saved_fixture()?;
    let batch = manifest["steps"][0]["batches"][0]["transaction_ids"]
        .as_array_mut()
        .context("negative control requires batched fixture")?;
    batch.swap(0, 1);
    let digest = save_manifest(directory.path(), &manifest)?;
    let saved = Saved::load(&directory.path().join("manifest.json"), &digest)?;
    let error = saved
        .inputs()
        .err()
        .context("accepted reordered batch transactions")?;
    ensure!(
        error.to_string().contains("batch transaction association"),
        "unexpected rejection: {error:#}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a generated batched sequence and local bitcoind; intermediate checkpoint negative control"]
async fn workload_saved_sequence_rejects_changed_intermediate_state() -> Result<()> {
    let (directory, mut manifest) = saved_fixture()?;
    let state = &manifest["steps"][0]["batches"][0]["checkpoint"]["state"];
    let name = state["name"]
        .as_str()
        .context("negative control requires batched fixture")?;
    let path = directory.path().join(name);
    let mut projection: Value = serde_json::from_slice(&fs::read(&path)?)?;
    projection
        .as_array_mut()
        .context("projection is not an array")?
        .push(json!({"table":"unexpected_intermediate_state","rows":[]}));
    fs::write(&path, serde_json::to_vec(&projection)?)?;
    let digest = hash_file(&path)?;
    manifest["steps"][0]["batches"][0]["checkpoint"]["state"]["sha256"] = json!(digest);
    manifest["steps"][0]["batches"][1]["checkpoint"]["before"] = json!(digest);
    let digest = save_manifest(directory.path(), &manifest)?;
    let saved = Saved::load(&directory.path().join("manifest.json"), &digest)?;
    saved.inputs()?;
    let error = replay::run(saved, &digest)
        .await
        .err()
        .context("accepted changed intermediate state")?;
    ensure!(
        format!("{error:#}").contains("checkpoint byte"),
        "unexpected replay rejection: {error:#}"
    );
    eprintln!("workload_saved_sequence_negative_control={error:#}");
    Ok(())
}
