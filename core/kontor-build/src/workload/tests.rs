use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::fixture::{Fixture, parse};
use super::model::Money;
use super::{check_reports, manifest, verify};

fn documents() -> Value {
    serde_json::from_str(include_str!("tests/documents.json")).unwrap()
}

fn check(documents: &Value) -> Result<()> {
    check_reports(
        &manifest(&documents[0])?,
        &documents[1],
        &documents[2],
        &documents[3],
    )
}

#[test]
fn frozen_versions_and_nonzero_input_positions() -> Result<()> {
    let mut data = documents();
    check(&data)?;
    data[0]["schema_version"] = json!(2);
    data[0]["execution"]["effective_retain_blocks"] = json!(7);
    data[2]["prune_watermark"] = json!(3);
    check(&data)?;
    for index in 0..3 {
        data[0]["input"]["operations"][index]["input_index"] = json!(4);
        data[2]["receipts"][index]["input_index"] = json!(4);
        data[3]["operations"][index]["input_index"] = json!(4);
    }
    let mut core = data[2]["receipts"][2].clone();
    core["id"] = json!(4);
    for field in ["txid", "tx_index", "input_index", "op_index"] {
        core[field] = Value::Null;
    }
    core["payer_signer_id"] = json!(1);
    core["signer_id"] = json!(1);
    core["contract"] = json!("token_0_0");
    core["func"] = json!("mint-emission");
    data[2]["receipts"].as_array_mut().unwrap().push(core);
    check(&data)
}

#[test]
fn rejects_identity_accounting_and_rollback_mutations() {
    let changes = [
        ("/0/schema_version", json!(true)),
        ("/0/schema_version", json!(2)),
        ("/0/execution/network", json!("mainnet")),
        ("/0/execution/starting_block_height", json!(0)),
        ("/0/execution/starting_block_height", json!(10)),
        ("/0/input/operations/2/op_index", json!(0)),
        ("/0/input/operations/1/tx_index", json!(0)),
        ("/0/input/previous_hash", json!("ff".repeat(32))),
        ("/0/decision/block_hash", json!("ff".repeat(32))),
        ("/2/receipts/0/height", json!(9)),
        ("/2/receipts/0/tx_index", json!(2)),
        ("/2/receipts/1/result_index", json!(1)),
        ("/2/usage/0/tx_index", Value::Null),
        ("/2/usage/0/system_fuel", json!(3001)),
        ("/2/prune_watermark", json!(0)),
        ("/2/contract_views/B/storage_state", json!([1, 0, 1, 0])),
        ("/3/source_commit", json!("b".repeat(40))),
        ("/3/operations/0/gas", json!(true)),
        ("/3/operations/1/deposit_fuel", json!(2001)),
        ("/3/operations/1/reserved_deposit_gas", json!(1)),
        ("/3/operations/1/payer_after", json!("1")),
        ("/3/operations/1/burner_after", json!("0")),
        ("/3/operations/1/floor_after", json!("0")),
        ("/3/operations/1/storage_state", json!([1, 0, 1, 0])),
        ("/3/operations/1/error_message", json!("unrelated failure")),
    ];
    for (path, value) in changes {
        let mut data = documents();
        *data.pointer_mut(path).unwrap() = value;
        assert!(check(&data).is_err(), "{path}");
    }
    for field in ["status", "value"] {
        let mut data = documents();
        let wrong = json!(if field == "status" { "Other" } else { "wrong" });
        data[2]["receipts"][0][field] = wrong.clone();
        data[3]["operations"][0][field] = wrong;
        assert!(check(&data).is_err());
    }
    let mut data = documents();
    data[2]["usage"][0]["user_fuel"] = json!(0);
    for operation in data[3]["operations"].as_array_mut().unwrap() {
        operation["user_fuel"] = json!(0);
    }
    assert!(check(&data).is_err());
    let mut data = documents();
    let mut extra = data[2]["receipts"][2].clone();
    extra["id"] = json!(4);
    extra["op_index"] = json!(3);
    data[2]["receipts"].as_array_mut().unwrap().push(extra);
    assert!(check(&data).is_err());
}

#[test]
fn pruning_keeps_the_unchanged_finalized_live_successor() {
    for scenario in 0..6 {
        let mut data = documents();
        match scenario {
            0 => data[2]["state_versions"] = data[1]["state_versions"].clone(),
            1 => data[2]["state_versions"] = json!([]),
            2 => data[2]["state_versions"][0]["value_hex"] = json!("ff"),
            3 => {
                data[1]["state_versions"][1]["height"] = json!(5);
                data[2]["state_versions"][0]["height"] = json!(5);
            }
            4 => {
                data[1]["state_versions"][0]["height"] = json!(5);
                data[1]["state_versions"][1]["height"] = json!(6);
                data[2]["state_versions"][0]["height"] = json!(6);
            }
            _ => {
                data[1]["state_versions"][1]["deleted"] = json!(true);
                data[2]["state_versions"][0]["deleted"] = json!(true);
            }
        }
        assert!(check(&data).is_err(), "pruning scenario {scenario}");
    }
}

#[test]
fn closed_records_and_exact_amounts() -> Result<()> {
    assert_eq!(
        Money::try_from("0.000000000000000001".to_owned())?
            .units
            .to_string(),
        "1"
    );
    for bad in [
        "-1",
        "01",
        "1.0",
        "1e-9",
        "0.0000000000000000001",
        "NaN",
        "1.",
    ] {
        assert!(Money::try_from(bad.to_owned()).is_err(), "{bad}");
    }
    assert!(Money::try_from("9".repeat(78)).is_err());
    for path in [
        "/2/receipts/0",
        "/3/operations/0",
        "/0/decision",
        "/0/source",
    ] {
        let baseline = documents();
        for key in baseline.pointer(path).unwrap().as_object().unwrap().keys() {
            let mut data = baseline.clone();
            data.pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(check(&data).is_err(), "missing {path}/{key}");
        }
        let mut data = baseline;
        data.pointer_mut(path).unwrap()["ignored"] = json!(0);
        assert!(check(&data).is_err(), "unknown {path}");
    }
    for bytes in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":{"x":1,"x":2}}"#,
        br#"[1.0]"#,
        br#"[1e0]"#,
        b"[NaN]",
        b"[Infinity]",
        b"\xff",
        b"{} {}",
    ] {
        assert!(parse(bytes).is_err(), "{bytes:?}");
    }
    Ok(())
}

fn write_reference(root: &Path, reference: &mut Value, bytes: &[u8]) -> Result<()> {
    fs::write(root.join(reference["path"].as_str().unwrap()), bytes)?;
    reference["sha256"] = json!(hex::encode(Sha256::digest(bytes)));
    Ok(())
}

fn frozen_files(root: &Path) -> Result<Value> {
    let mut data = documents();
    for path in [
        "/snapshot/database",
        "/input/raw_block",
        "/source/core_lockfile",
        "/input/bitcoin_validation/record",
        "/execution/lifecycle_parameters",
    ] {
        write_reference(root, data[0].pointer_mut(path).unwrap(), b"{}")?;
    }
    for artifact in data[0]["artifacts"].as_array_mut().unwrap() {
        write_reference(root, &mut artifact["compressed"], b"synthetic artifact")?;
    }
    data[3]["snapshot_sha256"] = data[0]["snapshot"]["database"]["sha256"].clone();
    data[3]["raw_block_sha256"] = data[0]["input"]["raw_block"]["sha256"].clone();
    for (index, path) in [
        (1, "/snapshot/reset_report"),
        (2, "/expected_report"),
        (3, "/numeric_check"),
    ] {
        let bytes = serde_json::to_vec(&data[index])?;
        write_reference(root, data[0].pointer_mut(path).unwrap(), &bytes)?;
    }
    Ok(data)
}

#[test]
fn file_identity_containment_and_same_bytes_validation() -> Result<()> {
    let dir = tempdir()?;
    let data = frozen_files(dir.path())?;
    let path = dir.path().join("manifest.json");
    let mut bytes = serde_json::to_vec_pretty(&data[0])?;
    bytes.push(b'\n');
    fs::write(&path, &bytes)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let result = verify(&path, &digest)?;
    assert_eq!(result.manifest, data[0]);
    assert_eq!(result.before, data[1]);
    assert_eq!(result.after, data[2]);
    assert_eq!(result.numeric, data[3]);
    assert_eq!(result.manifest_sha256, digest);
    assert!(verify(&path, &"0".repeat(64)).is_err());
    let reader = Fixture::open(&path)?;
    for bad in [
        "../outside",
        "/absolute",
        "x//y",
        "./numeric.json",
        "x/../numeric.json",
        "x\\y",
        "x\0y",
    ] {
        let reference = json!({"path":bad,"sha256":data[0]["numeric_check"]["sha256"]});
        assert!(reader.verify_references(&reference).is_err(), "{bad}");
    }
    fs::write(dir.path().join("numeric.json"), b"{}")?;
    assert!(verify(&path, &digest).is_err());
    Ok(())
}

fn candidate_files(root: &Path) -> Result<()> {
    let data = frozen_files(root)?;
    let manifest = &data[0];
    for (from, to) in [
        ("before.json", "before-report.json"),
        ("after.json", "trial-one.db-report.json"),
        ("after.json", "trial-two.db-report.json"),
        ("numeric.json", "numeric-check.json"),
        ("lifecycle.json", "lifecycle-parameters.json"),
    ] {
        fs::copy(root.join(from), root.join(to))?;
    }
    for name in [
        "trial-one.db-projection.json",
        "trial-two.db-projection.json",
    ] {
        fs::write(root.join(name), b"{}")?;
    }
    let lock=b"[[package]]\nname = \"wasmtime\"\nsource = \"git+https://example.invalid/wasmtime#0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7\"\n";
    fs::write(root.join("Cargo.lock"), lock)?;
    let mut source = manifest["source"].clone();
    source["git_status_log"] = json!("");
    source["git_head_log"] = json!(format!(
        "{}\n",
        manifest["source"]["kontor_commit"].as_str().unwrap()
    ));
    source["embedded_source_commit"] = manifest["source"]["kontor_commit"].clone();
    source["core_lockfile_sha256"] = json!(hex::encode(Sha256::digest(lock)));
    let candidate = json!({
        "replays":2,"frozen_acceptance":false,"source_commit":manifest["source"]["kontor_commit"],
        "raw_block_sha256":manifest["input"]["raw_block"]["sha256"],"snapshot_sha256":manifest["snapshot"]["database"]["sha256"],
        "raw_txids":manifest["input"]["raw_txids"],"contracts":["smokea_2_0","smokeb_2_1"],"funding_seed_hex":manifest["funding_seed_hex"],
        "schema_sha256":manifest["snapshot"]["schema_sha256"],"anchor_height":9,"anchor_hash":manifest["snapshot"]["anchor_hash"],
        "block_height":10,"block_hash":manifest["input"]["block_hash"],"payer_x_only_pubkey":manifest["input"]["payer_x_only_pubkey"],
        "starting_block_height":1,"next_consensus_height":10
    });
    for (name, value) in [
        ("candidate.json", candidate),
        ("source.json", source),
        ("artifacts.json", manifest["artifacts"].clone()),
        (
            "bitcoin-validation.json",
            manifest["input"]["bitcoin_validation"].clone(),
        ),
    ] {
        fs::write(root.join(name), serde_json::to_vec(&value)?)?;
    }
    Ok(())
}

#[test]
fn candidate_assembly_preserves_existing_files_and_cleans_failed_candidates() -> Result<()> {
    let dir = tempdir()?;
    candidate_files(dir.path())?;
    let result = super::assemble(dir.path())?;
    let output = dir.path().join("candidate-manifest.json");
    let original = fs::read(&output)?;
    assert_eq!(result["frozen_acceptance"], false);
    verify(&output, result["sha256"].as_str().unwrap())?;
    assert!(super::assemble(dir.path()).is_err());
    assert_eq!(fs::read(&output)?, original);
    fs::remove_file(&output)?;
    fs::write(dir.path().join("numeric-check.json"), b"{}")?;
    assert!(super::assemble(dir.path()).is_err());
    assert!(!output.exists());
    candidate_files(dir.path())?;
    fs::write(dir.path().join("trial-two.db-report.json"), b"{}")?;
    assert!(super::assemble(dir.path()).is_err());
    assert!(!output.exists());
    candidate_files(dir.path())?;
    fs::write(dir.path().join("Cargo.lock"), b"version = 4\n")?;
    let source_path = dir.path().join("source.json");
    let mut source: Value = serde_json::from_slice(&fs::read(&source_path)?)?;
    source["core_lockfile_sha256"] = json!(hex::encode(Sha256::digest(b"version = 4\n")));
    fs::write(source_path, serde_json::to_vec(&source)?)?;
    assert!(super::assemble(dir.path()).is_err());
    assert!(!output.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn fixture_references_reject_symlink_escape() -> Result<()> {
    let dir = tempdir()?;
    let outside = tempdir()?;
    fs::write(dir.path().join("manifest.json"), b"{}")?;
    fs::write(outside.path().join("data"), b"{}")?;
    symlink(outside.path(), dir.path().join("escape"))?;
    let reader = Fixture::open(&dir.path().join("manifest.json"))?;
    let reference = json!({"path":"escape/data","sha256":hex::encode(Sha256::digest(b"{}"))});
    assert!(reader.verify_references(&reference).is_err());
    Ok(())
}
