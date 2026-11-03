use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::fixture::{Fixture, parse};
use super::load;
use crate::container::sha256;

/// Assemble an unapproved candidate without replacing a reviewed manifest.
pub fn assemble(directory: &Path) -> Result<Value> {
    let root = directory.canonicalize()?;
    let read = |name: &str| -> Result<Value> { parse(&fs::read(root.join(name))?) };
    let reference = |name: &str| -> Result<Value> {
        Ok(json!({"path":name,"sha256":sha256(&root.join(name))?}))
    };
    let candidate = read("candidate.json")?;
    let source = read("source.json")?;
    let retention = candidate
        .get("effective_retain_blocks")
        .cloned()
        .unwrap_or(json!(6));
    ensure!(
        matches!(retention.as_u64(), Some(6 | 7)),
        "unsupported candidate retention"
    );
    let before = read("before-report.json")?;
    ensure!(
        read("trial-one.db-report.json")? == read("trial-two.db-report.json")?,
        "candidate replay reports differ"
    );
    ensure!(
        read("trial-one.db-projection.json")? == read("trial-two.db-projection.json")?,
        "candidate replay database projections differ"
    );
    ensure!(
        candidate["replays"] == 2 && candidate["frozen_acceptance"] == false,
        "expected an unapproved two-replay development candidate"
    );
    ensure!(
        source["git_status_log"] == ""
            && source["git_head_log"]
                .as_str()
                .context("source git head")?
                .trim()
                == source["embedded_source_commit"]
                    .as_str()
                    .context("embedded commit")?
            && source["embedded_source_commit"] == candidate["source_commit"],
        "candidate source differs"
    );
    let lockfile = reference("Cargo.lock")?;
    ensure!(
        lockfile["sha256"] == source["core_lockfile_sha256"],
        "candidate lockfile differs"
    );
    let lock: toml::Value = toml::from_str(&fs::read_to_string(root.join("Cargo.lock"))?)?;
    let packages: Vec<_> = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .context("lockfile packages")?
        .iter()
        .filter(|p| p.get("name").and_then(toml::Value::as_str) == Some("wasmtime"))
        .collect();
    ensure!(packages.len() == 1, "expected one Wasmtime package");
    let revision = packages[0]
        .get("source")
        .and_then(toml::Value::as_str)
        .context("Wasmtime source")?
        .rsplit('#')
        .next()
        .unwrap();
    let bitcoin = read("bitcoin-validation.json")?;
    let raw_block = reference("block.bin")?;
    let snapshot = reference("snapshot.db")?;
    ensure!(
        raw_block["sha256"] == candidate["raw_block_sha256"]
            && snapshot["sha256"] == candidate["snapshot_sha256"],
        "candidate input identity differs"
    );
    let txid = &candidate["raw_txids"][2];
    let operations:Vec<_>=["write-result-payload(1)","scan-compound(false)","write-result-payload(2)"].into_iter().enumerate().map(|(i,expression)|json!({
        "txid":txid,"tx_index":2,"input_index":0,"op_index":i,
        "contract":candidate["contracts"][usize::from(i==1)],"expression":expression,"gas_limit":100000
    })).collect();
    let mut manifest = json!({
        "schema_version":if retention==7 {2} else {1},"kind":"smoke","case_id":"paid-success-failure-success-v1",
        "funding_seed_hex":candidate["funding_seed_hex"],
        "source":{
            "kontor_commit":candidate["source_commit"],"rustc_verbose":source["rustc_verbose"],"target":source["target"],
            "profile":source["profile"],"features":source["features"],"core_lockfile":lockfile,"wasmtime_revision":revision,
            "engine":"pulley","pulley_stack_bytes":524288,"native_fiber_bytes":2097152
        },
        "artifacts":read("artifacts.json")?,
        "snapshot":{
            "database":snapshot,"schema_sha256":candidate["schema_sha256"],"anchor_height":candidate["anchor_height"],
            "anchor_hash":candidate["anchor_hash"],"checkpoint":before["checkpoint"],"prune_watermark":before["prune_watermark"],
            "reset_report":reference("before-report.json")?
        },
        "input":{
            "raw_block":raw_block,"height":candidate["block_height"],"block_hash":candidate["block_hash"],"previous_hash":candidate["anchor_hash"],
            "raw_txids":candidate["raw_txids"],"kontor_txids":[txid],"kontor_input_count":1,"operation_count":3,
            "payer_x_only_pubkey":candidate["payer_x_only_pubkey"],"operations":operations,
            "bitcoin_validation":{
                "network":bitcoin["network"],"bitcoind_version":bitcoin["bitcoind_version"],"accepted_block_hash":bitcoin["accepted_block_hash"],
                "record":reference("bitcoin-validation.json")?
            }
        },
        "execution":{
            "executor":"RuntimeExecutor","component_cache":"cold","network":"regtest","prune_enabled":true,"retain_blocks":6,
            "starting_block_height":candidate["starting_block_height"],"gas_to_fuel_multiplier":1000,"execution_price":"0.000000001",
            "storage_gas_per_byte":1,"lifecycle_parameters":reference("lifecycle-parameters.json")?,"independent_resets":2,"timing_claim":"none"
        },
        "expected_report":reference("trial-one.db-report.json")?,"numeric_check":reference("numeric-check.json")?,
        "decision":{
            "consensus_height":candidate["next_consensus_height"],"certificate_hex":"","value_kind":"block",
            "block_height":candidate["block_height"],"block_hash":candidate["block_hash"],"certified_txs":null
        }
    });
    if retention == 7 {
        manifest["execution"]["effective_retain_blocks"] = retention;
    }
    let output = root.join("candidate-manifest.json");
    let mut bytes = serde_json::to_vec_pretty(&manifest)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    let result = (|| -> Result<Value> {
        file.write_all(&bytes)?;
        file.flush()?;
        let documents = load(Fixture::open(&output)?)?;
        Ok(json!({"manifest":output,"sha256":documents.manifest_sha256,"frozen_acceptance":false}))
    })();
    drop(file);
    if result.is_err() {
        fs::remove_file(&output).context("remove invalid candidate manifest")?;
    }
    result
}
