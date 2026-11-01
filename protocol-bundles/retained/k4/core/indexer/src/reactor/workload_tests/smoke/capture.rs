use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use brotli::Decompressor;
use libsql::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::diagnostic::money;
use crate::built_info::{FEATURES_LOWERCASE, GIT_COMMIT_HASH, PROFILE, RUSTC_VERSION, TARGET};
use crate::database::native_contracts::NATIVE_CONTRACTS;
use crate::runtime::GenesisParameters;

fn command(root: &Path, program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()?;
    ensure!(output.status.success(), "{program} metadata command failed");
    Ok(String::from_utf8(output.stdout)?)
}

pub(super) fn source() -> Result<Value> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let head = command(&root, "git", &["rev-parse", "HEAD"])?;
    let status = command(
        &root,
        "git",
        &["status", "--porcelain", "--untracked-files=all"],
    )?;
    ensure!(status.is_empty(), "workload source checkout must be clean");
    ensure!(
        Some(head.trim()) == GIT_COMMIT_HASH,
        "compiled source revision differs from checkout"
    );
    let rustc = command(&root, "rustc", &["-vV"])?;
    ensure!(
        rustc.lines().next() == Some(RUSTC_VERSION),
        "compiler metadata differs from compiled version"
    );
    let mut features: Vec<_> = FEATURES_LOWERCASE
        .iter()
        .copied()
        .filter(|feature| !feature.is_empty())
        .collect();
    features.sort_unstable();
    features.dedup();
    ensure!(matches!(PROFILE, "debug" | "release"));
    Ok(
        json!({"git_head_log":head,"git_status_log":status,"embedded_source_commit":GIT_COMMIT_HASH,
        "rustc_verbose":rustc,"target":TARGET,"profile":if PROFILE == "debug" {"dev"} else {"release"},
        "features":features,"core_lockfile_sha256":hex::encode(Sha256::digest(fs::read(root.join("core/Cargo.lock"))?))}),
    )
}

pub(super) async fn schema(conn: &Connection) -> Result<(Value, String)> {
    let mut rows = conn.query(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name", (),
    ).await?;
    let mut projection = Vec::new();
    while let Some(row) = rows.next().await? {
        projection.push(json!([
            row.get::<String>(0)?,
            row.get::<String>(1)?,
            row.get::<String>(2)?,
            row.get::<Option<String>>(3)?
        ]));
    }
    let projection = json!(projection);
    let hash = hex::encode(Sha256::digest(serde_json::to_vec(&projection)?));
    Ok((projection, hash))
}

pub(super) fn artifacts(output: &Path, smoke_addresses: &[String]) -> Result<Value> {
    fs::create_dir(output.join("artifacts"))?;
    let smoke = (
        "error_test",
        include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br").as_slice(),
    );
    let mut contracts = NATIVE_CONTRACTS.to_vec();
    contracts.push(smoke);
    contracts.sort_by_key(|(name, _)| *name);
    let mut artifacts = Vec::new();
    for (name, compressed) in contracts {
        let path = format!("artifacts/{name}.wasm.br");
        fs::write(output.join(&path), compressed)?;
        let mut raw = Vec::new();
        Decompressor::new(compressed, 4096).read_to_end(&mut raw)?;
        let addresses = if name == "error_test" {
            smoke_addresses.to_vec()
        } else {
            vec![format!("{name}_0_0")]
        };
        artifacts.push(json!({"id":name,"compressed":{"path":path,"sha256":hex::encode(Sha256::digest(compressed))},
            "raw_sha256":hex::encode(Sha256::digest(&raw)),"addresses":addresses}));
    }
    Ok(json!(artifacts))
}

pub(super) fn lifecycle(genesis: &GenesisParameters) -> Result<Value> {
    let validators = genesis.validators.iter().map(|validator| Ok(json!({
        "x_only_pubkey":validator.x_only_pubkey,"ed25519_pubkey":hex::encode(&validator.ed25519_pubkey),
        "stake":money(validator.stake)?,
    }))).collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"sigma_min":money(genesis.sigma_min)?,"validators":validators,
        "policy_source":"native contract artifacts plus restored state", "network":"regtest"}),
    )
}

pub(super) fn write(output: &Path, name: &str, value: &Value) -> Result<()> {
    fs::write(output.join(name), serde_json::to_vec_pretty(value)?)
        .context("write candidate metadata")
}
