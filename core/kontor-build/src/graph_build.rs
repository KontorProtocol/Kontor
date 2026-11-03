use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::build_artifacts::stage_artifacts;
use crate::build_inputs::{current_artifacts, identities};
use crate::canonical_json::{Style, encode};
use crate::container::sha256;
use crate::execution_definition::verify as verify_definition;
use crate::provenance::{GraphKind, source_inputs};
use crate::recipes::{Graphs, Kind, graph_root, identity};
use crate::source_policy::{Kind as PolicyKind, check as source_policy};
use crate::toolchain::Environment;

pub fn fingerprint(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        encode(value, Style::Compact)?.as_bytes(),
    )))
}
pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    fs::write(path, format!("{}\n", encode(value, Style::Pretty)?))?;
    Ok(())
}
fn command(arguments: &[String], cwd: &Path, env: &Environment) -> Result<Command> {
    let (program, arguments) = arguments.split_first().context("missing command")?;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(cwd)
        .env_clear()
        .envs(env);
    Ok(command)
}
pub fn run_logged(arguments: &[String], cwd: &Path, env: &Environment, log: &Path) -> Result<()> {
    eprintln!("Running: {}", arguments.join(" "));
    let output = File::create(log)?;
    let status = command(arguments, cwd, env)?
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output))
        .status()?;
    if !status.success() {
        let mut file = File::open(log)?;
        let length = file.metadata()?.len();
        file.seek(SeekFrom::Start(length.saturating_sub(48000)))?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail)?;
        let text = String::from_utf8_lossy(&tail);
        let start = text
            .char_indices()
            .rev()
            .nth(11999)
            .map_or(0, |(index, _)| index);
        anyhow::bail!(
            "command failed ({status}): {}\n{}",
            log.display(),
            &text[start..]
        );
    }
    Ok(())
}
pub fn metadata(
    manifest: &Path,
    target: Option<&str>,
    env: &Environment,
    offline: bool,
    features: &[String],
    cwd: &Path,
) -> Result<Value> {
    let mut args = vec![
        "cargo".into(),
        "metadata".into(),
        "--locked".into(),
        "--format-version=1".into(),
        "--manifest-path".into(),
        manifest.to_str().context("non-UTF-8 manifest")?.into(),
    ];
    if let Some(target) = target {
        args.extend(["--filter-platform".into(), target.into()]);
    }
    if !features.is_empty() {
        args.extend(["--features".into(), features.join(",")]);
    }
    if offline {
        args.push("--offline".into());
    }
    let output = command(&args, cwd, env)?
        .stderr(Stdio::inherit())
        .output()?;
    ensure!(
        output.status.success(),
        "Cargo metadata failed ({})",
        output.status
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
#[derive(Clone, Deserialize)]
pub struct Options {
    pub target: String,
    pub profile: String,
    pub jobs: u32,
    pub offline: bool,
}
pub fn compile_graph(
    root: &Path,
    label: &str,
    graphs: &Graphs,
    options: &Options,
    base_env: &Environment,
    output: &Path,
    wrapper: &Path,
    cargo_home: &Path,
) -> Result<Value> {
    ensure!(
        matches!(options.profile.as_str(), "dev" | "release") && (1..=2).contains(&options.jobs),
        "invalid graph build profile or job count"
    );
    let selected = graphs.get(label).context("unknown graph label")?;
    let source_root = graph_root(root, selected)?;
    let manifest = source_root
        .join("protocol-bundles")
        .join(&selected.directory)
        .join("Cargo.toml");
    let recipe: Value = toml::from_str(&fs::read_to_string(&manifest)?)?;
    ensure!(
        ["dev", "release"]
            .iter()
            .all(|profile| recipe["profile"][profile]["panic"] == "unwind"),
        "bundle profiles must use the common unwind runtime"
    );
    let directory = output.join(label);
    fs::create_dir_all(&directory)?;
    let lock = manifest.with_file_name("Cargo.lock");
    let lock_hash = sha256(&lock)?;
    let graph_identity = identity(root, label, graphs)?;
    let namespace = format!("kontor_{label}_{}", &fingerprint(&graph_identity)?[..24]);
    let wrapper_hash = sha256(wrapper)?;
    let target_dir = directory
        .join("target")
        .join(format!("{namespace}_{}", &wrapper_hash[..16]));
    let mut env = base_env.clone();
    for (key, value) in [
        (
            "CARGO_TARGET_DIR",
            target_dir
                .to_str()
                .context("non-UTF-8 target directory")?
                .to_owned(),
        ),
        ("KONTOR_PROTOCOL_BUNDLE", "1".into()),
        ("KONTOR_NATIVE_NAMESPACE", namespace.clone()),
        ("BUNDLE_LIFT_RATE", selected.lift_rate.to_string()),
        ("BUNDLE_GRAPH", label.into()),
        (
            "RUSTC_WRAPPER",
            wrapper.to_str().context("non-UTF-8 wrapper path")?.into(),
        ),
        (
            "RUSTFLAGS",
            format!("-Cmetadata={namespace} -Cpanic=unwind"),
        ),
    ] {
        env.insert(key.into(), value);
    }
    let data = metadata(
        &manifest,
        Some(&options.target),
        &env,
        options.offline,
        &[],
        &source_root,
    )?;
    // Execution identity binds all targets, unlike the platform-specific artifact inventory.
    let definition = if selected.kind == Kind::Executor {
        Some(verify_definition(
            &source_root,
            &manifest,
            &metadata(&manifest, None, &env, options.offline, &[], &source_root)?,
        )?)
    } else {
        None
    };
    let packages = identities(root, selected, &serde_json::from_value(data.clone())?)?;
    let kind = match selected.kind {
        Kind::Executor => GraphKind::Executor,
        Kind::Consensus => GraphKind::Consensus,
        Kind::Proof => GraphKind::Proof,
    };
    let policy_kind = match selected.kind {
        Kind::Executor => PolicyKind::Executor,
        Kind::Consensus => PolicyKind::Consensus,
        Kind::Proof => PolicyKind::Proof,
    };
    let source_metadata = serde_json::from_value(data.clone())?;
    let sources = source_inputs(&source_root, &source_metadata, kind, Some(root), cargo_home)?;
    let policy = source_policy(
        &source_root,
        &serde_json::from_value(data.clone())?,
        policy_kind,
    )?;
    write_json(&directory.join("source-inputs.json"), &sources)?;
    write_json(&directory.join("metadata.json"), &data)?;
    let mut args = vec![
        "cargo".into(),
        "build".into(),
        "--locked".into(),
        "--manifest-path".into(),
        manifest.to_str().context("non-UTF-8 manifest")?.into(),
        "--target".into(),
        options.target.clone(),
        "--profile".into(),
        options.profile.clone(),
        "-j".into(),
        options.jobs.to_string(),
        "--message-format=json-render-diagnostics".into(),
    ];
    if options.offline {
        args.push("--offline".into());
    }
    let log = directory.join("build.log");
    run_logged(&args, &source_root, &env, &log)?;
    ensure!(
        sha256(wrapper)? == wrapper_hash,
        "compiler wrapper changed during graph compilation"
    );
    ensure!(
        sha256(&lock)? == lock_hash,
        "locked build modified the dependency lock"
    );
    ensure!(
        source_inputs(&source_root, &source_metadata, kind, Some(root), cargo_home)? == sources,
        "source inputs changed while the graph was compiling"
    );
    ensure!(
        metadata(
            &manifest,
            Some(&options.target),
            &env,
            options.offline,
            &[],
            &source_root
        )? == data,
        "resolved metadata changed while the graph was compiling"
    );
    if let Some(original) = &definition {
        ensure!(
            &verify_definition(
                &source_root,
                &manifest,
                &metadata(&manifest, None, &env, options.offline, &[], &source_root)?
            )? == original,
            "execution definition changed while the graph was compiling"
        );
    }
    let artifacts = current_artifacts(
        &log,
        &target_dir,
        &options.target,
        recipe["package"]["name"]
            .as_str()
            .context("missing package name")?,
    )?;
    let mut result = stage_artifacts(&directory, &artifacts, &namespace, root)?;
    let locked: Value = toml::from_str(&fs::read_to_string(&lock)?)?;
    let fields = json!({"graph":label,"identity":graph_identity,"namespace":namespace,"lock_sha256":lock_hash,
        "build_log_sha256":sha256(&log)?,"manifest_sha256":sha256(&manifest)?,"packages":packages,
        "source_inputs_sha256":fingerprint(&sources)?,"locked_packages":locked.get("package").context("missing lockfile packages")?,
        "source_policy":policy,"wrapper":wrapper,"wrapper_binary_sha256":wrapper_hash,
        "wrapper_sha256":sha256(&root.join("core/kontor-build/src/bin/kontor-graph-rustc.rs"))?,
        "injected_metadata":namespace,"rustflags":env["RUSTFLAGS"],"native_outputs":artifacts["native_outputs"]});
    result
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    if let Some(definition) = definition {
        result["execution_definition"] = definition;
    }
    write_json(&directory.join("build-inputs.json"), &result)?;
    Ok(result)
}
#[derive(Deserialize)]
pub struct Request {
    pub root: PathBuf,
    pub label: String,
    pub graphs: Graphs,
    pub options: Options,
    pub env: Environment,
    pub output: PathBuf,
    pub wrapper: PathBuf,
    pub cargo_home: PathBuf,
}
pub fn run(request: Request) -> Result<Value> {
    compile_graph(
        &request.root,
        &request.label,
        &request.graphs,
        &request.options,
        &request.env,
        &request.output,
        &request.wrapper,
        &request.cargo_home,
    )
}
#[cfg(test)]
mod tests;
