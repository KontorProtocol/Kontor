mod build;
mod symbols;
pub mod vendor;

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::canonical_json::{Style, encode};
use crate::container::sha256;
use crate::execution_definition::resolve;
use build::{Graph, build};
use vendor::VendorArgs;

const CRATES: [&str; 3] = ["blst", "ring", "secp256k1-sys"];
type Environment = BTreeMap<OsString, OsString>;

#[derive(Args)]
pub struct QualifyArgs {
    /// New evidence directory, never reused.
    #[arg(long)]
    pub output: PathBuf,
}

fn environment() -> Environment {
    let mut env: Environment = env::vars_os().collect();
    for name in [
        "RUSTC_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "KONTOR_NATIVE_NAMESPACE",
        "KONTOR_PROTOCOL_BUNDLE",
    ] {
        env.remove(&OsString::from(name));
    }
    for (key, value) in [
        ("RUSTUP_TOOLCHAIN", "1.99.1"),
        ("CCACHE_DISABLE", "1"),
        ("CC_ENABLE_DEBUG_OUTPUT", "1"),
    ] {
        env.insert(key.into(), value.into());
    }
    env
}

fn command(program: impl AsRef<Path>, cwd: &Path, env: &Environment) -> Command {
    let mut command = Command::new(program.as_ref());
    command.current_dir(cwd).env_clear().envs(env);
    command
}

fn logged(command: &mut Command, log: &Path) -> Result<ExitStatus> {
    eprintln!("Running {:?}, log {}", command.get_program(), log.display());
    let output = File::create(log)?;
    Ok(command
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output))
        .status()?)
}

fn run(command: &mut Command, log: &Path) -> Result<()> {
    let status = logged(command, log)?;
    ensure!(
        status.success(),
        "command failed ({status}), inspect {}",
        log.display()
    );
    Ok(())
}

fn capture(command: &mut Command) -> Result<Vec<u8>> {
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "{:?} failed: {}",
        command.get_program(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    fs::write(path, format!("{}\n", encode(value, Style::Pretty)?))?;
    Ok(())
}

fn source_manifest(root: &Path) -> Result<BTreeMap<PathBuf, String>> {
    fn walk(root: &Path, dir: &Path, entries: &mut BTreeMap<PathBuf, String>) -> Result<()> {
        for item in fs::read_dir(dir)? {
            let path = item?.path();
            if path
                .file_name()
                .is_some_and(|name| name == "target" || name == "__pycache__")
            {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                walk(root, &path, entries)?;
            } else if path.is_file() {
                ensure!(
                    path.canonicalize()?.starts_with(root),
                    "qualification source escapes checkout"
                );
                entries.insert(path.strip_prefix(root)?.to_owned(), sha256(&path)?);
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    for name in ["core/Cargo.toml", "core/Cargo.lock", "tools/kontor"] {
        entries.insert(PathBuf::from(name), sha256(&root.join(name))?);
    }
    for name in [
        "tools/native-crypto",
        "core/kontor-build",
        "core/vendor/blst",
        "core/vendor/ring",
        "core/vendor/secp256k1-sys",
        "core/vendor/kontor-native-build",
    ] {
        walk(root, &root.join(name), &mut entries)?;
    }
    Ok(entries)
}

fn strip_audits(report: &mut Value) -> Result<Vec<Value>> {
    let members: Vec<&mut Value> = if report.get("members").is_some() {
        report["members"]
            .as_array_mut()
            .context("invalid object members")?
            .iter_mut()
            .collect()
    } else {
        vec![report]
    };
    members
        .into_iter()
        .map(|member| {
            member
                .as_object_mut()
                .context("invalid object report")?
                .remove("namespace_audit")
                .context("missing namespace audit")
        })
        .collect()
}

fn compare_objects(
    tool: &Path,
    reference: &Graph,
    candidate: &Graph,
    output: &Path,
) -> Result<Vec<Value>> {
    ensure!(
        reference.native.keys().eq(candidate.native.keys()),
        "native archive inventory changed"
    );
    let mut results = Vec::new();
    for (key, path) in &reference.native {
        let other = &candidate.native[key];
        let mut before: Value =
            serde_json::from_slice(&capture(Command::new(tool).arg(path).arg(""))?)?;
        let mut after: Value = serde_json::from_slice(&capture(
            Command::new(tool).arg(other).arg(&candidate.namespace),
        )?)?;
        strip_audits(&mut before)?;
        let audits = strip_audits(&mut after)?;
        let prefix = format!("{}-{}", candidate.name, key.replace('/', "-"));
        let audit_path = output.join(format!("{prefix}.namespace-audit.json"));
        write_json(&audit_path, &json!(audits))?;
        if before != after {
            write_json(&output.join(format!("{prefix}.before.json")), &before)?;
            write_json(&output.join(format!("{prefix}.after.json")), &after)?;
            anyhow::bail!(
                "native code/data/symbol/relocation drift: {key}, inspect {prefix} reports"
            );
        }
        results.push(json!({"archive":key,"upstream_sha256":sha256(path)?,"candidate_sha256":sha256(other)?,
            "normalized_report_sha256":hex::encode(Sha256::digest(encode(&before,Style::Spaced)?)),"namespace_audit_sha256":sha256(&audit_path)?}));
    }
    Ok(results)
}

pub fn qualify(root: &Path, args: QualifyArgs) -> Result<String> {
    let root = root.canonicalize()?;
    let output = resolve(&args.output)?;
    fs::create_dir_all(output.parent().context("evidence parent")?)?;
    fs::create_dir(&output).context("evidence directory must be new")?;
    let sources = source_manifest(&root)?;
    let env = environment();
    fs::write(
        output.join("vendor.log"),
        vendor::verify(&root, VendorArgs::default())?,
    )?;
    let pristine_dir = output.join("pristine");
    fs::create_dir(&pristine_dir)?;
    let pristine: BTreeMap<_, _> = vendor::sources(&root)?
        .iter()
        .map(|entry| Ok((entry.name.clone(), vendor::archive(entry, &pristine_dir)?)))
        .collect::<Result<_>>()?;
    let tool_project = root.join("tools/native-crypto/object-report");
    run(
        command("cargo", &tool_project, &env)
            .env("CARGO_TARGET_DIR", output.join("object-tool"))
            .args(["build", "--locked", "--offline", "-j2"]),
        &output.join("object-tool.log"),
    )?;
    let tool = output.join("object-tool/debug/kontor-native-object-report");
    let mut graphs = Vec::new();
    let mut reports = Vec::new();
    let mut baseline = None;
    for configuration in ["portable", "native"] {
        let upstream = build(&root, &output, &env, &pristine, configuration, "upstream")?;
        for variant in ["default", "namespaced"] {
            let candidate = build(&root, &output, &env, &pristine, configuration, variant)?;
            let objects = compare_objects(&tool, &upstream, &candidate, &output)?;
            let expected = fs::read(upstream.project.join("vectors.bin"))?;
            ensure!(
                fs::read(candidate.project.join("vectors.bin"))? == expected
                    && baseline.as_ref().is_none_or(|base| base == &expected),
                "crypto outputs differ from pristine baseline"
            );
            baseline = Some(expected);
            reports.push(json!({"graph":candidate.name,"lock_sha256":candidate.lock_sha256,"objects":objects}));
            if variant == "namespaced" || configuration == "portable" {
                graphs.push(candidate);
            }
        }
    }
    let names = symbols::audit(&graphs, &output)?;
    let executable = output.join("dual-crypto");
    let mut link = command("rustc", &root, &env);
    link.arg("--edition=2024")
        .arg(root.join("tools/native-crypto/fixtures/host.rs"))
        .arg("-o")
        .arg(&executable);
    for graph in &graphs {
        link.arg("--extern")
            .arg(format!("crypto_{}={}", graph.graph, graph.facade.display()))
            .arg("-L")
            .arg(format!(
                "dependency={}",
                graph.project.join("target/release/deps").display()
            ));
    }
    run(&mut link, &output.join("link.log"))?;
    symbols::audit_final(&executable, &graphs, &names, &output)?;
    run(
        command(&executable, &root, &env).arg(graphs[0].project.join("vectors.bin")),
        &output.join("run.log"),
    )?;
    let namespaced = graphs
        .iter()
        .find(|graph| !graph.namespace.is_empty())
        .context("missing namespaced graph")?;
    for name in CRATES {
        let log = output.join(format!("reject-missing-namespace-{name}.log"));
        let status = logged(
            command("cargo", &namespaced.project, &env)
                .env("KONTOR_PROTOCOL_BUNDLE", "1")
                .env("CARGO_TARGET_DIR", output.join("rejection-target"))
                .args([
                    "build",
                    "--locked",
                    "--offline",
                    "--release",
                    "-j2",
                    "-p",
                    name,
                ]),
            &log,
        )?;
        ensure!(
            !status.success()
                && fs::read_to_string(&log)?
                    .contains("protocol bundle requires an explicit KONTOR_NATIVE_NAMESPACE"),
            "{name} failed to reject missing namespace for expected reason: {}",
            log.display()
        );
    }
    ensure!(
        source_manifest(&root)? == sources,
        "qualification sources changed during run"
    );
    let result = fs::read_to_string(output.join("run.log"))?;
    write_json(
        &output.join("report.json"),
        &json!({
            "compiler":String::from_utf8(capture(command("rustc",&root,&env).arg("-Vv"))?)?,"sources":sources,"graphs":reports,
            "native_definition_counts":names.iter().map(|names|names.len()).collect::<Vec<_>>(),
            "vectors_sha256":hex::encode(Sha256::digest(baseline.context("missing vector baseline")?)),"result":result
        }),
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests;
